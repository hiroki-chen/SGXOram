/*
 Copyright (c) 2022 Haobin Chen

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <enclave/enclave_cache.hh>

#include <cmath>
#include <cstring>
#include <stdexcept>

#include <basic_models.hh>
#include <enclave/enclave_t.h>
#include <enclave/enclave_crypto_manager.hh>
#include <enclave/enclave_utils.hh>

EnclaveCache::EnclaveCache(size_t max_size, cache_type_t cache_type)
    : max_size_(max_size), cache_list_(), key_map_(), cache_type_(cache_type) {
  // Check the maximum size of the cache, just a sanity check.
  if (cache_type_ == cache_type_t::ENCLAVE_CACHE_SLOT_BODY &&
      max_size_ * 65535 > maximum_cache_size_in_bytes) {
    ENCLAVE_LOG(
        "[enclave] Due to the size limitation, the cache cannot be created.");
    ocall_panic_and_flush("Cache pool cannot be created due to EPC limit.");
  } else if (cache_type_ == cache_type_t::ENCLAVE_CACHE_SLOT_HEADER &&
             max_size_ * ORAM_SLOT_HEADER_SIZE > maximum_cache_size_in_bytes) {
    ENCLAVE_LOG(
        "[enclave] Due to the size limitation, the cache cannot be created.");
    ocall_panic_and_flush("Cache pool cannot be created due to EPC limit.");
  }

  ENCLAVE_LOG("[enclave] Cache pool created. Type = {}.", cache_type_);
}

// Create an instance within the function body is thread-safe and is guaranteed
// to return the same instance once so that different threads will not get
// different instances that cause non-atomicity.
std::shared_ptr<EnclaveCache> EnclaveCache::get_instance_for_slot_body(void) {
  static std::shared_ptr<EnclaveCache> instance_(new EnclaveCache(
      maximum_cache_size, cache_type_t::ENCLAVE_CACHE_SLOT_BODY));
  return instance_;
}

std::shared_ptr<EnclaveCache> EnclaveCache::get_instance_for_slot_header(void) {
  static std::shared_ptr<EnclaveCache> instance_(new EnclaveCache(
      maximum_cache_size_for_header, cache_type_t::ENCLAVE_CACHE_SLOT_HEADER));
  return instance_;
}

void EnclaveCache::replace_item(const std::string& key,
                                const std::string& value, bool is_dirty,
                                bool is_body) {
  // First check if the cache is full.
  if (cache_list_.size() >= max_size_) {
    // Need to write back to the external memory if the dirty bit is set.
    // We use the write-back strategy to avoid the overhead of the write-back
    // operation :), and we always remove the last item from the cache list.
    auto last_item = cache_list_.back();

    // Check whether the key is in memory.
    bool is_body_in_storage, is_header_in_storage;
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    status = ocall_is_body_in_storage((int*)(&is_body_in_storage), key.c_str());
    enclave_utils::check_sgx_status(status, "ocall_is_body_in_storage()");
    status =
        ocall_is_header_in_storage((int*)(&is_header_in_storage), key.c_str());
    enclave_utils::check_sgx_status(status, "ocall_is_header_in_storage()");

    // If the dirty bit is set or the key is not in the memory (when
    // initializing), we need to write back to the external memory.
    if ((last_item.second.first & CACHE_DIRTY_BIT) ||
        (is_body && !is_body_in_storage) ||
        (!is_body && !is_header_in_storage)) {
      // Write back the last item to the external memory.
      // The key is the hashed fingerprint of the slot.
      std::string old_key = last_item.first;
      std::string old_value = last_item.second.second;

      if (is_body) {
        // status = ocall_write_slot(old_key.c_str(),
        // (uint8_t*)old_value.data(),
        //                           old_value.size());
        // enclave_utils::check_sgx_status(status, "ocall_write_slot()");
        enclave_utils::slot_segment_write(old_key.c_str(),
                                          (uint8_t*)old_value.data(),
                                          old_value.size(), seg_size_);
      } else {
        int64_t begin = enclave_utils::get_current_time();
        ocall_write_slot_header(old_key.c_str(), (uint8_t*)old_value.data(),
                                old_value.size());
        int64_t end = enclave_utils::get_current_time();
        ocall_latency += (end - begin);
      }
    }

    key_map_.erase(last_item.first);
    cache_list_.pop_back();
  }
  // Insert the new item to the front of the cache.
  cache_list_.emplace_front(
      std::make_pair(key, std::make_pair(is_dirty, value)));
  key_map_[key] = cache_list_.begin();
}

void EnclaveCache::write(const std::string& key, const std::string& value,
                         bool is_body) {
  auto it = key_map_.find(key);
  if (it != key_map_.end()) {
    // ENCLAVE_LOG("[enclave] W Cache hit on key %s.", key.c_str());
    // Update the item.
    it->second->second.second = value;
    cache_list_.splice(cache_list_.begin(), cache_list_, it->second);
  } else {
    // ENCLAVE_LOG("[enclave] W Cache miss on key %s.", key.c_str());
    replace_item(key, value, true, is_body);
  }

  // Set the dirty bit of the first element because we have updated it.
  // Even if the cache entry remains unchanged, we still need to set the dirty
  // bit because we cannot know whether the cache entry is changed or not.
  cache_list_.begin()->second.first |= CACHE_DIRTY_BIT;
}

std::string EnclaveCache::internal_read(const std::string& key, size_t size,
                                        bool is_body) {
  auto it = key_map_.find(key);

  if (it == key_map_.end()) {
    // ENCLAVE_LOG("[enclave] R Cache miss on key %s", key.c_str());
    // ENCLAVE_LOG("[enclave] R Fetching from external memory...");

    // If the target key value is not in the cache, fetch it from the external
    // memory. We assume the external memory is always available.
    // Always remember to add the size for IV and MAC tag.
    size_t buf_size = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + size;
    std::string buf(buf_size, 0);
    sgx_status_t status = SGX_ERROR_UNEXPECTED;

    if (is_body) {
      // status = ocall_read_slot(&buf_size, key.c_str(), (uint8_t*)buf.data(),
      //                          buf_size);
      enclave_utils::slot_segment_read(key.c_str(), (uint8_t*)buf.data(),
                                       buf_size, seg_size_);
      // enclave_utils::check_sgx_status(status, "slot_segment_read()");
    } else {
      int64_t begin = enclave_utils::get_current_time();
      status = ocall_read_slot_header(&buf_size, key.c_str(),
                                      (uint8_t*)buf.data(), buf_size);
      int64_t end = enclave_utils::get_current_time();
      ocall_latency += (end - begin);

      enclave_utils::check_sgx_status(status, "ocall_read_slot_header()");
    }

    // Insert into the cache.
    replace_item(key, buf, false, is_body);
    return buf;
  } else {
    // ENCLAVE_LOG("[enclave] R Cache hit on key %s", key.c_str());
    const std::string ans = it->second->second.second;
    cache_list_.splice(cache_list_.begin(), cache_list_, it->second);
    return ans;
  }
}

std::string EnclaveCache::read(const std::string& key, size_t size) {
  // If the size is given, then we read the slot body.
  return internal_read(key, size, true);
}

std::string EnclaveCache::read(const std::string& key) {
  // If the size is not given, then we read the slot header.
  return internal_read(key, ORAM_SLOT_HEADER_SIZE, false);
}

sgx_status_t SGXAPI ecall_test_oram_cache() {
  std::shared_ptr<EnclaveCache> cache =
      EnclaveCache::get_instance_for_slot_body();
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();

  const uint32_t level = crypto_manager->get_oram_config()->level;
  const uint32_t way = crypto_manager->get_oram_config()->way;

  return SGX_SUCCESS;
}