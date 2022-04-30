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

#include <basic_models.hh>
#include <enclave/enclave_t.h>
#include <enclave/enclave_utils.hh>

std::shared_ptr<EnclaveCache> EnclaveCache::instance_;

EnclaveCache::EnclaveCache(size_t max_size)
    : max_size_(max_size), cache_list_(), key_map_(), status(true) {
  // Check the maximum size of the cache, just a sanity check.
  if (max_size_ * sizeof(sgx_oram::oram_slot_leaf_t) >
      maximum_cache_size_in_bytes) {
    ENCLAVE_LOG(
        "[enclave] Due to the size limitation, the cache cannot be created.");
    ocall_panic_and_flush("Cache pool cannot be created due to EPC limit.");
  }
  ENCLAVE_LOG("[enclave] Cache pool created.");
}

std::shared_ptr<EnclaveCache> EnclaveCache::get_instance(void) {
  if (instance_ == nullptr) {
    instance_ = std::shared_ptr<EnclaveCache>(new EnclaveCache());
  }
  return instance_;
}

void EnclaveCache::replace_item(const std::string& key,
                                const std::string& value) {
  // First check if the cache is full.
  if (cache_list_.size() >= max_size_) {
    // Need to write back to the external memory if the dirty bit is set.
    // We use the write-back strategy to avoid the overhead of the write-back
    // operation :), and we always remove the last item from the cache list.
    auto last_item = cache_list_.end();

    if (last_item->second.first & CACHE_DIRTY_BIT) {
      // Write back the last item to the external memory.
      // The key is the hashed fingerprint of the slot.
      std::string old_key = last_item->first;
      std::string old_value = last_item->second.second;
      ENCLAVE_LOG("[enclave] Write back the last item to the external memory.");
      ocall_write_slot(old_key.c_str(), (uint8_t*)old_value.c_str(),
                       old_value.size());
    }

    --last_item;
    key_map_.erase(last_item->first);
    cache_list_.pop_back();
  }
  // Insert the new item to the front of the cache.
  cache_list_.push_front(std::make_pair(key, std::make_pair(0, value)));
  key_map_[key] = cache_list_.begin();
}

void EnclaveCache::write(const std::string& key, const std::string& value,
                         bool leaf_type) {
  auto it = key_map_.find(key);
  if (it != key_map_.end()) {
    ENCLAVE_LOG("[enclave] Cache hit.");
    cache_list_.splice(cache_list_.begin(), cache_list_, it->second);
    it->second = cache_list_.begin();
  } else {
    ENCLAVE_LOG("[enclave] Cache miss on key %s.",
                hex_to_string((uint8_t*)key.data()).c_str());
    ENCLAVE_LOG("[enclave] Create a new cache entry.");

    replace_item(key, value);
    // Set the dirty bit of the first element because we have updated it.
    cache_list_.begin()->second.first |= CACHE_DIRTY_BIT;
  }
}

std::string EnclaveCache::read(const std::string& key, bool leaf_type) {
  auto it = key_map_.find(key);

  if (it == key_map_.end()) {
    ENCLAVE_LOG("[enclave] Cache miss on key %s",
                hex_to_string((uint8_t*)key.data()).c_str());
    ENCLAVE_LOG("[enclave] Fetching from external memory...");

    // If the target key value is not in the cache, fetch it from the external
    // memory. We assume the external memory is always available.
    size_t buf_size = leaf_type ? sizeof(sgx_oram::oram_slot_leaf_t)
                                : sizeof(sgx_oram::oram_slot_t);
    uint8_t* buf = (uint8_t*)malloc(buf_size);
    sgx_status_t status =
        ocall_read_slot(&buf_size, key.c_str(), buf, buf_size);
    check_sgx_status(status, "ocall_read_slot()");

    safe_free(buf);
    // Insert into the cache.
    const std::string slot(reinterpret_cast<char*>(buf), buf_size);
    replace_item(key, slot);
    return slot;
  } else {
    ENCLAVE_LOG("[enclave] Cache hit on key %s",
                hex_to_string((uint8_t*)key.data()).c_str());
    cache_list_.splice(cache_list_.begin(), cache_list_, it->second);
    it->second = cache_list_.begin();
    return it->second->second.second;
  }
}