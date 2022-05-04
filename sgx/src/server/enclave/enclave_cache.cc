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

// Create an instance within the function body is thread-safe and is guaranteed
// to return the same instance once. Different threads will not get different
// instances.
std::shared_ptr<EnclaveCache> EnclaveCache::get_instance(void) {
  static std::shared_ptr<EnclaveCache> instance_(new EnclaveCache());
  return instance_;
}

void EnclaveCache::replace_item(const std::string& key,
                                const std::string& value, bool is_dirty) {
  // First check if the cache is full.
  if (cache_list_.size() >= max_size_) {
    // Need to write back to the external memory if the dirty bit is set.
    // We use the write-back strategy to avoid the overhead of the write-back
    // operation :), and we always remove the last item from the cache list.
    auto last_item = cache_list_.back();

    // Check whether the key is in memory.
    bool is_in_memory;
    sgx_status_t status =
        ocall_is_in_memory((int*)(&is_in_memory), key.c_str());
    check_sgx_status(status, "ocall_is_in_memory()");

    // If the dirty bit is set or the key is not in the memory (when
    // initializing), we need to write back to the external memory.
    if ((last_item.second.first & CACHE_DIRTY_BIT) || !(is_in_memory)) {
      // Write back the last item to the external memory.
      // The key is the hashed fingerprint of the slot.
      std::string old_key = last_item.first;
      std::string old_value = last_item.second.second;
      ENCLAVE_LOG(
          "[enclave] Write back the last item %s to the external memory. The "
          "size of the old value is %zu",
          old_key.c_str(), old_value.size());
      ocall_write_slot(old_key.c_str(), (uint8_t*)old_value.data(),
                       old_value.size());
    }

    key_map_.erase(last_item.first);
    cache_list_.pop_back();
  }
  // Insert the new item to the front of the cache.
  cache_list_.emplace_front(std::make_pair(key, std::make_pair(is_dirty, value)));
  key_map_[key] = cache_list_.begin();
}

void EnclaveCache::write(const std::string& key, const std::string& value,
                         bool leaf_type) {
  auto it = key_map_.find(key);
  if (it != key_map_.end()) {
    ENCLAVE_LOG("[enclave] W Cache hit on key %s.", key.c_str());
    // Update the item.
    it->second->second.second = value;
    cache_list_.splice(cache_list_.begin(), cache_list_, it->second);
  } else {
    ENCLAVE_LOG("[enclave] W Cache miss on key %s.", key.c_str());
    replace_item(key, value, true);
  }

  // Set the dirty bit of the first element because we have updated it.
  // Even if the cache entry remains unchanged, we still need to set the dirty
  // bit because we cannot know whether the cache entry is changed or not.
  cache_list_.begin()->second.first |= CACHE_DIRTY_BIT;
}

std::string EnclaveCache::read(const std::string& key, bool leaf_type) {
  auto it = key_map_.find(key);

  if (it == key_map_.end()) {
    ENCLAVE_LOG("[enclave] R Cache miss on key %s", key.c_str());
    ENCLAVE_LOG("[enclave] R Fetching from external memory...");

    // If the target key value is not in the cache, fetch it from the external
    // memory. We assume the external memory is always available.
    size_t buf_size = leaf_type ? sizeof(sgx_oram::oram_slot_leaf_t)
                                : sizeof(sgx_oram::oram_slot_t);
    // Always remember to add the size for IV and MAC tag.
    buf_size += SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;
    std::string slot;
    slot.resize(buf_size);
    sgx_status_t status = ocall_read_slot(&buf_size, key.c_str(),
                                          (uint8_t*)slot.data(), buf_size);
    check_sgx_status(status, "ocall_read_slot()");

    // Insert into the cache.
    replace_item(key, slot, false);
    return slot;
  } else {
    ENCLAVE_LOG("[enclave] R Cache hit on key %s", key.c_str());
    const std::string ans = it->second->second.second;
    cache_list_.splice(cache_list_.begin(), cache_list_, it->second);
    return ans;
  }
}

sgx_status_t SGXAPI ecall_test_oram_cache() {
  std::shared_ptr<EnclaveCache> cache = EnclaveCache::get_instance();
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();

  const uint32_t level = crypto_manager->get_oram_config()->level;
  const uint32_t way = crypto_manager->get_oram_config()->way;

  // The roadmap is to traverse all the slots by the cache and check if the
  // slot header is correct. There are two things we need to test:
  // - Read
  // - Write. We take the write-back strategy.
  // ENCLAVE_LOG(
  //     "[enclave] ++ Start testing the cache: type = sequential access.\n");
  // for (uint32_t i = 0; i < level; i++) {
  //   const uint32_t level_size = std::pow(way, i);

  //   size_t slot_size = (i == level - 1) ? sizeof(sgx_oram::oram_slot_leaf_t)
  //                                       : sizeof(sgx_oram::oram_slot_t);
  //   uint8_t* const slot_buf = (uint8_t*)malloc(slot_size);

  //   for (uint32_t j = 0; j < level_size; j++) {
  //     const std::string key = crypto_manager->enclave_sha_256(enclave_strcat(
  //         std::to_string(i).c_str(), "_", std::to_string(j).c_str()));
  //     std::string ans = cache->read(key, i == level - 1);
  //     // Decrypt the slot.
  //     ans = crypto_manager->enclave_aes_128_gcm_decrypt(ans);

  //     if (ans.size() != slot_size) {
  //       ENCLAVE_LOG("[enclave] Read error on key %s",
  //                   hex_to_string((uint8_t*)key.data()).c_str());
  //       ocall_panic_and_flush("Read error on key.");
  //     } else {
  //       memcpy(slot_buf, ans.data(), slot_size);

  //       // Check header.
  //       sgx_oram::oram_slot_header_t* const slot_header =
  //           (sgx_oram::oram_slot_header_t*)slot_buf;

  //       if (slot_header->level != i || slot_header->offset != j) {
  //         ENCLAVE_LOG("[enclave] Read error on key %s",
  //                     hex_to_string((uint8_t*)key.data()).c_str());
  //         ocall_panic_and_flush("Read error on key.");
  //       }
  //     }
  //   }

  //   safe_free(slot_buf);
  // }
  // ENCLAVE_LOG("[enclave] -- Cache test for sequential access is passed.\n");

  // ENCLAVE_LOG("[enclave] ++ Start testing the cache: type = random
  // access.\n"); uint32_t n = 10000; while (n--) {
  //   const uint32_t level_cur = uniform_random(0, level - 1);
  //   const uint32_t offset = uniform_random(0, std::pow(way, level_cur) - 1);

  //   ENCLAVE_LOG("[enclave] Random access: level = %d, offset = %d.\n",
  //               level_cur, offset);

  //   const std::string key = crypto_manager->enclave_sha_256(
  //       enclave_strcat(std::to_string(level_cur).c_str(), "_",
  //                      std::to_string(offset).c_str()));

  //   std::string ans = cache->read(key, level_cur == level - 1);
  //   ans = crypto_manager->enclave_aes_128_gcm_decrypt(ans);
  //   size_t slot_size = (level_cur == level - 1)
  //                          ? sizeof(sgx_oram::oram_slot_leaf_t)
  //                          : sizeof(sgx_oram::oram_slot_t);
  //   uint8_t* const slot_buf = (uint8_t*)malloc(slot_size);
  //   memcpy(slot_buf, ans.data(), slot_size);

  //   // Check header.
  //   sgx_oram::oram_slot_header_t* const slot_header =
  //       (sgx_oram::oram_slot_header_t*)slot_buf;
  //   if (slot_header->level != level_cur || slot_header->offset != offset) {
  //     ENCLAVE_LOG("[enclave] Read error on key %s",
  //                 hex_to_string((uint8_t*)key.data()).c_str());
  //     ocall_panic_and_flush("Read error on key.");
  //   }

  //   safe_free(slot_buf);
  // }
  // ENCLAVE_LOG("[enclave] -- Cache test for random access is passed.\n");

  // ENCLAVE_LOG(
  //     "[enclave] ++ Start testing the cache: type = sequential write.\n");
  // for (uint32_t i = 0; i < level; i++) {
  //   const uint32_t level_size = std::pow(way, i);
  //   size_t slot_size = (i == level - 1) ? sizeof(sgx_oram::oram_slot_leaf_t)
  //                                       : sizeof(sgx_oram::oram_slot_t);
  //   uint8_t* const slot_buf = (uint8_t*)malloc(slot_size);

  //   for (uint32_t j = 0; j < level_size; j++) {
  //     // First read the content of the slot.
  //     const std::string key = crypto_manager->enclave_sha_256(enclave_strcat(
  //         std::to_string(i).c_str(), "_", std::to_string(j).c_str()));
  //     std::string ans = cache->read(key, i == level - 1);
  //     ans = crypto_manager->enclave_aes_128_gcm_decrypt(ans);
  //     memcpy(slot_buf, ans.data(), slot_size);

  //     sgx_oram::oram_block_t* const block =
  //         (sgx_oram::oram_block_t*)(slot_buf +
  //                                   sizeof(sgx_oram::oram_slot_header_t));
  //     block->data[0] = std::to_string(i).c_str()[0];

  //     // Write back the content.
  //     std::string cipher_text = crypto_manager->enclave_aes_128_gcm_encrypt(
  //         std::string((char*)slot_buf, slot_size));
  //     cache->write(key, cipher_text, i == level - 1);
  //   }
  //   safe_free(slot_buf);
  // }
  // ENCLAVE_LOG("[enclave] -- Cache test for sequential write is passed.\n");

  ENCLAVE_LOG("[enclave] ++ Start testing the cache: type = read.\n");
  int n = 100;
  while (n--) {
    const std::string key = crypto_manager->enclave_sha_256(enclave_strcat(
        std::to_string(1).c_str(), "_", std::to_string(2).c_str()));
    std::string ans = cache->read(key, false);
    ans = crypto_manager->enclave_aes_128_gcm_decrypt(ans);
  }
  ENCLAVE_LOG("[enclave] -- Cache test for read is passed.\n");
  return SGX_SUCCESS;
}