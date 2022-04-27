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
#include <enclave/enclave_u.h>
#include <enclave/enclave_utils.hh>

template <typename key_type, typename value_type>
std::shared_ptr<EnclaveCache<key_type, value_type>>
    EnclaveCache<key_type, value_type>::instance_;

template <typename key_type, typename value_type>
EnclaveCache<key_type, value_type>::EnclaveCache(size_t max_size)
    : max_size_(max_size), cache_list_(), key_map_() {
  // Check the maximum size of the cache, just a sanity check.
  if (max_size_ * sizeof(sgx_oram::oram_slot_leaf_t) > maximum_cache_size) {
    ENCLAVE_LOG("[enclave] Due to the size limitation, the cache cannot be created.");
    ocall_panic_and_flush("Cache pool cannot be created due to EPC limit.");
  }
  ENCLAVE_LOG("[enclave] Cache pool created.");
}

template <typename key_type, typename value_type>
std::shared_ptr<EnclaveCache<key_type, value_type>>
EnclaveCache<key_type, value_type>::get_instance(void) {
  if (instance_ == nullptr) {
    instance_ = std::shared_ptr<EnclaveCache<key_type, value_type>>();
  }
  return instance_;
}

// FIXME: The target key value may exist in the external memory,
//        but the key value may not exist in the cache.
template <typename key_type, typename value_type>
void EnclaveCache<key_type, value_type>::write(const key_type& key,
                                               const value_type& value) {
  auto it = key_map_.find(key);
  if (it != key_map_.end()) {
    ENCLAVE_LOG("[enclave] Cache hit.");
    cache_list_.splice(cache_list_.begin(), cache_list_, it->second);
    it->second = cache_list_.begin();
  } else {
    ENCLAVE_LOG("[enclave] Cache miss on key %s.", hex_to_string(key).c_str());
    ENCLAVE_LOG("[enclave] Fetch from the external memory and cache it.");
    // TODO: How to handle cache miss on write?
    cache_list_.push_front(cache_entry_t(key, value));
    key_map_[key] = cache_list_.begin();
    if (cache_list_.size() > max_size_) {
      auto last = cache_list_.end();
      last--;
      key_map_.erase(last->first);
      cache_list_.pop_back();
    }
  }
}

template <typename key_type, typename value_type>
value_type EnclaveCache<key_type, value_type>::read(const key_type& key) {
  auto it = key_map_.find(key);
  if (it == key_map_.end()) {
    ENCLAVE_LOG("[enclave] Cache miss on key %s", hex_to_string(key).c_str());
    ENCLAVE_LOG("[enclave] Fetching from external memory...");
    // TODO: Invoke an OCALL and get the value from external memory.
    return value_type();
  }
  cache_list_.splice(cache_list_.begin(), cache_list_, it->second);
  it->second = cache_list_.begin();
  return it->second->second;
}