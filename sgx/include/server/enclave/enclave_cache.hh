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
#ifndef ENCLAVE_CACHE_HH
#define ENCLAVE_CACHE_HH

#include <cstdint>
#include <list>
#include <memory>
#include <unordered_map>

constexpr uint32_t maximum_cache_size_in_bytes = 96 * 1024 * 1024;
constexpr uint32_t maximum_cache_size = 32;

// The cache is implemented as a LRU cache.
// Key type is the hashed fingerprint of the slot, and the value type is the
// slot itself in byte array (or std::string for convenience, because we don't
// need check the buffer length).
template <typename key_type, typename value_type>
class EnclaveCache {
  using cache_entry_t = typename std::pair<key_type, value_type>;
  using cache_list_t = std::list<cache_entry_t>;
  using key_list_iterator_t = typename cache_list_t::iterator;
  using key_map_t = std::unordered_map<key_type, key_list_iterator_t>;

 private:
  size_t max_size_;
  cache_list_t cache_list_;
  key_map_t key_map_;

  static std::shared_ptr<EnclaveCache> instance_;

  // The constructor is private to ensure that the cache is created
  // through the static get_instance() method to prevent multiple
  // instances of the cache, which does not make sense.
  EnclaveCache(size_t max_size = maximum_cache_size);

 public:
  static std::shared_ptr<EnclaveCache> get_instance(void);

  // Update the cache with the new slot.
  // If the entry already exists, it will be moved to the front of the cache.
  void write(const key_type& key, const value_type& value);

  // Get the value of the entry with the given key.
  // - If the entry does not exist, return nullptr.
  // - If the entry exists in the external memory, it will be moved to the front
  //   of the cache.
  value_type read(const key_type& key);
};

#endif  // ENCLAVE_CACHE_HH