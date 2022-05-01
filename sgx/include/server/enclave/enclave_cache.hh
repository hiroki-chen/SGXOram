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
#include <string>
#include <unordered_map>

#define CACHE_DIRTY_BIT 0b1

constexpr size_t maximum_cache_size_in_bytes = 96 * 1024 * 1024;
constexpr size_t maximum_cache_size = 16;

// The cache is implemented as a LRU cache.
// Key type is the hashed fingerprint of the slot, and the value type is the
// slot itself in byte array (or std::string for convenience, because we don't
// need check the buffer length).
class EnclaveCache {
  using value_t = std::pair<uint32_t, std::string>;
  using cache_entry_t =  std::pair<std::string, value_t>;
  using cache_list_t = std::list<cache_entry_t>;
  using key_list_iterator_t = cache_list_t::iterator;
  using key_map_t = std::unordered_map<std::string, key_list_iterator_t>;

 private:
  size_t max_size_;
  cache_list_t cache_list_;
  key_map_t key_map_;

  static std::shared_ptr<EnclaveCache> instance_;

  bool status = 0;

  // The constructor is private to ensure that the cache is created
  // through the static get_instance() method to prevent multiple
  // instances of the cache, which does not make sense.
  EnclaveCache(size_t max_size = maximum_cache_size);

  void replace_item(const std::string& key, const std::string& value);

 public:
  static std::shared_ptr<EnclaveCache> get_instance(void);

  // Update the cache with the new slot.
  // If the entry already exists, it will be moved to the front of the cache.
  // Also, if the entry is dirty, it will be written back to the external memory;
  // otherwise, it will be ignored and be replaced by the new slot.
  // This is called write-back strategy.
  void write(const std::string& key, const std::string& value, bool leaf_type);

  // Get the value of the entry with the given key.
  // - If the entry does not exist, return nullptr.
  // - If the entry exists in the external memory, it will be moved to the front
  //   of the cache.
  std::string read(const std::string& key, bool leaf_type);

  bool is_cache_enabled() { return status; }
};

#endif  // ENCLAVE_CACHE_HH