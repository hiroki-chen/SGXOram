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

#include <basic_models.hh>

#define CACHE_DIRTY_BIT 0b1

constexpr size_t maximum_cache_size_in_bytes = 96 * 1024 * 1024;
constexpr size_t maximum_cache_size = 16;
constexpr size_t maximum_cache_size_for_header = 256;

using sgx_oram::cache_type_t;

/**
 * @brief The cache is implemented as a LRU cache.
 * - Key type is the hashed fingerprint of the slot, and the value type is the
 *   slot itself in byte array (or std::string for convenience, because we don't
 *   need check the buffer length).
 * - The cache DOES NOT do any cryptographic operations. It only stores the
 *   fingerprint of the slot and the slot itself.
 *
 */
class EnclaveCache {
  using value_t = std::pair<uint32_t, std::string>;
  using cache_entry_t = std::pair<std::string, value_t>;
  using cache_list_t = std::list<cache_entry_t>;
  using key_list_iterator_t = cache_list_t::iterator;
  using key_map_t = std::unordered_map<std::string, key_list_iterator_t>;

 private:
  size_t max_size_;
  cache_list_t cache_list_;
  key_map_t key_map_;
  cache_type_t cache_type_;
  // The constructor is private to ensure that the cache is created
  // through the static get_instance_for_slot_body() method to prevent multiple
  // instances of the cache, which does not make sense.
  EnclaveCache(size_t max_size, cache_type_t cache_type);

  void replace_item(const std::string& key, const std::string& value,
                    bool is_dirty, bool is_body);

  std::string internal_read(const std::string& key, size_t size, bool is_body);

 public:
  static std::shared_ptr<EnclaveCache> get_instance_for_slot_body(void);
  static std::shared_ptr<EnclaveCache> get_instance_for_slot_header(void);

  /**
   * @brief Update the cache with the new slot. If the entry already exists, it
   * will be moved to the front of the cache. Also, if the entry is dirty, it
   * will be written back to the external memory; otherwise, it will be ignored
   * and be replaced by the new slot. This is called write-back strategy.
   *
   * @param key
   * @param value
   * @param is_body
   */
  void write(const std::string& key, const std::string& value, bool is_body);

  /**
   * @brief Get the value of the entry with the given key.
   * - If the entry does not exist, return nullptr.
   * - If the entry exists in the external memory, it will be moved to the front
   *   of the cache.
   *
   * @param key
   * @param size
   * @return std::string
   */
  std::string read(const std::string& key, size_t size);

  /**
   * @brief Get the value of the entry with the given key.
   * @note  This is for reading the header since the size of the header is
   *        fixed.
   *
   * @param key
   * @return std::string
   */
  std::string read(const std::string& key);
};

#endif  // ENCLAVE_CACHE_HH