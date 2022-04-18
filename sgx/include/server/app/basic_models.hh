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
#include <rapidjson/document.h>

#include <stdint.h>
#include <string>
#include <vector>

// Fixed. Better not chan
#define DEFAULT_ORAM_DATA_SIZE 4096
#define DEFAULT_ORAM_BLOCK_SIZE 4160
#define DEFAULT_SLOT_SIZE 32

namespace sgx_oram {
// TODO: Defined a C-like struct for all the data structures so as to do
// serialization and deserialization.

// The ORAM block (4096 + 32 + 32) bytes in total.
typedef struct _oram_block_t {
  // The block identifier.
  uint32_t bid;
  // The block address (real).
  uint32_t address;
  // The block data.
  uint8_t data[DEFAULT_ORAM_DATA_SIZE];
} oram_block_t;

typedef struct _oram_slot_t {
  // The range of the slot.
  uint32_t range_begin;
  uint32_t range_end;
  // The level of the slot.
  uint32_t level;
  // The available space of the slot.
  uint32_t dummy_number;
  // The storage of the slot.
  std::vector<oram_block_t> blocks;
} oram_slot_t;

typedef struct Position {
  uint32_t level_cur;

  // Offset starts at 0. :))
  uint32_t offset;

  uint32_t bid_cur;

  uint32_t bid_dst;

  // Offset levelwise.
  uint32_t slot_num;

  Position() = default;

  /**
   * @brief Construct a new Position object
   *
   * @param level_cur
   * @param offset
   * @param bid_cur
   * @param bid_dst  By default this should be 0xffffffff.
   */
  Position(const uint32_t& level_cur, const uint32_t& offset,
           const uint32_t& bid_cur, const uint32_t& bid_dst = 0xffffffff);

} Position;

/**
 * @brief This is the implementation of each block in the ORAM.
 *
 */
typedef struct Block {
  bool is_dummy;

  std::string data;

  uint32_t bid;

  uint32_t address;  // unique id.

  /**
   * @brief Deserialize a block from json.
   *
   * @details In order to transfer data between the enclave and the untrusted
   *          memory space, we need to implement serialization.
   *
   * @param json
   * @return Block
   */
  static Block from_json(const std::string& json);

  static Block from_value(const rapidjson::Value& value);

  std::string to_json(void) const;

  Block(const bool& is_dummy, const std::string& data, const uint32_t& bid,
        const uint32_t& address = 0xffffffff);

  Block(const bool& is_dummy);

  Block() = default;
} Block;

/**
 * @brief This is the implementation of the ORAM slot
 *
 * @note Storage layout:
 *                                      O                   L
 *                                  O  O  O  O              L-1
 *                                O O O O O O O O O         L-2
 *                                      ....                ...
 *                                      O O OO              1 <----- At this
 * level we could store buckets.
 */
typedef struct Slot {
  // Stores the block.
  std::vector<Block> storage;

  // The bid range that the current slot can handle.
  std::pair<uint32_t, uint32_t> range;

  uint32_t level;

  // This is used to generate a random position for receiving a data from S1.
  uint32_t dummy_number;

  void add_block(const Block& block, const uint32_t& pos);

  void set_range(const uint32_t& begin, const uint32_t& end);

  void set_level(const uint32_t& level);

  std::pair<uint32_t, uint32_t> get_range(void) { return range; }

  bool in(const uint32_t& bid);

  uint32_t size(void) { return (uint32_t)storage.size(); };

  static Slot from_json(const std::string& json);

  std::string to_json(void) const;

  Slot(const uint32_t& size);

  Slot() = default;
} Slot;
}  // namespace sgx_oram