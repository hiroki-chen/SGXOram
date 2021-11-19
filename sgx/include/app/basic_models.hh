/*
 Copyright (c) 2021 Haobin Chen

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

#include <stdint.h>
#include <string>
#include <vector>

namespace sgx_oram {
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
    Position(const uint32_t& level_cur, const uint32_t& offset, const uint32_t& bid_cur, const uint32_t& bid_dst = 0xffffffff);
} Position;

/**
 * @brief This is the implementation of each block in the ORAM.
 * 
 */
typedef struct Block {
    bool is_dummy;

    std::string data;

    uint32_t bid;

    uint32_t address; // unique id.

    Block(const bool& is_dummy, const std::string& data, const uint32_t& bid, const uint32_t& address = 0xffffffff);

    Block(const bool& is_dummy);

    // Block(const Block& block);

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
 *                                      O O OO              1               <----- At this level we could store buckets.
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

    Slot(const uint32_t& size);
} Slot;
}