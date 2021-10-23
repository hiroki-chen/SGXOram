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
#ifndef MODELS_HH
#define MODELS_HH

#include <cstdint>
#include <vector>
#include <map>
#include <memory>
#include <string>

namespace sgx_oram {

/**
 * @brief This is the implementation of each block in the ORAM.
 * 
 */
typedef struct Block {
    bool is_dummy;

    std::string data;

    uint32_t bid;

    Block(const bool& is_dummy, const std::string& data, const uint32_t& bid);

    Block(const bool& is_dummy);
} Block;

/**
 * @brief This is the implementation of the ORAM slot
 * 
 */
typedef class Slot {
protected:
    // Stores the block.
    std::vector<Block> storage;
public:
    void add_block(const Block& block);

    Slot(const uint32_t& size);
} Slot;

/**
 * @brief This is the main body of the ORAM.
 * 
 * !! INDEX OF THE SLOT STARTS AT 0 !!
 */
typedef class Oram {
private:
    // This is the storage type of the oram. Usage: [level_num][bid_range]
    std::vector<std::vector<Slot>> slots;

    // The position map. Usage: position[address] = (level, id).
    std::map<uint32_t, std::pair<uint32_t, uint32_t>> position_map;

    // The way of the tree.
    const uint32_t p;

    // The total level of the tree.
    const uint32_t level;

    // The number of the blocks
    const uint32_t block_number;

public:
    Oram(const uint32_t& p, const uint32_t& block_number);

    /**
     * @brief Access the SGXOram.
     * 
     * @param op        op == 0 means a read operation.
     * @param bid 
     * @param data      op == 0, data = \perp. Otherwise we write data to the position of address.
     */
    void oram_access(const bool& op, const uint32_t& address, std::string& data);
} Oram;

} // namespace sgx_oram

#endif