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

#include <cxxopts.hh>

#include <cstdint>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace sgx_oram {

typedef struct Position {
    uint32_t level_cur;

    uint32_t offset;

    uint32_t bid_cur;

    uint32_t bid_dst;

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

    Block(const bool& is_dummy, const std::string& data, const uint32_t& bid);

    Block(const bool& is_dummy);
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

    // The position map. Usage: position[address] = (level, x, bid_cur, bid_dst)
    std::map<uint32_t, Position> position_map;

    // Constant
    const uint32_t constant;

    // The way of the tree.
    const uint32_t p;

    // The total level of the tree.
    const uint32_t level;

    // The number of the blocks
    const uint32_t block_number;

    const bool verbose;

    // The input file path.
    std::ifstream* data_file;

    /* ============ Functions ============= */
    void init_position_map(void);

    void init_oram(const std::vector<Block>& blocks);

    Position get_position(const uint32_t& permutated_pos, const std::vector<uint32_t>& level_size_information);
public:
    Oram() = delete;

    Oram(const cxxopts::ParseResult& result);

    /**
     * @brief Access the SGXOram.
     * 
     * @param op        op == 0 means a read operation.
     * @param bid 
     * @param data      op == 0, data = \perp. Otherwise we write data to the position of address.
     */
    void oram_access(const bool& op, const uint32_t& address, std::string& data);
} Oram;

/**
 * @brief Class for the command line parser.
 * 
 */
typedef class Parser {
private:
    cxxopts::ParseResult result;

    cxxopts::Options* options;

    const int argc;

    const char** argv;

public:
    Parser() = delete;

    /**
     * @brief Construct a new Parser object
     * 
     * @param argc 
     * @param argv 
     * @note        argc and argv are captured from main function.
     */
    Parser(const int& argc, const char** argv);

    void parse(void);

    cxxopts::ParseResult get_result(void) { return result; }
} Parser;

} // namespace sgx_oram

#endif