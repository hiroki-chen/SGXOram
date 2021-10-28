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
#include <plog/Record.h>

#include <cmath>
#include <cstdint>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#define MAXIMUM_LOG_SIZE 65535

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
typedef class Slot {
private:
    // Stores the block.
    std::vector<Block> storage;

    // The bid range that the current slot can handle.
    std::pair<uint32_t, uint32_t> range;

    uint32_t level;

    // This is used to generate a random position for receiving a data from S1.
    uint32_t dummy_number;

    friend class Oram;

public:
    void add_block(const Block& block, const uint32_t& pos);

    void set_range(const uint32_t& begin, const uint32_t& end);

    void set_level(const uint32_t& level);

    std::pair<uint32_t, uint32_t> get_range(void) { return range; }

    bool in(const uint32_t& bid);

    friend plog::Record& operator<<(plog::Record& record, const Slot& slot);

    uint32_t size(void) { return storage.size(); };

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
    const double constant;

    // The way of the tree.
    const uint32_t p;

    // The total level of the tree.
    const uint32_t level;

    // The number of the blocks
    uint32_t block_number;

    // Should be verbosely output the information
    const bool verbose;

    // Test round.
    const uint32_t round;

    // For initialization.
    std::vector<uint32_t> level_size_information;

    // The input file path.
    std::ifstream* data_file;

    /* ============ Functions ============= */
    void init_slot(void);

    void init_sgx(std::vector<Block>& blocks);

    void print_sgx(void);

    Slot& get_slot(const uint32_t& bid, const uint32_t& level);

    void set_slot(const uint32_t& bid, const uint32_t& level, const Slot& slot);

    /**
     * @brief Obliviously access Slot S1.
     * 
     * @param op 
     * @param flag 
     * @param slot
     * @param data 
     * @param level 
     * @param address 
     * 
     * @return Block
     */
    Block
    obli_access_s1(
        const bool& op,
        const bool& flag,
        Slot& slot,
        std::string& data,
        const uint32_t& level,
        const Position& position);

    // FIXME: ObliviousAccessSx will accidentally overwrite the data, check what is happening.

    /**
     * @brief Obliviously access Slot S2.
     * 
     * @param op 
     * @param flag 
     * @param slot 
     * @param next_slot
     * @param data1 
     * @param data 
     * @param level 
     * @param address 
     * @return Block 
     */
    Block
    obli_access_s2(
        const bool& op,
        const bool& flag,
        Slot& slot,
        Slot& next_slot,
        const Block& data1,
        std::string& data,
        const uint32_t& level,
        const Position& position);

    /**
     * @brief Obliviously access Slot S3.
     * 
     * @param rbid 
     * @param data2 
     * @param slot 
     * @param level 
     * @param address 
     */
    void
    obli_access_s3(
        const uint32_t& rbid,
        const Block& data2,
        Slot& slot,
        const uint32_t& level,
        const Position& position);

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

    void run_test(void);
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

plog::Record& operator<<(plog::Record& record, const Position& position);
} // namespace sgx_oram

#endif