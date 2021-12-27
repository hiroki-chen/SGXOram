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

#include <app/basic_models.hh>
#include <cxxopts.hh>

#include <cmath>
#include <cstdint>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#define MAXIMUM_LOG_SIZE 65535

static const std::string enclave_path = "./build/enclave/enclave_signed.so";

namespace sgx_oram {
typedef struct Config {
    double constant;

    uint32_t p;

    uint32_t real_block_num;

    bool verbose;

    uint32_t round;

    uint32_t type;
} Config;

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

    const uint32_t real_block_num;

    // Should be verbosely output the information
    const bool verbose;

    // Test round.
    const uint32_t round;

    // How the slot size is initialized.
    // Type 1: 1 : 2 : 6.... with constant
    // Type 2: p : p : p : p...
    const uint32_t type;

    // For initialization.
    std::vector<uint32_t> level_size_information;

    // The input file path.
    std::ifstream* data_file = nullptr;

    /* ============ Functions ============= */
    void init_oram(void);

    void init_slot(void);

    void init_sgx(std::vector<Block>& blocks);

    void print_sgx(void);

    Slot& get_slot(const uint32_t& bid, const uint32_t& level);

    void set_slot(const uint32_t& bid, const uint32_t& level, const Slot& slot);

    // TODO: Obli_Access_SXX should be implemented in the SGX.
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

    /**
     * @brief Obliviously access Slot S2.
     * 
     * @param op 
     * @param flag 
     * @param slot 
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

    Oram(const Config& config);

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
} // namespace sgx_oram
#endif