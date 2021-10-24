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
#include <cmath> // WARNING: FOR CLANG ON MACOS CATALINA OR HIGHER, CMATH IS CORRUPTED...
#include <random>

#include <models.hh>
#include <plog/Appenders/ColorConsoleAppender.h>
#include <plog/Formatters/TxtFormatter.h>
#include <plog/Initializers/RollingFileInitializer.h>
#include <plog/Log.h>
#include <plog/Logger.h>
#include <utils.hh>

static plog::RollingFileAppender<plog::TxtFormatter> file_appender("./log/log.out"); // Create the 1st appender.
static plog::ColorConsoleAppender<plog::TxtFormatter> consoler_appender; // Create the 2nd appender.

sgx_oram::Position::Position(
    const uint32_t& level_cur,
    const uint32_t& offset,
    const uint32_t& bid_cur,
    const uint32_t& bid_dst)
    : level_cur(level_cur)
    , offset(offset)
    , bid_cur(bid_cur)
    , bid_dst(bid_dst)
{
}

sgx_oram::Block::Block(const bool& is_dummy, const std::string& data, const uint32_t& bid)
    : is_dummy(is_dummy)
    , data(data)
    , bid(bid)
{
}

sgx_oram::Block::Block(const bool& is_dummy)
    : is_dummy(is_dummy)
{
}

sgx_oram::Slot::Slot(const uint32_t& size)
{
    storage.reserve(size);
}

sgx_oram::Oram::Oram(const cxxopts::ParseResult& result)
    : constant(result["constant"].as<uint32_t>())
    , p(result["way"].as<uint32_t>())
    , level(1 + std::ceil(std::log(result["number"].as<uint32_t>()) / std::log(p))) // \log_{p}{N} = \log_{N} / \log_{p}
    , block_number((uint32_t)(std::pow(p, level - 1)))
    , verbose(result["verbose"].as<bool>())
{
    // Create a logger.
    plog::init(plog::debug, &file_appender).addAppender(&consoler_appender);

    std::vector<std::string> data;

    if (result.count("file") != 0) {
        const std::string file_path = result["file"].as<std::string>();
        data_file = new std::ifstream(file_path, std::ios::in);

        if (data_file->good()) {
            PLOG(plog::info) << "Detected input file.";
            data = get_data_from_file(data_file);
        } else {
            PLOG(plog::warning) << "Cannot open the input file on the disk. Try to generate random strings.";
            data = generate_random_strings(block_number, 32);
        }
    } else {
        PLOG(plog::info) << "Generating random strings as input data";
        data = generate_random_strings(block_number, 32);
    }

    // PLOG(plog::debug) << level;

    // Convert to the block vector and initialize the oram controller.
    const std::vector<Block> blocks = convert_to_blocks(data);

    // Initialize the position map.
    init_position_map();

    // If there is no input file, we generate random data.
    PLOG(plog::info) << "The ORAM controller is initialized!";
}

sgx_oram::Parser::Parser(const int& argc, const char** argv)
    : argc(argc)
    , argv(argv)
{
    options = new cxxopts::Options("Simulator",
        " ------ The SGX-Based ORAM Created by Data Security Lab at Nankai University -----\n"
        " Authored by Haobin Chen and Siyi Lv\n"
        " Copyright ©️ Nankai University");

    options->add_options()("c,constant", "The constant multiplicated with the slot size.", cxxopts::value<uint32_t>()->default_value("1"))("f,file", "The file path of the data you want to load into the SGX.", cxxopts::value<std::string>()->default_value("./input.data"))("n,number", "The number of the total blocks.", cxxopts::value<uint32_t>()->default_value("100000"))("v,verbose", "Enable verbose mode", cxxopts::value<bool>()->default_value("false"))("w,way", "The number of ways in the SGX tree.", cxxopts::value<uint32_t>()->default_value("8"))("h,help", "Print usage information.");
}

/*
    We first calculate the size of the sgx tree, and then we do a permutation, according to which the bid is stored.
 */
void sgx_oram::Oram::init_position_map(void)
{
    uint32_t sgx_size = 0;
    uint32_t cur_size = 1;

    // This vector is used to look up the size of each level (in blocks).
    std::vector<uint32_t> level_size_information;
    // We traverse from the root to the leaf.
    for (uint32_t i = 0; i < level; i++) {
        const uint32_t cur_slot_num = (uint32_t)(std::pow(p, i));
        cur_size *= std::min(level, i + 1);
        sgx_size += cur_size * cur_slot_num;
        level_size_information.push_back(cur_size);
    }

    LOG(plog::debug) << "The size of the SGX tree is " << sgx_size;

    // Permute the position... We first load it into the permutation vector and then do a random shuffle.
    std::vector<uint32_t> permutation_vec(sgx_size, 0xffffffff);
    for (uint32_t i = 0; i < block_number; i++) {
        permutation_vec[i] = i;
    }
    // Shuffle the permutation vector.
    std::random_device rd;
    std::mt19937 engine(rd());
    std::shuffle(permutation_vec.begin(), permutation_vec.end(), engine);

    // Initialize the position map according to the permutation vector.
    // This is an inverted vector where index is the position.
    for (uint32_t i = 0; i < permutation_vec.size(); i++) {
        // 0xfffffff denotes a piece of dummy permutation information.
        if (permutation_vec[i] != 0xffffffff) {
            const Position position = get_position(i, level_size_information);
            if (verbose) {
                PLOG(plog::debug) << "The position for item " << permutation_vec[i] << " is " << position; 
            }
        }
    }
}

sgx_oram::Position
sgx_oram::Oram::get_position(const uint32_t& permutated_pos, const std::vector<uint32_t>& level_size_information)
{
    uint32_t cur = permutated_pos;
    uint32_t i = 0;
    uint32_t level_size = level_size_information[i] * (uint32_t)(std::pow(p, i));
    while (cur + 1 >= level_size) {
        cur -= level_size;
        i++;
        level_size = level_size_information[i] * (uint32_t)(std::pow(p, i));
    }
    const uint32_t level_cur = level - i;
    
    // TODO: We now get the current level, and the value "cur" can be used to locate the bid_cur.
    return Position(level_cur, 0xffffffff, 0xffffffff, 0xffffffff);
}

void sgx_oram::Parser::parse(void)
{
    result = options->parse(argc, argv);

    if (result.count("help")) {
        std::cout << options->help() << std::endl;
        exit(0);
    }
}