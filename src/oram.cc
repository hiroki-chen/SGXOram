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
    , data(data.begin(), data.end())
    , bid(bid)
{
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

    // Convert to the block vector and initialize the oram controller.
    const std::vector<Block> blocks = convert_to_blocks(data);

    // Initialize the position map.
    init_position_map();

    // Initilize the slot level by level.
    init_slot();

    init_sgx(blocks);

    // If there is no input file, we generate random data.
    PLOG(plog::info) << "The ORAM controller is initialized!";

    if (verbose) {
        print_sgx();
    }
}

/*
    We first calculate the size of the sgx tree, and then we do a permutation, according to which the bid is stored.
 */
void sgx_oram::Oram::init_position_map(void)
{
    uint32_t sgx_size = 0;
    uint32_t cur_size = 1;

    // This vector is used to look up the size of each level (in blocks).

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
        const uint32_t address = permutation_vec[i];
        if (address != 0xffffffff) {
            Position position = get_position(i, level_size_information);
            if (verbose) {
                PLOG(plog::debug) << "The position for item " << address << " is " << position << " raw: " << i;
            }
            position_map[address] = position;
        }
    }
}

sgx_oram::Position
sgx_oram::Oram::get_position(const uint32_t& permutated_pos, const std::vector<uint32_t>& level_size_information)
{
    uint32_t cur = permutated_pos;
    uint32_t i = 0;
    uint32_t level_size = level_size_information[i] * (uint32_t)(std::pow(p, i));
    while (cur >= level_size) {
        cur -= level_size;
        i++;
        level_size = level_size_information[i] * (uint32_t)(std::pow(p, i));
    }
    const uint32_t level_cur = i;
    // TODO: We now get the current level, and the value "cur" can be used to locate the bid_cur.
    const uint32_t slot_pos = std::floor(cur * 1.0 / level_size_information[i]);
    const uint32_t offset = cur - slot_pos * level_size_information[i];

    Position position = Position(level_cur, offset, 0xffffffff, 0xffffffff);
    position.slot_num = slot_pos;
    return position;
}

void sgx_oram::Oram::init_slot(void)
{
    LOG(plog::info) << "The ORAM controller is initializing the SGX storage tree level by level...";

    // Although we mark the leaf level as 1, for computational convernience, we still
    // traverse from 0 to L - 1, i.e., from root to leaf.
    for (uint32_t i = 0; i < level; i++) {
        const uint32_t slot_num_cur = (uint32_t)std::pow(p, i);
        std::vector<Slot> slot_vec;
        for (uint32_t j = 0; j < slot_num_cur; j++) {
            // Set basic information for the slot.
            // Note that the range is bigger when the node is closer to the root!
            const uint32_t level_size = (uint32_t)(std::pow(p, level - 1 - i));
            const uint32_t begin = j * level_size;
            const uint32_t end = begin + level_size - 1; // Starts at 0.
            const uint32_t slot_size = (uint32_t)(std::floor(constant * level_size_information[i]));
            Slot slot(slot_size);
            slot.set_level(i);
            slot.set_range(begin, end);
            slot_vec.push_back(slot);
        }
        slots.push_back(slot_vec);
        // LOG(plog::debug) << i << ": " << slots[i][0].size();
    }

    LOG(plog::info) << "The ORAM has initialized the SGX storage tree.";
}

void sgx_oram::Oram::init_sgx(const std::vector<Block>& blocks)
{
    LOG(plog::info) << "The ORAM controller is loading the SGX data...";
    // Fill each slot with given blocks.
    for (uint32_t i = 0; i < blocks.size(); i++) {
        // Read the position from the position map.
        const Position& position = position_map[i];
        const uint32_t level = position.level_cur;
        const uint32_t slot_num = position.slot_num;
        const uint32_t offset = position.offset;
        // PLOG(plog::info) << "reading " << i << " position " << position;
        slots[level][slot_num].add_block(blocks[i], offset);
    }

    LOG(plog::info) << "The ORAM controller has initialized the SGX data.";
}

void sgx_oram::Oram::print_sgx(void)
{
    for (uint32_t i = 0; i < slots.size(); i++) {
        LOG(plog::debug) << "LEVEL " << i << ": ";
        for (uint32_t j = 0; j < slots[i].size(); j++) {
            LOG(plog::debug) << slots[i][j];
        }
    }
}

namespace sgx_oram {
plog::Record& operator<<(plog::Record& record, const sgx_oram::Slot& slot)
{
    const auto storage = slot.storage;
    record << "Slot range: [" << slot.range.first << ", " << slot.range.second << "]";
    for (auto item : storage) {
        record << std::endl << "is_dummy: " << item.is_dummy << " data: " << item.data << std::endl;
    }

    return record;
}
}
