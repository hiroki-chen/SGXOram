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

#include <utils.hh>
#include <models.hh>

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
    : p(result["way"].as<uint32_t>())
    , level(std::ceil(std::log(result["number"].as<uint32_t>()) / std::log(p))) // \log_{p}{N} = \log_{N} / \log_{p}
    , block_number((uint32_t)(std::pow(p, level)))
{
    std::vector<std::string> data;

    if (result.count("file") != 0) {
        const std::string file_path = result["file"].as<std::string>();
        data_file = new std::ifstream(file_path, std::ios::in);

        // TODO: process data in
    } else {
        data = generate_random_strings(block_number, 32);
    }

    // Convert to the block vector and initialize the oram controller.
    const std::vector<Block> blocks = convert_to_blocks(data);

    // Initialize the position map.
    init_position_map();

    // If there is no input file, we generate random data.
    std::cout << "[DEBUG:] " << "The ORAM controller is initialized!" << std::endl;
}

sgx_oram::Parser::Parser(const int& argc, const char** argv)
    : argc(argc)
    , argv(argv)
{
    options = new cxxopts::Options("Simulator",
        " ------ The SGX-Based ORAM Created by Data Security Lab at Nankai University -----\n"
        " Authored by Haobin Chen and Siyi Lv\n"
        " Copyright ©️ Nankai University");

    options->add_options()
        ("f,file", "The file path of the data you want to load into the SGX.", cxxopts::value<std::string>()->default_value("./input.data"))
        ("n,number", "The number of the total blocks.", cxxopts::value<uint32_t>()->default_value("100000"))
        ("w,way", "The number of ways in the SGX tree.", cxxopts::value<uint32_t>()->default_value("8"))
        ("h,help", "Print usage information.")
    ;
}

void sgx_oram::Oram::init_position_map(void)
{
    std::random_device rd;
    std::mt19937 engine(rd());
    std::uniform_int_distribution<> dist_level(0, level);

    
    for (uint32_t i = 0; i < block_number; i++) {
        // First designate the level.
        const uint32_t l = dist_level(engine);
    }
}

void sgx_oram::Parser::parse(void)
{
    result = options->parse(argc, argv);

    if (result.count("help")) {
        std::cout << options->help() << std::endl;
        exit(0);
    }
}