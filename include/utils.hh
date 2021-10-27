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
#ifndef UTILS_HH
#define UTILS_HH

#include <plog/Record.h>
#include <models.hh>

#include <string>
#include <vector>

namespace sgx_oram {
    static const std::string candidate =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    std::vector<std::string> generate_random_strings(const uint32_t& number, const uint32_t& length = 32);

    std::vector<std::string> get_data_from_file(std::ifstream* const file);

    std::vector<Block> convert_to_blocks(const std::vector<std::string>& data);
    
    uint32_t uniform_random(const uint32_t& lower, const uint32_t& upper);
} // sgx_oram

#endif