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

#include <string>

static const std::string digits = "0123456789abcdef";

std::string hex_to_string(const uint8_t* array, const size_t& len = 32);

void convert_endian(uint8_t* array, const size_t& len = 32);

// safe free.
void safe_free(void* ptr);

void fisher_yates_shuffle(uint32_t* array, const size_t& len);

std::string get_log_file_name(void);

#endif
