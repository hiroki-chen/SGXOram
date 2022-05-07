/*
 Copyright (c) 2022 Haobin Chen

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
#ifndef ORAM_UTILS_H
#define ORAM_UTILS_H

#include <cassert>
#include <string>
#include <sstream>

#include "oram_defs.h"

#define PANIC_IF(cond, message) assert(!(cond) && message)

namespace oram_utils {
std::string read_key_crt_file(const std::string& path);

template <typename... Args>
std::string string_concat(const std::string& s, Args&&... args) {
  std::ostringstream oss;
  oss << s;
  // Recursively concatenate the rest of the arguments using argument pack
  // expansion and perfect forwarding.
  (oss << ... << std::forward<Args>(args));
  return oss.str();
}

void safe_free(void* ptr);

void safe_free_all(size_t ptr_num, ...);

void convert_to_block(const std::string& data, partition_oram::oram_block_t* const block);

void check_status(partition_oram::Status status, const std::string& reason);
}  // namespace oram_utils

#endif  // ORAM_UTILS_H