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
#include "oram_utils.h"

#include <fstream>
#include <sstream>

#include <spdlog/spdlog.h>

extern std::shared_ptr<spdlog::logger> logger;

namespace oram_utils {
std::string read_key_crt_file(const std::string& path) {
  std::ifstream file(path, std::ifstream::in);
  std::ostringstream oss;

  if (file.good()) {
    oss << file.rdbuf();
    file.close();
  } else {
    logger->error("Failed to read key file: {}", path);
    return "";
  }

  return oss.str();
}

void safe_free(void* ptr) {
  if (ptr != nullptr) {
    free(ptr);
  } else {
    logger->error("Failed to free nullptr");
  }
}

void safe_free_all(size_t ptr_num, ...) {
  va_list ap;
  va_start(ap, ptr_num);
  for (size_t i = 0; i < ptr_num; ++i) {
    void* ptr = va_arg(ap, void*);
    safe_free(ptr);
  }
  va_end(ap);
}

void convert_to_block(const std::string& data,
                      partition_oram::oram_block_t* const block) {
  PANIC_IF(data.size() != ORAM_BLOCK_SIZE, "Invalid data size");

  memcpy(block, data.data(), ORAM_BLOCK_SIZE);
}

void check_status(partition_oram::Status status, const std::string& reason) {
  if (status != partition_oram::Status::OK) {
    logger->error("{}", reason);
    abort();
  }
}
}  // namespace oram_utils