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

#include <cstring>
#include <fstream>
#include <sstream>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/bin_to_hex.h>

#include "oram_crypto.h"

extern std::shared_ptr<spdlog::logger> logger;

namespace oram_utils {
std::string ReadKeyCrtFile(const std::string& path) {
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

std::vector<std::string> ReadDataFromFile(const std::string& path) {
  std::ifstream file(path, std::ifstream::in);
  std::vector<std::string> data;

  if (file.good()) {
    std::string line;
    while (std::getline(file, line)) {
      data.emplace_back(line);
    }
    file.close();
  } else {
    logger->error("Failed to read data file: {}", path);
  }
  return data;
}

void SafeFree(void* ptr) {
  if (ptr != nullptr) {
    free(ptr);
  } else {
    logger->error("Failed to free nullptr");
  }
}

void SafeFreeAll(size_t ptr_num, ...) {
  va_list ap;
  va_start(ap, ptr_num);
  for (size_t i = 0; i < ptr_num; ++i) {
    void* ptr = va_arg(ap, void*);
    SafeFree(ptr);
  }
  va_end(ap);
}

void ConvertToBlock(const std::string& data,
                    partition_oram::oram_block_t* const block) {
  PANIC_IF(data.size() != ORAM_BLOCK_SIZE, "Invalid data size");

  memcpy(block, data.data(), ORAM_BLOCK_SIZE);
}

void ConvertToString(const partition_oram::oram_block_t* const block,
                     std::string* const data) {
  data->resize(ORAM_BLOCK_SIZE);
  memcpy(data->data(), (void*)block, ORAM_BLOCK_SIZE);
}

void CheckStatus(partition_oram::Status status, const std::string& reason) {
  if (status != partition_oram::Status::kOK) {
    logger->error("{}", reason);
    abort();
  }
}

void PadStash(partition_oram::p_oram_stash_t* const stash,
              const size_t bucket_size) {
  const size_t stash_size = stash->size();
  if (stash_size < bucket_size) {
    for (size_t i = stash_size; i < bucket_size; ++i) {
      partition_oram::oram_block_t dummy;

      if (oram_crypto::Cryptor::RandomBytes((uint8_t*)(&dummy),
                                            ORAM_BLOCK_SIZE) !=
          partition_oram::Status::kOK) {
        logger->error("Failed to generate random bytes");
        abort();
      }

      stash->emplace_back(dummy);
    }
  }
}

std::vector<std::string> SerializeToStringVector(
    const partition_oram::p_oram_bucket_t& bucket) {
  std::vector<std::string> ans;

  for (size_t i = 0; i < bucket.size(); ++i) {
    std::string data;
    ConvertToString(&bucket[i], &data);
    ans.emplace_back(data);
  }

  return ans;
}

partition_oram::p_oram_bucket_t DeserializeFromStringVector(const std::vector<std::string>& data) {
  partition_oram::p_oram_bucket_t ans;

  for (size_t i = 0; i < data.size(); ++i) {
    partition_oram::oram_block_t block;
    ConvertToBlock(data[i], &block);
    ans.emplace_back(block);
  }

  return ans;
}

void PrintStash(const partition_oram::p_oram_stash_t& stash) {
  for (size_t i = 0; i < stash.size(); ++i) {
    std::string data;
    ConvertToString(&stash[i], &data);
    logger->info("{}", spdlog::to_hex(data));
  }
}  // namespace oram_utils