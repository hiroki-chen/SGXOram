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
#ifndef ORAM_DEFS_H
#define ORAM_DEFS_H

#include <unordered_map>
#include <utility>
#include <vector>

#define DEFAULT_ORAM_DATA_SIZE 4096

#define ORAM_BLOCK_SIZE sizeof(partition_oram::oram_block_t)

namespace partition_oram {
// The header containing metadata.
typedef struct _oram_block_header_t {
  uint32_t block_id;
} oram_block_header_t;

// The block for ORAM storage.
typedef struct _oram_block_t {
  oram_block_header_t header;

  uint8_t data[DEFAULT_ORAM_DATA_SIZE];
} oram_block_t;

enum Status {
  OK = 0,
  INVALID_ARGUMENT = 1,
  INVALID_OPERATION = 2,
  OUT_OF_MEMORY = 3,
  FILE_NOT_FOUND = 4,
  FILE_IO_ERROR = 5,
  OUT_OF_RANGE = 6,
  SERVER_ERROR = 7,
  UNKNOWN_ERROR = 8,
};

enum Operation {
  READ = 0,
  WRITE = 1,
  INVALID = 2,
};

enum EvictType {
  EVICT_SEQ = 0,
  EVICT_RAND = 1,
};

static const std::unordered_map<Status, std::string> error_list = {
    {OK, "OK"},
    {INVALID_ARGUMENT, "Invalid argument"},
    {INVALID_OPERATION, "Invalid operation"},
    {OUT_OF_MEMORY, "Out of memory"},
    {FILE_NOT_FOUND, "File not found"},
    {FILE_IO_ERROR, "File I/O error"},
    {OUT_OF_RANGE, "Out of range"},
    {SERVER_ERROR, "Server error"},
    {UNKNOWN_ERROR, "Unknown error"},
};

// Alias for Path ORAM.
using p_oram_bucket_t = std::vector<oram_block_t>;
using p_oram_stash_t = std::vector<oram_block_t>;
using p_oram_path_t = std::vector<p_oram_bucket_t>;
using p_oram_position_t = std::unordered_map<uint32_t, uint32_t>;
// Alias for Partition ORAM.
using pp_oram_pos_t = std::pair<uint32_t, uint32_t>;
using pp_oram_position_t = std::unordered_map<uint32_t, pp_oram_pos_t>;
using pp_oram_slot_t = std::vector<std::vector<oram_block_t>>;

struct block_eq {
 private:
  uint32_t block_id;

 public:
  explicit block_eq(uint32_t id) : block_id(id) {}
  inline bool operator()(const oram_block_t& block) const {
    return block.header.block_id == block_id;
  }
};
}  // namespace partition_oram

#endif  // ORAM_DEFS_H