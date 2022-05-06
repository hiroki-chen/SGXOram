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
#ifndef ORAM_STORAGE_H
#define ORAM_STORAGE_H

#include <cstdint>
#include <cstddef>
#include <cmath>
#include <vector>

#define DEFAULT_ORAM_DATA_SIZE 4096

// The header containing metadata.
typedef struct _oram_block_header_t {

} oram_block_header_t;

// The block for ORAM storage.
typedef struct _oram_block_t {
  oram_block_header_t header;

  uint8_t data[DEFAULT_ORAM_DATA_SIZE];
} oram_block_t;

namespace partition_oram {
  class BinaryTree {
    size_t size;
    size_t height;

    public:
      BinaryTree(size_t num_of_blocks);

      size_t get_size(void) const { return size; }

      size_t get_height(void) const { return height; }

      size_t get_leaf_number(void) const { return std::pow(2, height) - 1; }

      std::vector<oram_block_t> read_bucket();

      virtual ~BinaryTree() {};
  };

  class PartitionOramStorage {

  };
} // namespace partition_oram

#endif // ORAM_STORAGE_H