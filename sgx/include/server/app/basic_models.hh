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
#include <rapidjson/document.h>

#include <stdint.h>
#include <string>
#include <vector>

// Fixed.
#define DEFAULT_ORAM_DATA_SIZE 4096
#define DEFAULT_ORAM_BLOCK_SIZE 4160
#define DEFAULT_SLOT_SIZE 32

namespace sgx_oram {
// If we need to transfer data between the untrusted memory and the enclave, we better
// organize all the data structures in a C-like style for best performance.

typedef struct _oram_block_header_t {
  // The block identifier.
  uint32_t bid;
  // The block address (real).
  uint32_t address;
} oram_block_header_t;

// The ORAM block (4096 + 32 + 32) bytes in total.
typedef struct _oram_block_t {
  // The block header.
  oram_block_header_t header;
  // The block data.
  uint8_t data[DEFAULT_ORAM_DATA_SIZE];
} oram_block_t;

typedef struct _oram_slot_header_t {
  // The range of the slot.
  uint32_t range_begin;
  uint32_t range_end;
  // The level of the slot.
  uint32_t level;
  // The available space of the slot.
  uint32_t dummy_number;
} oram_slot_header_t;

typedef struct _oram_slot_t {
  // The slot header.
  oram_slot_header_t header;
  // The storage of the slot.
  oram_block_t blocks[DEFAULT_SLOT_SIZE];
} oram_slot_t;

typedef struct _oram_position_t {
  // The level.
  uint32_t level;
  // The current bid.
  uint32_t bid;
  // The address. 
  uint32_t address;
} oram_position_t;
}  // namespace sgx_oram