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
#ifndef BASIC_MODELS_HH
#define BASIC_MODELS_HH

#include <stdint.h>

// Fixed.
#define DEFAULT_ORAM_DATA_SIZE 4096

#define ORAM_BLOCK_HEADER_SIZE sizeof(sgx_oram::oram_block_header_t)
#define ORAM_SLOT_HEADER_SIZE sizeof(sgx_oram::oram_slot_header_t)
#define ORAM_POSITION_SIZE sizeof(sgx_oram::oram_position_t)
#define ORAM_BLOCK_SIZE sizeof(sgx_oram::oram_block_t)
#define ORAM_SLOT_INTERNAL_SIZE sizeof(sgx_oram::oram_slot_t)
#define ORAM_SLOT_LEAF_SIZE sizeof(sgx_oram::oram_slot_leaf_t)

#define WORD_SIZE 4

#define ENCRYPTED_POSITION_SIZE \
  sizeof(sgx_oram::oram_position_t) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE

#define ENCRYPTED_SLOT_SIZE \
  sizeof(sgx_oram::oram_slot_leaf_t) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE

#define ENCRYPTED_BLOCK_SIZE \
  sizeof(sgx_oram::oram_block_t) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE

// If the compiler does not give the macro, use the default value.
#ifndef DEFAULT_SLOT_SIZE
#define DEFAULT_SLOT_SIZE 32
#endif

#ifndef DEFAULT_BUCKET_SIZE
#define DEFAULT_BUCKET_SIZE 64
#endif

namespace sgx_oram {
// If we need to transfer data between the untrusted memory and the enclave, we
// better organize all the data structures in a C-like style for best
// performance.

typedef enum _oram_slot_type {
  ORAM_SLOT_TYPE_LEAF = 0,
  ORAM_SLOT_TYPE_INTERNAL = 1,
  ORAM_SLOT_TYPE_INVALID = 2
} oram_slot_type_t;

typedef enum _oram_block_type {
  ORAM_BLOCK_TYPE_NORMAL = 0,
  ORAM_BLOCK_TYPE_DUMMY = 1,
  ORAM_BLOCK_TYPE_INVALID = 2
} oram_block_type_t;

typedef struct _oram_block_header_t {
  // The type of the block.
  oram_block_type_t type;
  // The block identifier.
  uint32_t bid;
  // The block address (real).
  uint32_t address;
} oram_block_header_t;

// The ORAM block of 4096 bytes in total.
// It is enforced that the block size is a multiple of the word size.
typedef struct _oram_block_t {
  // The block header.
  oram_block_header_t header;
  // The block data.
  uint8_t data[DEFAULT_ORAM_DATA_SIZE];
} oram_block_t;

typedef struct _oram_slot_header_t {
  // The slot type.
  oram_slot_type_t type;
  // The level at which the slot is located.
  uint16_t level;
  uint16_t offset;
  // The range of the slot.
  uint32_t range_begin;
  uint32_t range_end;
  // The available space of the slot.
  // Note that the actual space is much bigger than the available space
  // because we need to allocate the buffer in advance; thus we cannot
  // predict the actual space.
  uint32_t dummy_number;
  uint32_t slot_size;
} oram_slot_header_t;

typedef struct _oram_slot_t {
  // The slot header.
  oram_slot_header_t header;
  // The storage of the slot.
  oram_block_t blocks[DEFAULT_SLOT_SIZE];
} oram_slot_t;

typedef struct _oram_slot_leaf_t {
  // The slot header.
  oram_slot_header_t header;
  // The storage of the slot.
  oram_block_t blocks[DEFAULT_BUCKET_SIZE];
} oram_slot_leaf_t;

typedef struct _oram_position_t {
  // The level.
  uint32_t level;
  // The current bid.
  uint32_t bid;
  // The address.
  uint32_t address;
} oram_position_t;

typedef struct _oram_configuration_t {
  uint32_t way;
  uint32_t number;
  uint32_t bucket_size;
  uint32_t type;
  uint32_t constant;
  uint32_t round;
  uint32_t level;
  uint32_t oram_type;
} oram_configuration_t;

typedef enum _oram_operation_t {
  ORAM_OPERATION_READ = 0,
  ORAM_OPERATION_WRITE = 1,
  ORAM_OPERATION_INVALID = 2
} oram_operation_t;

}  // namespace sgx_oram

#endif  // BASIC_MODELS_HH