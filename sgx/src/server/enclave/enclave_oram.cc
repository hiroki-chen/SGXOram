/*
 Copyright (c) 2022 Haobin Chen and Siyi Lv

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
#include <algorithm>
#include <cmath>
#include <string.h>

#include <sgx_urts.h>

#include <enclave/enclave_t.h>
#include <enclave/enclave_utils.hh>
#include <enclave/enclave_oram.hh>
#include <enclave/enclave_crypto_manager.hh>

extern EnclaveCryptoManager* crypto_manager;

static sgx_status_t populate_leaf_slot(sgx_oram::oram_slot_leaf_t* slot,
                                       size_t slot_size) {
  printf("[enclave] Populating leaf slot...");
  sgx_oram::oram_slot_header_t* slot_header = &(slot->header);

  // First we should perform a sanity check on
  // whether the slot is really a leaf node.
  if (slot_header->type != sgx_oram::ORAM_SLOT_TYPE_LEAF) {
    printf("[enclave] The slot is not a leaf node.\n");
    return SGX_ERROR_INVALID_PARAMETER;
  }

  const uint32_t slot_begin = slot_header->range_begin;
  for (size_t i = 0; i < slot_size >> 1; i++) {
    // Locate the slot in the storage.
    sgx_oram::oram_block_t* block_ptr = &(slot->blocks[i]);
    // Fill in the block with metadata first.
    block_ptr->header.type = sgx_oram::ORAM_BLOCK_TYPE_NORMAL;
    block_ptr->header.bid = slot_begin + i;
    // FIXME: The address and the bid should (not) be the same. How to deal with the position map?...
    block_ptr->header.address = slot_begin + i;
    // Then fill in the data.
    if (sgx_read_rand(block_ptr->data, DEFAULT_ORAM_DATA_SIZE) != SGX_SUCCESS) {
      printf("[enclave] Failed to read random data.");
      return SGX_ERROR_UNEXPECTED;
    }
  }

  for (size_t i = slot_size >> 1; i < slot_size; i++) {
    // Locate the slot in the storage.
    sgx_oram::oram_block_t* block_ptr = &(slot->blocks[i]);
    // Mark the block as empty.
    block_ptr->header.type = sgx_oram::ORAM_BLOCK_TYPE_DUMMY;
  }

  return SGX_SUCCESS;
}

static sgx_status_t init_so2_oram(sgx_oram::oram_configuration_t* oram_config,
                                  uint32_t* level_size_information) {
  printf(
      "[enclave] The ORAM controller is initializing the SGX storage tree "
      "level by level...\n");

  uint32_t sgx_size = 0;
  uint32_t cur_size = 1;

  const uint32_t way = oram_config->way;
  const uint32_t type = oram_config->type;
  const uint32_t constant = oram_config->constant;
  const uint32_t level = oram_config->level;

  for (uint32_t i = 0; i < oram_config->level; i++) {
    const uint32_t cur_slot_num = (uint32_t)std::pow(way, i);

    switch (type) {
      case 0: {
        cur_size *= (uint32_t)(std::ceil(std::min(way, i + 1) * constant));
        break;
      }
      case 1: {
        cur_size = way;
        break;
      }
      case 2: {
        cur_size = (uint32_t)(std::ceil(std::pow(way, level - i) * constant));
        break;
      }
    }

    sgx_size += cur_size * cur_slot_num;
    level_size_information[i] = cur_size;
  }

  // Print the size of the ORAM tree.
  printf("[enclave] The size of the ORAM tree is %u.\n", sgx_size);
  return SGX_SUCCESS;
}

static sgx_status_t init_so2_slots(sgx_oram::oram_configuration_t* oram_config,
                                   uint32_t* level_size_information) {
  printf("[enclave] The bucket size is %d", BUCKET_SIZE);
  printf(
      "[enclave] The ORAM controller is initializing the SGX storage slots "
      "for each level...\n");
  const uint32_t level = oram_config->level;
  const uint32_t way = oram_config->way;
  const uint32_t bucket_size = oram_config->bucket_size;
  const uint32_t cur_slot_num = (uint32_t)std::pow(way, level);

  for (uint32_t i = 0; i < level; i++) {
    const uint32_t cur_slot_num = (uint32_t)std::pow(way, i);
    const uint32_t level_size = (uint32_t)std::pow(way, level - i - 1);

    for (uint32_t j = 0; j < cur_slot_num; j++) {
      const uint32_t begin = j * level_size;
      const uint32_t end = begin + level_size - 1;

      bool is_leaf = (i == level - 1);
      // Set the metadata for every slot at the current level.
      sgx_oram::oram_slot_header_t header;
      header.type = is_leaf ? sgx_oram::ORAM_SLOT_TYPE_LEAF
                            : sgx_oram::ORAM_SLOT_TYPE_INTERNAL;
      header.level = i;
      header.dummy_number = (is_leaf ? bucket_size : level_size_information[i]);
      header.range_begin = begin;
      header.range_end = end;

      void* slot;
      size_t slot_size;
      if (!is_leaf) {
        slot_size = sizeof(sgx_oram::oram_slot_t);
        slot = (sgx_oram::oram_slot_t*)malloc(slot_size);
        memcpy(slot, &header, sizeof(sgx_oram::oram_slot_header_t));
      } else {
        slot_size = sizeof(sgx_oram::oram_slot_leaf_t);
        slot = (sgx_oram::oram_slot_leaf_t*)malloc(slot_size);
        memcpy(slot, &header, sizeof(sgx_oram::oram_slot_header_t));
        // Intialize the content of the slot.
        if (populate_leaf_slot((sgx_oram::oram_slot_leaf_t*)slot,
                               bucket_size) != SGX_SUCCESS) {
          printf("[enclave] Failed to populate the leaf slot.\n");
          return SGX_ERROR_UNEXPECTED;
        }
      }

      // Calculate the hash value of the slot.
      const std::string slot_identifier = std::to_string(i) + std::to_string(j);
      const std::string slot_hash =
          crypto_manager->enclave_sha_256(slot_identifier);

      // Encrypt the slot.
      const std::string encrypted_slot =
          crypto_manager->enclave_aes_128_gcm_encrypt(
              std::string(reinterpret_cast<char*>(&slot), slot_size));

      // Write the slot to the SGX storage.
      sgx_status_t status = SGX_ERROR_UNEXPECTED;
      if ((status = ocall_write_slot(slot_hash.c_str(),
                                     (uint8_t*)encrypted_slot.c_str(),
                                     encrypted_slot.size())) != SGX_SUCCESS) {
        printf("[enclave] Failed to write the slot to the SGX storage.");
        return status;
      }

      safe_free(slot);
    }
  }

  safe_free(level_size_information);
  return SGX_SUCCESS;
}

sgx_status_t ecall_access_data(int op_type, uint8_t* data, size_t data_len) {
  return SGX_SUCCESS;
}

sgx_status_t init_oram(sgx_oram::oram_configuration_t* oram_config) {
  // Check if the bucket_size is correct.
  if (oram_config->bucket_size != BUCKET_SIZE) {
    printf("[enclave] The bucket size is not correct.\n");
    return SGX_ERROR_UNEXPECTED;
  }

  if (oram_config->oram_type == 1) {
    uint32_t* level_size_information =
        (uint32_t*)malloc(sizeof(uint32_t) * oram_config->level);
    sgx_status_t status = SGX_ERROR_UNEXPECTED;

    if ((status = init_so2_oram(oram_config, level_size_information)) !=
        SGX_SUCCESS) {
      printf("[enclave] Failed to initialize the ORAM tree.");
      // Safely free the allocated memory.
      safe_free(level_size_information);
      return status;
    } else if ((status = init_so2_slots(oram_config, level_size_information)) !=
               SGX_SUCCESS) {
      printf("[enclave] Failed to initialize the ORAM slots.");
      safe_free(level_size_information);
      return status;
    }

  } else {
    // The ORAM type is incorrect. We report an error.
    printf("[enclave] The ORAM type is incorrect.\n");
    return SGX_ERROR_INVALID_ATTRIBUTE;
  }
}