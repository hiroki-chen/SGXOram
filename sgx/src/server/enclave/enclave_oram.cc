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

// This function will calculate the offset for the slot at current level
// based on the value of block id which indicates the path from the root
// to the current slot. To determine the offset, the total level and the
// ways of the ORAM tree are needed.
static uint32_t calculate_offset(uint32_t block_id, uint32_t level) {}

// This function assembles position for the current block.
static std::string assemble_position_and_encrypt(
    sgx_oram::oram_position_t* position, uint32_t level, uint32_t bid,
    uint32_t address) {
  position->level = level;
  position->bid = bid;
  position->address = address;

  return crypto_manager->enclave_aes_128_gcm_encrypt(
      std::string((char*)position, sizeof(sgx_oram::oram_position_t)));
}

static sgx_status_t populate_leaf_slot(sgx_oram::oram_slot_leaf_t* slot,
                                       size_t slot_size, uint32_t* permutation,
                                       size_t permutation_size,
                                       uint32_t offset) {
  printf("[enclave] Populating leaf slot...");
  printf("[enclave] slot_size: %zu, permutation_size: %zu, offset: %u\n",
         slot_size, permutation_size << 1, offset);
  sgx_oram::oram_slot_header_t* slot_header = &(slot->header);

  // First we should perform a sanity check on
  // whether the slot is really a leaf node.
  if (slot_header->type != sgx_oram::ORAM_SLOT_TYPE_LEAF) {
    printf("[enclave] The slot is not a leaf node.\n");
    return SGX_ERROR_INVALID_PARAMETER;
  }

  const uint32_t slot_begin = slot_header->range_begin;
  size_t i = 0;
  // The loop should end when i reaches the halve of the slot size or the
  // offset is larger than the needed size.
  for (; i < (slot_size >> 1) && (offset <= slot_begin); i++) {
    // Locate the slot in the storage.
    sgx_oram::oram_block_t* block_ptr = &(slot->blocks[i]);
    // Fill in the block with metadata first.
    block_ptr->header.type = sgx_oram::ORAM_BLOCK_TYPE_NORMAL;
    block_ptr->header.bid = slot_begin + i;
    block_ptr->header.address = permutation[offset + i];

    // Handle the position map.
    sgx_oram::oram_position_t* position =
        (sgx_oram::oram_position_t*)malloc(sizeof(sgx_oram::oram_position_t));
    memset(position, 0, sizeof(sgx_oram::oram_position_t));
    const std::string position_str = assemble_position_and_encrypt(
        position, slot_header->level, slot_begin + i, permutation[offset + i]);
    // Write the position back to the server.
    sgx_status_t status = ocall_write_position(
        std::to_string(permutation[offset + i]).c_str(),
        (uint8_t*)position_str.c_str(), position_str.size());
    check_sgx_status(status, "ocall_write_position()");
    safe_free(position);
    // Then fill in the data.
    status = sgx_read_rand(block_ptr->data, DEFAULT_ORAM_DATA_SIZE);
    check_sgx_status(status, "sgx_read_rand()");
  }

  for (; i < slot_size; i++) {
    // Locate the slot in the storage.
    sgx_oram::oram_block_t* block_ptr = &(slot->blocks[i]);
    // Mark the block as empty.
    block_ptr->header.type = sgx_oram::ORAM_BLOCK_TYPE_DUMMY;
  }

  return SGX_SUCCESS;
}

static sgx_status_t init_so2_oram(uint32_t* level_size_information) {
  printf(
      "[enclave] The ORAM controller is initializing the SGX storage tree "
      "level by level...\n");

  uint32_t sgx_size = 0;
  uint32_t cur_size = 1;

  const uint32_t way = crypto_manager->get_oram_config()->way;
  const uint32_t type = crypto_manager->get_oram_config()->type;
  const uint32_t constant = crypto_manager->get_oram_config()->constant;
  const uint32_t level = crypto_manager->get_oram_config()->level;

  for (uint32_t i = 0; i < crypto_manager->get_oram_config()->level; i++) {
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

// This function will initialize the storage tree.
static sgx_status_t init_so2_slots(uint32_t* level_size_information,
                                   uint32_t* permutation,
                                   size_t permutation_size) {
  printf("[enclave] The bucket size is %d", BUCKET_SIZE);
  printf(
      "[enclave] The ORAM controller is initializing the SGX storage slots "
      "for each level...\n");
  const uint32_t level = crypto_manager->get_oram_config()->level;
  const uint32_t way = crypto_manager->get_oram_config()->way;
  const uint32_t bucket_size = crypto_manager->get_oram_config()->bucket_size;
  const uint32_t cur_slot_num = (uint32_t)std::pow(way, level);

  uint32_t offset = 0;

  for (uint32_t i = 0; i < level; i++) {
    const uint32_t cur_slot_num = (uint32_t)std::pow(way, i);
    const uint32_t level_size = (uint32_t)std::pow(way, level - i - 1);

    for (uint32_t j = 0; j < cur_slot_num; j++) {
      // If offset is bigger than the number of the blocks, then we should
      // immediately stop; otherwise it is meaningless.
      // if (offset >= permutation_size) {
      //   break;
      // }

      const uint32_t begin = j * level_size;
      const uint32_t end = begin + level_size - 1;

      bool is_leaf = (i == level - 1);
      // Set the metadata for every slot at the current level.
      sgx_oram::oram_slot_header_t* header =
          (sgx_oram::oram_slot_header_t*)malloc(
              sizeof(sgx_oram::oram_slot_header_t));
      header->type = is_leaf ? sgx_oram::ORAM_SLOT_TYPE_LEAF
                             : sgx_oram::ORAM_SLOT_TYPE_INTERNAL;
      header->level = i;
      header->dummy_number =
          (is_leaf ? bucket_size : level_size_information[i]);
      header->range_begin = begin;
      header->range_end = end;

      // Copy the header to the slot.
      void* slot;
      size_t slot_size = 0;
      if (!is_leaf) {
        slot_size = sizeof(sgx_oram::oram_slot_t);
        slot = (sgx_oram::oram_slot_t*)malloc(slot_size);
        memcpy(slot, header, sizeof(sgx_oram::oram_slot_header_t));
        // The header is no longer needed.
        safe_free(header);
      } else {
        slot_size = sizeof(sgx_oram::oram_slot_leaf_t);
        slot = (sgx_oram::oram_slot_leaf_t*)malloc(slot_size);
        memcpy(slot, header, sizeof(sgx_oram::oram_slot_header_t));
        safe_free(header);
        // Intialize the content of the slot.
        if (populate_leaf_slot((sgx_oram::oram_slot_leaf_t*)slot, bucket_size,
                               permutation, permutation_size,
                               offset) != SGX_SUCCESS) {
          printf("[enclave] Failed to populate the leaf slot.\n");
          return SGX_ERROR_UNEXPECTED;
        } else {
          offset += bucket_size >> 1;
        }
      }

      // Calculate the hash value of the slot.
      const std::string slot_identifier = std::to_string(i) + std::to_string(j);
      const std::string slot_hash =
          crypto_manager->enclave_sha_256(slot_identifier);

      // Encrypt the slot.
      const std::string encrypted_slot =
          crypto_manager->enclave_aes_128_gcm_encrypt(
              std::string(reinterpret_cast<char*>(slot), slot_size));
      safe_free(slot);

      // Write the slot to the SGX storage.
      sgx_status_t status = SGX_ERROR_UNEXPECTED;
      if ((status = ocall_write_slot(slot_hash.c_str(),
                                     (uint8_t*)encrypted_slot.c_str(),
                                     encrypted_slot.size())) != SGX_SUCCESS) {
        printf("[enclave] Failed to write the slot to the SGX storage.");
        return status;
      }
    }
  }

  safe_free(level_size_information);
  return SGX_SUCCESS;
}

// The main entry of the data access.
// In this function, three slots are involved to fetch the block from
// the ORAM tree, although a slot is implicitly accessed by another function
// called by this function.
static void data_access(int op_type, uint32_t current_level, uint8_t* data,
                        size_t data_size, bool condition,
                        sgx_oram::oram_position_t* position) {
  // Read two slots S1 and S2 from the outside memory. Originally, in the (ORAM)
  // simulation mode, we fetch the slots by their levels and offsets at certain
  // level. However, in the SGX mode, we fetch the slots by their hash values,
  // albeit the hash values are not the same as the levels and offsets, but they
  // are calculated by level + offset.
  // TODO: Wrap this to a function.
  const uint32_t offset_s1 = calculate_offset(position->bid, current_level);
  const uint32_t offset_s2 = calculate_offset(position->bid, current_level - 1);
  // Then we calculate the hash value of the two slots.
  const std::string slot_identifier_s1 =
      std::to_string(current_level) + std::to_string(offset_s1);
  const std::string slot_identifier_s2 =
      std::to_string(current_level - 1) + std::to_string(offset_s2);
  const std::string slot_hash_s1 =
      crypto_manager->enclave_sha_256(slot_identifier_s1);
  const std::string slot_hash_s2 =
      crypto_manager->enclave_sha_256(slot_identifier_s2);

  // Read the two slots from the external memory. We first prepare the buffer for them.
  bool is_leaf = (current_level == crypto_manager->get_oram_config()->level);
}

sgx_status_t ecall_access_data(int op_type, uint32_t block_address,
                               uint8_t* data, size_t data_len) {
  // Travers all the levels of the ORAM tree and call data_access function.
  const uint32_t level = crypto_manager->get_oram_config()->level;
  //  Also, we need to read the position for the address.
  sgx_oram::oram_position_t* position =
      (sgx_oram::oram_position_t*)malloc(sizeof(sgx_oram::oram_position_t));
  sgx_status_t status = SGX_ERROR_UNEXPECTED;
  size_t position_size = 0;
  ocall_read_position(&position_size, std::to_string(block_address).c_str(),
                      (uint8_t*)position, sizeof(sgx_oram::oram_position_t));

  const uint32_t block_level = position->level;
  const uint32_t bid_cur = position->bid;
  for (uint32_t i = 1; i <= level; i++) {
    // If the current level is the same as the block level, then we should
    // directly access the data; otherwise, we should perform fake access.
    bool condition = (i == block_level);
    // call data_access(op_type, i == l, bid_cur, i);
  }

  return SGX_SUCCESS;
}

sgx_status_t init_oram(uint32_t* permutation, size_t permutation_size) {
  // Check if the bucket_size is correct.
  if (crypto_manager->get_oram_config()->bucket_size != BUCKET_SIZE) {
    printf("[enclave] The bucket size is not correct.\n");
    return SGX_ERROR_UNEXPECTED;
  }

  if (crypto_manager->get_oram_config()->oram_type == 1) {
    uint32_t* level_size_information = (uint32_t*)malloc(
        sizeof(uint32_t) * crypto_manager->get_oram_config()->level);
    sgx_status_t status = SGX_ERROR_UNEXPECTED;

    if ((status = init_so2_oram(level_size_information)) != SGX_SUCCESS) {
      printf("[enclave] Failed to initialize the ORAM tree.");
      // Safely free the allocated memory.
      safe_free(level_size_information);
      return status;
    } else if ((status = init_so2_slots(level_size_information, permutation,
                                        permutation_size)) != SGX_SUCCESS) {
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

sgx_status_t SGXAPI ecall_init_oram_controller(uint8_t* oram_config,
                                               size_t oram_config_size,
                                               uint32_t* permutation,
                                               size_t permutation_size) {
  // Copy the configuration into the cryptomanager.
  crypto_manager->set_oram_config(oram_config, oram_config_size);
  // Begin initialize the slot...
  printf("[enclave] Initializing the slot...");
  printf("[enclave] oram_type is %d.",
         crypto_manager->get_oram_config()->oram_type);
  return init_oram(permutation, permutation_size);
}
