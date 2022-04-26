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
#include <enclave/enclave_oram.hh>

#include <cstring>
#include <algorithm>
#include <cmath>

#include <sgx_urts.h>

#include <enclave/enclave_t.h>
#include <enclave/enclave_utils.hh>
#include <enclave/enclave_crypto_manager.hh>

extern EnclaveCryptoManager* crypto_manager;

static void print_permutation(const uint32_t* permutation, uint32_t size) {
  for (uint32_t i = 0; i < size; ++i) {
    ENCLAVE_LOG("%u ", permutation[i]);
  }
  ENCLAVE_LOG("\n");
}

// This function fetches the target slot from the outside memory by calculting
// its hash value and then decrypt it in the enclave. Finally, it writes the
// decrypted target slot to the target slot buffer allocate by the caller.
static void get_slot_and_decrypt(uint32_t level, uint32_t offset,
                                 uint8_t* slot_buffer, size_t slot_size) {
  const std::string sid = std::to_string(level) + std::to_string(offset);
  const std::string slot_hash = crypto_manager->enclave_sha_256(sid);

  // For safety reason, we use the same buffer to store the decrypted target.
  // Note that the size of the buffer should be at least the size of the
  // leaf slot to prevent buffer overflow.
  sgx_status_t status = SGX_ERROR_UNEXPECTED;
  status =
      ocall_read_slot(&slot_size, slot_hash.c_str(), slot_buffer, slot_size);
  check_sgx_status(status, "get_slot_and_decrypt()");

  // Decrypt the target slot.
  const std::string decrypted_slot =
      crypto_manager->enclave_aes_128_gcm_decrypt(
          std::string(reinterpret_cast<char*>(slot_buffer), slot_size));
  // Copy back to the buffer.
  memcpy(slot_buffer, decrypted_slot.c_str(), decrypted_slot.size());
}

// This function will calculate the offset for the slot at current level
// based on the value of block id which indicates the path from the root
// to the current slot. To determine the offset, the total level and the
// ways of the ORAM tree are needed.
static inline uint32_t calculate_offset(uint32_t block_id, uint32_t level_cur) {
  const uint32_t level = crypto_manager->get_oram_config()->level;
  const uint32_t way = crypto_manager->get_oram_config()->way;

  return std::floor((block_id * 1.0 / std::pow(way, level - level_cur - 1)));
}

// This function assembles position for the current block.
static std::string assemble_position_and_encrypt(uint32_t level, uint32_t bid,
                                                 uint32_t address) {
  ENCLAVE_LOG("[enclave] Assembling position for bid: %d\n", bid);
  sgx_oram::oram_position_t* position =
      (sgx_oram::oram_position_t*)malloc(sizeof(sgx_oram::oram_position_t));
  position->level = level;
  position->bid = bid;
  position->address = address;

  const std::string ans = crypto_manager->enclave_aes_128_gcm_encrypt(
      std::string((char*)position, sizeof(sgx_oram::oram_position_t)));
  safe_free(position);
  return ans;
}

static sgx_status_t populate_leaf_slot(sgx_oram::oram_slot_leaf_t* slot,
                                       size_t slot_size, uint32_t* permutation,
                                       size_t permutation_size,
                                       uint32_t offset) {
  sgx_oram::oram_slot_header_t* slot_header = &(slot->header);

  // First we should perform a sanity check on
  // whether the slot is really a leaf node.
  if (slot_header->type != sgx_oram::ORAM_SLOT_TYPE_LEAF) {
    ENCLAVE_LOG("[enclave] The slot is not a leaf node.\n");
    return SGX_ERROR_INVALID_PARAMETER;
  }

  const uint32_t slot_begin = slot_header->range_begin;
  const uint32_t real_number = crypto_manager->get_oram_config()->number / 2;
  ENCLAVE_LOG("[enclave] Populating leaf slot...");
  ENCLAVE_LOG(
      "[enclave] slot_size: %zu, permutation_size: %zu, offset: %u, "
      "slot_begin: %u\n",
      slot_size, permutation_size, offset, slot_begin);

  size_t i = 0;
  // The loop should end when i reaches the halve of the slot size or the
  // offset is larger than the needed size.
  // Note that blocks in the same bucket have the same block id. So the offset
  // is BUCKET_SIZE times bigger than the actual offset; therefore, we need to
  // multiply slot_begin by the macro BUCKET_SIZE.

  // Or more simply, the offset + i cannot exceed the real_number.
  for (; (i + offset <= real_number) && (i < BUCKET_SIZE >> 1); i++) {
    // Locate the slot in the storage.
    sgx_oram::oram_block_t* block_ptr = &(slot->blocks[i]);
    // Fill in the block with metadata first.
    block_ptr->header.type = sgx_oram::ORAM_BLOCK_TYPE_NORMAL;
    block_ptr->header.bid = offset + i;
    block_ptr->header.address = permutation[offset + i];

    // Assemble the <k, v> pair.
    ENCLAVE_LOG("[enclave] Adddress is %d\n", permutation[offset + i]);
    const std::string position_str = assemble_position_and_encrypt(
        slot_header->level, offset + i, permutation[offset + i]);
    const std::string position_fingerprint = crypto_manager->enclave_sha_256(
        std::to_string(permutation[offset + i]));

    // Write the position back to the server.
    // Note that the key of the position map is the hash value for the address
    // and the value of that is the encrypted byte array.
    sgx_status_t status = ocall_write_position(position_fingerprint.c_str(),
                                               (uint8_t*)position_str.c_str(),
                                               position_str.size());
    check_sgx_status(status, "ocall_write_position()");
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
  ENCLAVE_LOG(
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
  ENCLAVE_LOG("[enclave] The size of the ORAM tree is %u.\n", sgx_size);
  return SGX_SUCCESS;
}

// This function will initialize the storage tree.
static sgx_status_t init_so2_slots(uint32_t* level_size_information,
                                   uint32_t* permutation,
                                   size_t permutation_size) {
  print_permutation(permutation, permutation_size);

  ENCLAVE_LOG("[enclave] The bucket size is %d", BUCKET_SIZE);
  ENCLAVE_LOG(
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
          ENCLAVE_LOG("[enclave] Failed to populate the leaf slot.\n");
          return SGX_ERROR_UNEXPECTED;
        } else {
          offset += bucket_size >> 1;
        }
      }

      // Calculate the hash value of the slot by its current level and the
      // offset at the current level.
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
        ENCLAVE_LOG("[enclave] Failed to write the slot to the SGX storage.");
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
static void data_access(sgx_oram::oram_operation_t, uint32_t current_level,
                        uint8_t* data, size_t data_size, bool condition,
                        sgx_oram::oram_position_t* position) {
  // Read two slots S1 and S2 from the outside memory. Originally, in the (ORAM)
  // simulation mode, we fetch the slots by their levels and offsets at certain
  // level. However, in the SGX mode, we fetch the slots by their hash values,
  // albeit the hash values are not the same as the levels and offsets, but they
  // are calculated by level + offset.
  const uint32_t offset_s1 = calculate_offset(position->bid, current_level);
  const uint32_t offset_s2 = calculate_offset(position->bid, current_level - 1);
  // Allocate the slot buffers.
  const uint32_t level = crypto_manager->get_oram_config()->level;
  size_t slot_size_s1 = (current_level == level)
                            ? sizeof(sgx_oram::oram_slot_leaf_t)
                            : sizeof(sgx_oram::oram_slot_t);
  size_t slot_size_s2 = (current_level == level)
                            ? sizeof(sgx_oram::oram_slot_leaf_t)
                            : sizeof(sgx_oram::oram_slot_t);
  uint8_t* s1 = (uint8_t*)malloc(sizeof(sgx_oram::oram_slot_leaf_t));
  uint8_t* s2 = (uint8_t*)malloc(sizeof(sgx_oram::oram_slot_leaf_t));
  size_t s1_size = 0;
  size_t s2_size = 0;

  // Read the slots from the SGX storage.
  // FIXME: We may need to put all the slots in a buffer pool so that we can
  // immediately free the unneeded slots after a write opeation.
  // CAVEAT: Malloc without free is not a good idea.
  get_slot_and_decrypt(current_level, offset_s1, s1, slot_size_s1);
  get_slot_and_decrypt(current_level - 1, offset_s2, s2, slot_size_s2);

  // Call sub_access(op_type, condition, S1, S2, data, data_size, i, pi);
  safe_free(s1);
  safe_free(s2);
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
  const std::string position_fingerprint =
      crypto_manager->enclave_sha_256(std::to_string(block_address));
  ocall_read_position(&position_size, position_fingerprint.c_str(),
                      (uint8_t*)position, sizeof(sgx_oram::oram_position_t));

  const uint32_t block_level = position->level;
  const uint32_t bid_cur = position->bid;

  ENCLAVE_LOG("[enclave] block_level: %u, bid_cir: %u", block_level, bid_cur);

  for (uint32_t i = 1; i <= level; i++) {
    // If the current level is the same as the block level, then we should
    // directly access the data; otherwise, we should perform fake access.
    bool condition = (i == block_level);
    data_access(static_cast<sgx_oram::oram_operation_t>(op_type), i, data,
                data_len, condition, position);
  }

  return SGX_SUCCESS;
}

sgx_status_t init_oram(uint32_t* permutation, size_t permutation_size) {
  // Check if the bucket_size is correct.
  if (crypto_manager->get_oram_config()->bucket_size != BUCKET_SIZE) {
    ENCLAVE_LOG("[enclave] The bucket size is not correct.\n");
    return SGX_ERROR_UNEXPECTED;
  }

  if (crypto_manager->get_oram_config()->oram_type == 1) {
    uint32_t* level_size_information = (uint32_t*)malloc(
        sizeof(uint32_t) * crypto_manager->get_oram_config()->level);
    sgx_status_t status = SGX_ERROR_UNEXPECTED;

    if ((status = init_so2_oram(level_size_information)) != SGX_SUCCESS) {
      ENCLAVE_LOG("[enclave] Failed to initialize the ORAM tree.");
      // Safely free the allocated memory.
      safe_free(level_size_information);
      return status;
    } else if ((status = init_so2_slots(level_size_information, permutation,
                                        permutation_size)) != SGX_SUCCESS) {
      ENCLAVE_LOG("[enclave] Failed to initialize the ORAM slots.");
      safe_free(level_size_information);
      return status;
    }

  } else {
    // The ORAM type is incorrect. We report an error.
    ENCLAVE_LOG("[enclave] The ORAM type is incorrect.\n");
    return SGX_ERROR_INVALID_ATTRIBUTE;
  }

  return SGX_SUCCESS;
}

sgx_status_t SGXAPI ecall_init_oram_controller(uint8_t* oram_config,
                                               size_t oram_config_size,
                                               uint32_t* permutation,
                                               size_t permutation_size) {
  // Copy the configuration into the cryptomanager.
  crypto_manager->set_oram_config(oram_config, oram_config_size);
  // Begin initialize the slot...
  ENCLAVE_LOG("[enclave] Initializing the slot...");
  ENCLAVE_LOG("[enclave] oram_type is %d.",
              crypto_manager->get_oram_config()->oram_type);
  // Note that the permutation_size is the size of the permutation array in
  // bytes. We need convert it back to the number of elements.
  return init_oram(permutation, permutation_size / sizeof(uint32_t));
}
