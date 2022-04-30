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
#include <enclave/enclave_cache.hh>
#include <enclave/enclave_utils.hh>
#include <enclave/enclave_crypto_manager.hh>

static inline bool check_slot_header(const char* const slot_header,
                                     uint32_t level) {
  const sgx_oram::oram_slot_header_t* header =
      reinterpret_cast<const sgx_oram::oram_slot_header_t*>(slot_header);
  return header->level == level;
}

static void print_permutation(const uint32_t* permutation, uint32_t size) {
  for (uint32_t i = 0; i < size; ++i) {
    ENCLAVE_LOG("%u ", permutation[i]);
  }
  ENCLAVE_LOG("\n");
}

// This function assembles position for the current block.
static std::string assemble_position_and_encrypt(uint32_t level, uint32_t bid,
                                                 uint32_t address) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  ENCLAVE_LOG("[enclave] Assembling position for bid: %d\n", bid);
  sgx_oram::oram_position_t* position =
      (sgx_oram::oram_position_t*)malloc(ORAM_POSITION_SIZE);
  position->level = level;
  position->bid = bid;
  position->address = address;

  const std::string ans = crypto_manager->enclave_aes_128_gcm_encrypt(
      std::string((char*)position, ORAM_POSITION_SIZE));
  safe_free(position);

  return ans;
}

static void get_position_and_decrypt(sgx_oram::oram_position_t* const position,
                                     uint32_t block_address) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  // Prepare the ciphertext buffer.
  uint8_t* ciphertext = (uint8_t*)malloc(ENCRYPTED_POSITION_SIZE);
  memset(ciphertext, 0, ENCRYPTED_POSITION_SIZE);

  // Read from the outside memory using OCALL.
  sgx_status_t status = SGX_ERROR_UNEXPECTED;
  size_t position_size = 0;
  const std::string position_fingerprint =
      crypto_manager->enclave_sha_256(std::to_string(block_address));
  ocall_read_position(&position_size, position_fingerprint.c_str(), ciphertext,
                      ENCRYPTED_POSITION_SIZE);

  // Check if the position is valid.
  if (position_size == 0) {
    ocall_panic_and_flush("The position is invalid.");
  }

  // Decrypt the position.
  const std::string position_encrypted =
      crypto_manager->enclave_aes_128_gcm_decrypt(std::string(
          reinterpret_cast<char*>(ciphertext), ENCRYPTED_POSITION_SIZE));
  // Copy the plaintext back to the buffer we've just prepared.
  memcpy(position, position_encrypted.c_str(), ORAM_POSITION_SIZE);
  // Finally, free the buffer we've just allocated.
  safe_free(ciphertext);
}

static sgx_status_t populate_internal_slot(sgx_oram::oram_slot_t* const slot,
                                           size_t slot_size) {
  ENCLAVE_LOG("[enclave] Populating internal slot at level: %d...",
              slot->header.level);
  // Report an error if the type of the slot is incorrect.
  if (slot->header.type !=
      sgx_oram::oram_slot_type_t::ORAM_SLOT_TYPE_INTERNAL) {
    ENCLAVE_LOG("[enclave] The slot is not an internal slot!");
    return SGX_ERROR_INVALID_PARAMETER;
  }
  // Populating internal nodes are rather simple because the only thing we need
  // to do here is set all the blocks thereof to be dummy blocks.
  for (size_t i = 0; i < slot_size; i++) {
    sgx_oram::oram_block_t* const block = &(slot->blocks[i]);
    memset(block, 0, ORAM_BLOCK_SIZE);
    block->header.type = sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_DUMMY;
  }

  return SGX_SUCCESS;
}

static sgx_status_t populate_leaf_slot(sgx_oram::oram_slot_leaf_t* const slot,
                                       size_t slot_size,
                                       const uint32_t* const permutation,
                                       size_t permutation_size,
                                       uint32_t offset) {
  sgx_oram::oram_slot_header_t* slot_header = &(slot->header);

  // First we should perform a sanity check on
  // whether the slot is really a leaf node.
  if (slot_header->type != sgx_oram::ORAM_SLOT_TYPE_LEAF) {
    ENCLAVE_LOG("[enclave] The slot is not a leaf node.\n");
    return SGX_ERROR_INVALID_PARAMETER;
  }

  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();

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
  // is DEFAULT_BUCKET_SIZE times bigger than the actual offset; therefore, we
  // need to multiply slot_begin by the macro DEFAULT_BUCKET_SIZE.

  // Or more simply, the offset + i cannot exceed the real_number.
  for (; (i + offset <= real_number) && (i < DEFAULT_BUCKET_SIZE >> 1); i++) {
    // Locate the slot in the storage.
    sgx_oram::oram_block_t* block_ptr = &(slot->blocks[i]);
    // Fill in the block with metadata first.
    block_ptr->header.type = sgx_oram::ORAM_BLOCK_TYPE_NORMAL;
    block_ptr->header.bid = slot_begin;
    block_ptr->header.address = permutation[offset + i];

    // Assemble the <k, v> pair.
    ENCLAVE_LOG("[enclave] Address is %d\n", permutation[offset + i]);
    const std::string position_str = assemble_position_and_encrypt(
        slot_header->level, slot_begin, permutation[offset + i]);
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

// This function encrypts the given slot and then stores the result in the
// external unstrusted memory. All the buffers are allocated by the caller.
static void encrypt_slot_and_store(uint8_t* const slot, size_t slot_size,
                                   uint32_t level, uint32_t offset) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  // Calculate the hash value of the slot by its current level and the
  // offset at the current level.
  const std::string sid = enclave_strcat(std::to_string(level).c_str(), "_",
                                         std::to_string(offset).c_str());
  ENCLAVE_LOG("[enclave] The sid is %s.\n", sid.c_str());
  const std::string slot_hash = crypto_manager->enclave_sha_256(sid);

  // Encrypt the slot.
  const std::string encrypted_slot =
      crypto_manager->enclave_aes_128_gcm_encrypt(
          std::string(reinterpret_cast<char*>(slot), slot_size));

  // Write the slot to the SGX storage.
  sgx_status_t status =
      ocall_write_slot(slot_hash.c_str(), (uint8_t*)encrypted_slot.c_str(),
                       encrypted_slot.size());
  check_sgx_status(status, "ocall_write_slot()");
}

// This function assembles the slot by the given paramters.
static size_t assemble_slot(uint8_t* slot,
                            sgx_oram::oram_slot_header_t* const header,
                            uint32_t bucket_size, uint32_t way, bool is_leaf,
                            const uint32_t* const permutation,
                            size_t permutation_size, uint32_t* const offset) {
  size_t slot_size = 0;
  if (!is_leaf) {
    slot_size = ORAM_SLOT_INTERNAL_SIZE;
    memcpy(slot, header, sizeof(sgx_oram::oram_slot_header_t));
    sgx_status_t status =
        populate_internal_slot((sgx_oram::oram_slot_t*)slot, way);
    check_sgx_status(status, "populate_internal_slot()");
  } else {
    slot_size = ORAM_SLOT_LEAF_SIZE;
    memcpy(slot, header, sizeof(sgx_oram::oram_slot_header_t));
    // Intialize the content of the slot.
    sgx_status_t status =
        populate_leaf_slot((sgx_oram::oram_slot_leaf_t*)slot, bucket_size,
                           permutation, permutation_size, *offset);
    check_sgx_status(status, "populate_leaf_slot()");
    *offset += bucket_size >> 1;
  }

  return slot_size;
}

// This function fetches the target slot from the outside memory by calculting
// its hash value and then decrypt it in the enclave. Finally, it writes the
// decrypted target slot to the target slot buffer allocate by the caller.
static void get_slot_and_decrypt(uint32_t level, uint32_t offset,
                                 uint8_t* slot_buffer, size_t slot_size) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  // Determine the size of the target slot in ciphertext.
  const size_t ciphertext_size =
      slot_size + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;
  // Compute the hash value of the target slot.
  const std::string sid = enclave_strcat(std::to_string(level).c_str(), "_",
                                         std::to_string(level).c_str());
  ENCLAVE_LOG("[enclave] sid: %s\n", sid.c_str());
  const std::string slot_hash = crypto_manager->enclave_sha_256(sid);

  // Prepare a buffer for storing the ciphertext of the slot.
  // Note that there are leaf and internal nodes, so we must allocate a buffer
  // that is large enough to hold the worst-case ciphertext.
  uint8_t* ciphertext = (uint8_t*)malloc(ciphertext_size);
  memset(ciphertext, 0, ciphertext_size);

  // For safety reason, we use the same buffer to store the decrypted target.
  // Note that the size of the buffer should be at least the size of the
  // leaf slot to prevent buffer overflow.
  // Here, the variable slot_size is useless, but we use it as sanity check.
  sgx_status_t status = SGX_ERROR_UNEXPECTED;
  status = ocall_read_slot(&slot_size, slot_hash.c_str(), ciphertext,
                           ciphertext_size);
  check_sgx_status(status, "get_slot_and_decrypt()");

  // Test if cache works.
  std::shared_ptr<EnclaveCache> cache = EnclaveCache::get_instance();
  cache->read(slot_hash, 1);

  // Check if the slot is valid.
  if (slot_size == 0) {
    ocall_panic_and_flush("The enclave proxy cannot fetch the target slot.");
  }

  // Decrypt the target slot.
  const std::string decrypted_slot =
      crypto_manager->enclave_aes_128_gcm_decrypt(
          std::string(reinterpret_cast<char*>(ciphertext), ciphertext_size));
  // Free the buffer we've just allocated.
  safe_free(ciphertext);

  // Sanity check: The header of the decrypted slot should not be corrupted
  //               by something weird.
  if (!check_slot_header(decrypted_slot.c_str(), level)) {
    ocall_panic_and_flush("The slot header is invalid.");
  }
  // Copy back to the buffer.
  memcpy(slot_buffer, decrypted_slot.c_str(), decrypted_slot.size());
}

// This function will calculate the offset for the slot at current level
// based on the value of block id which indicates the path from the root
// to the current slot. To determine the offset, the total level and the
// ways of the ORAM tree are needed.
static inline uint32_t calculate_offset(uint32_t block_id, uint32_t level_cur) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();

  const uint32_t level = crypto_manager->get_oram_config()->level;
  const uint32_t way = crypto_manager->get_oram_config()->way;

  return std::floor((block_id * 1.0 / std::pow(way, level - level_cur)));
}

// This function assembles the slot header by the given parameters.
static inline void assemble_slot_header(
    sgx_oram::oram_slot_header_t* const header, uint32_t level,
    uint32_t bucket_size, uint32_t begin, uint32_t end, uint32_t size,
    bool is_leaf) {
  header->type = is_leaf ? sgx_oram::ORAM_SLOT_TYPE_LEAF
                         : sgx_oram::ORAM_SLOT_TYPE_INTERNAL;
  header->level = level;
  header->dummy_number = (is_leaf ? bucket_size : size);
  header->slot_size = header->dummy_number;
  header->range_begin = begin;
  header->range_end = end;
}

static sgx_status_t init_so2_oram(uint32_t* const level_size_information) {
  ENCLAVE_LOG(
      "[enclave] The ORAM controller is initializing the SGX storage tree "
      "level by level...\n");

  uint32_t sgx_size = 0;
  uint32_t cur_size = 1;

  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();

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
static sgx_status_t init_so2_slots(uint32_t* const level_size_information,
                                   const uint32_t* const permutation,
                                   size_t permutation_size) {
  print_permutation(permutation, permutation_size);

  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();

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
      const uint32_t begin = j * level_size;
      const uint32_t end = begin + level_size - 1;

      bool is_leaf = (i == level - 1);
      // Set the metadata for every slot at the current level.
      sgx_oram::oram_slot_header_t* header =
          (sgx_oram::oram_slot_header_t*)malloc(
              sizeof(sgx_oram::oram_slot_header_t));
      assemble_slot_header(header, i, bucket_size, begin, end,
                           level_size_information[i], is_leaf);

      // Assemble the slot.
      uint8_t* slot = (uint8_t*)malloc(ORAM_SLOT_LEAF_SIZE);
      const size_t slot_size =
          assemble_slot(slot, header, bucket_size, way, is_leaf, permutation,
                        permutation_size, &offset);
      encrypt_slot_and_store(slot, slot_size, i, j);
      safe_free(header);
      safe_free(slot);
    }
  }

  safe_free(level_size_information);
  return SGX_SUCCESS;
}

static void sub_access(sgx_oram::oram_operation_t op_type, bool condition,
                       uint8_t* const s1, uint8_t* const s2,
                       uint8_t* const data_star, uint32_t level,
                       sgx_oram::oram_position_t* const position) {
  ENCLAVE_LOG("[enclave] Invoking sub_access for level %u...", level);
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  // Get the type of the slot from its header.
  sgx_oram::oram_slot_header_t* slot_header = (sgx_oram::oram_slot_header_t*)s1;
  sgx_oram::oram_slot_type_t slot_type_s1 = slot_header->type;

  // Initialize some useful variables.
  uint32_t counter = 0;
  // Create two buffers for temporarily holding the data.
  // bl1  : block_slot1_target
  // bl1' : block_slot1_evict
  sgx_oram::oram_block_t* block_slot1_target =
      (sgx_oram::oram_block_t*)malloc(ORAM_BLOCK_SIZE);
  sgx_oram::oram_block_t* block_slot1_evict =
      (sgx_oram::oram_block_t*)malloc(ORAM_BLOCK_SIZE);
  memset(block_slot1_target, 0, ORAM_BLOCK_SIZE);
  memset(block_slot1_evict, 0, ORAM_BLOCK_SIZE);

  // Determine the size of the slot.
  const size_t slot_size = slot_header->slot_size;
  // The only difference between a leaf node and the internal node is their
  // size. So headers are the same. We can just skip the header and directly
  // access the data in the slot.
  uint8_t* slot_storage = (s1 + sizeof(sgx_oram::oram_slot_header_t));

  // First, we do an one-pass on the slot S1.
  for (size_t i = 0; i < slot_size; i++) {
    // Reinterpret the memory space.
    sgx_oram::oram_block_t* block = (sgx_oram::oram_block_t*)slot_storage;

    // Initialize some bool variables.
    bool condition_existing = (block->header.bid == position->bid);
    bool condition_epsilon =
        is_in_range(block->header.bid, (sgx_oram::oram_slot_header_t*)s1);
    bool condition_this_dummy =
        (block->header.type ==
         sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_DUMMY);

    oblivious_assign(condition_existing && condition_this_dummy,
                     (uint8_t*)block_slot1_target, (uint8_t*)block,
                     ORAM_BLOCK_SIZE, ORAM_BLOCK_SIZE);
    bool constant = true;
    oblivious_assign(condition_existing && condition_this_dummy,
                     (bool*)&block->header.type, &constant);

    counter += condition_existing;
    bool condition_counter = (counter <= 1);
    // Copy the data to the target buffer.
    slot_storage += ORAM_BLOCK_SIZE;
  }

  // Test if oblivious_assign reads something from the source buffer.
  ENCLAVE_LOG("[enclave] The bid of the block_slot1_target is %u", block_slot1_target->header.bid);

  // Eventually, destroy all the allocated memory.
  safe_free(block_slot1_target);
  safe_free(block_slot1_evict);
}

// The main entry of the data access.
// In this function, three slots are involved to fetch the block from
// the ORAM tree, although a slot is implicitly accessed by another function
// called by this function.
static void data_access(sgx_oram::oram_operation_t op_type,
                        uint32_t current_level, uint8_t* const data,
                        size_t data_size, bool condition,
                        sgx_oram::oram_position_t* const position) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  // - Read two slots S1 and S2 from the outside memory. Originally, in the
  //   (ORAM) simulation mode, we fetch the slots by their levels and offsets at
  //   certain level.
  // - However, in the SGX mode, we fetch the slots by their hash values, albeit
  //   the hash values are not the same as the levels and offsets, but they are
  //   calculated by level + offset.
  // - Also note that since the level starts from 0, the level is slightly
  //   different from what we have written in the pseudocode. Moreover, because
  //   slot s1 is fetched by adding 1 to the current level, the iteration must
  //   stop at total_level - 1 to prevent the level overflow.
  const uint32_t offset_s1 = calculate_offset(position->bid, current_level + 1);
  const uint32_t offset_s2 = calculate_offset(position->bid, current_level);
  // Allocate the slot buffers.
  const uint32_t level = crypto_manager->get_oram_config()->level;
  // An extra offset is added.
  size_t slot_size_s1 = (current_level + 2 == level) ? ORAM_SLOT_LEAF_SIZE
                                                     : ORAM_SLOT_INTERNAL_SIZE;
  size_t slot_size_s2 = ORAM_SLOT_INTERNAL_SIZE;
  uint8_t* s1 = (uint8_t*)malloc(slot_size_s1);
  uint8_t* s2 = (uint8_t*)malloc(slot_size_s2);
  size_t s1_size = 0;
  size_t s2_size = 0;

  // Read the slots from the SGX storage.
  // We may need to put all the slots in a buffer pool so that we can
  // immediately free the unneeded slots after a write opeation.
  // CAVEAT: Malloc without free is not a good idea.
  get_slot_and_decrypt(current_level + 1, offset_s1, s1, slot_size_s1);
  get_slot_and_decrypt(current_level, offset_s2, s2, slot_size_s2);

  // Invoke sub_access.
  sub_access(op_type, condition, s1, s2, data, current_level, position);
  // Invoke sub_evict.
  // TODO.

  safe_free(s1);
  safe_free(s2);
}

sgx_status_t ecall_access_data(int op_type, uint32_t block_address,
                               uint8_t* data, size_t data_len) {
  ENCLAVE_LOG("[enclave] Accessing data at address %d.\n", block_address);
  // Get the instance of the cryptomanager.
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  // Travers all the levels of the ORAM tree and call data_access function.
  const uint32_t level = crypto_manager->get_oram_config()->level;
  //  Also, we need to read the position for the address.
  sgx_oram::oram_position_t* position =
      (sgx_oram::oram_position_t*)malloc(ORAM_POSITION_SIZE);

  get_position_and_decrypt(position, block_address);

  const uint32_t block_level = position->level;
  const uint32_t bid_cur = position->bid;

  ENCLAVE_LOG("[enclave] block_level: %u, bid_cur: %u", block_level, bid_cur);

  // We start from 0.
  for (uint32_t i = 0; i < level - 1; i++) {
    // If the current level is the same as the block level, then we should
    // directly access the data; otherwise, we should perform fake access.
    bool condition = (i == block_level);
    data_access(static_cast<sgx_oram::oram_operation_t>(op_type), i, data,
                data_len, condition, position);
  }

  return SGX_SUCCESS;
}

sgx_status_t init_oram(uint32_t* permutation, size_t permutation_size) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  // Check if the bucket_size is correct.
  if (crypto_manager->get_oram_config()->bucket_size != DEFAULT_BUCKET_SIZE ||
      crypto_manager->get_oram_config()->way != DEFAULT_SLOT_SIZE) {
    ENCLAVE_LOG("[enclave] The ORAM configuration is not correct.\n");
    return SGX_ERROR_UNEXPECTED;
  }

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

  return SGX_SUCCESS;
}

sgx_status_t SGXAPI ecall_init_oram_controller(uint8_t* oram_config,
                                               size_t oram_config_size,
                                               uint32_t* permutation,
                                               size_t permutation_size) {
  // Copy the configuration into the cryptomanager.
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  crypto_manager->set_oram_config(oram_config, oram_config_size);
  // Begin initialize the slot...
  ENCLAVE_LOG("[enclave] Initializing the slot...");
  ENCLAVE_LOG("[enclave] oram_type is %d.",
              crypto_manager->get_oram_config()->oram_type);
  // Note that the permutation_size is the size of the permutation array in
  // bytes. We need convert it back to the number of elements.
  return init_oram(permutation, permutation_size / sizeof(uint32_t));
}
