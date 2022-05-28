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
#include <enclave/enclave_oram_access.hh>
#include <enclave/enclave_crypto_manager.hh>

extern int64_t access_time;
extern int64_t eviction_time;

int64_t ocall_latency = 0;

static inline bool check_slot_header(
    const sgx_oram::oram_slot_header_t* const header_str, uint32_t level) {
  const sgx_oram::oram_slot_header_t* header =
      reinterpret_cast<const sgx_oram::oram_slot_header_t*>(header_str);
  return header->level == level;
}

std::string calculate_slot_fingerprint(uint32_t level, uint32_t offset) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  const std::string sid = enclave_utils::enclave_strcat(
      std::to_string(level).c_str(), "_", std::to_string(offset).c_str());
  return crypto_manager->enclave_sha_256(sid);
}

// This function assembles position for the current block.
void assemble_position(uint32_t level, uint32_t bid, uint32_t address,
                       sgx_oram::oram_position_t* const position) {
  position->level = level;
  position->bid = bid;
  position->address = address;
}

void get_position_and_decrypt(sgx_oram::oram_position_t* const position,
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
  status = ocall_read_position(&position_size, position_fingerprint.c_str(),
                               ciphertext, ENCRYPTED_POSITION_SIZE);
  enclave_utils::check_sgx_status(status, "ocall_read_position()");

  // Check if the position is valid.
  if (position_size == 0) {
    ocall_panic_and_flush("The position is invalid.");
  }

  // Decrypt the position.
  status = crypto_manager->enclave_aes_128_gcm_decrypt(
      ciphertext, ENCRYPTED_POSITION_SIZE,
      reinterpret_cast<uint8_t*>(position));
  enclave_utils::check_sgx_status(status, "enclave_aes_128_gcm_decrypt()");

  // Clean up the memory.
  enclave_utils::safe_free(ciphertext);
}

static sgx_status_t populate_slot(sgx_oram::oram_slot_header_t* const header,
                                  sgx_oram::oram_block_t* const slot,
                                  const uint32_t* const permutation,
                                  size_t permutation_size, uint32_t offset) {
  ENCLAVE_LOG("[enclave] populating the slot...");

  if (header->type != sgx_oram::oram_slot_type_t::ORAM_SLOT_TYPE_LEAF &&
      header->type != sgx_oram::oram_slot_type_t::ORAM_SLOT_TYPE_INTERNAL) {
    ENCLAVE_LOG("[enclave] Unknown slot type!");
    return SGX_ERROR_INVALID_PARAMETER;
  }

  const std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  const size_t slot_size = header->slot_size;
  const uint32_t slot_begin = header->range_begin;
  const uint32_t real_number = crypto_manager->get_oram_config()->number >> 1;

  size_t i = 0, limit = (slot_size >> 1);
  // The loop should end when i reaches the halve of the slot size or the
  // offset is larger than the needed size.
  // Note that blocks in the same bucket have the same block id. So the offset
  // is DEFAULT_BUCKET_SIZE times bigger than the actual offset; therefore, we
  // need to multiply slot_begin by the macro DEFAULT_BUCKET_SIZE.
  for (; (i + offset) <= real_number && (i < limit); i++) {
    sgx_oram::oram_block_t* const p_block = slot + i;
    // Fill in the block with metadata first.
    p_block->header.type = sgx_oram::ORAM_BLOCK_TYPE_NORMAL;
    p_block->header.bid = slot_begin;
    p_block->header.address = permutation[i + offset];

    ENCLAVE_LOG("[enclave] address = %u", permutation[i + offset]);

    // Assemble the <k, v> pair.
    sgx_oram::oram_position_t* position =
        (sgx_oram::oram_position_t*)malloc(ORAM_POSITION_SIZE);
    assemble_position(header->level, slot_begin, permutation[offset + i],
                      position);
    // Encrypt the position and the store it to the ouside.
    encrypt_position_and_store(position);
    // Then fill in the data.
    memset(p_block->data, 0, DEFAULT_ORAM_DATA_SIZE);
    p_block->data[0] = p_block->header.address;
    // Free the position.
    enclave_utils::safe_free(position);
    // Do not forget to  decrement the numebr of dummy blocks of the slot.
    header->dummy_number--;
  }

  for (; i < slot_size; i++) {
    sgx_oram::oram_block_t* const block_ptr = slot + i;
    // Mark the block as empty.
    block_ptr->header.type = sgx_oram::ORAM_BLOCK_TYPE_DUMMY;
  }

  return SGX_SUCCESS;
}

[[deprecated]] sgx_status_t populate_internal_slot(
    sgx_oram::oram_slot_header_t* const header,
    sgx_oram::oram_block_t* const slot) {
  // ENCLAVE_LOG("[enclave] Populating internal slot at level: %d...",
  //             slot->header.level);
  // Report an error if the type of the slot is incorrect.
  if (header->type != sgx_oram::oram_slot_type_t::ORAM_SLOT_TYPE_INTERNAL) {
    ENCLAVE_LOG("[enclave] The slot is not an internal slot!");
    return SGX_ERROR_INVALID_PARAMETER;
  }
  // Populating internal nodes are rather simple because the only thing we need
  // to do here is set all the blocks thereof to be dummy blocks.
  const size_t slot_size = header->slot_size;
  for (size_t i = 0; i < slot_size; i++) {
    sgx_oram::_oram_block_t* block = slot + i;
    memset(block, 0, ORAM_BLOCK_SIZE);
    block->header.type = sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_DUMMY;
  }

  return SGX_SUCCESS;
}

[[deprecated]] sgx_status_t populate_leaf_slot(
    sgx_oram::oram_slot_header_t* const header,
    sgx_oram::oram_block_t* const slot, const uint32_t* const permutation,
    size_t permutation_size, uint32_t offset) {
  const size_t slot_size = header->slot_size;
  // First we should perform a sanity check on
  // whether the slot is really a leaf node.
  if (header->type != sgx_oram::ORAM_SLOT_TYPE_LEAF) {
    ENCLAVE_LOG("[enclave] The slot is not a leaf node.\n");
    return SGX_ERROR_INVALID_PARAMETER;
  }

  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();

  const uint32_t slot_begin = header->range_begin;
  const uint32_t real_number =
      ((crypto_manager->get_oram_config()->number) >> 1);

  size_t i = 0, limit = ((header->slot_size) >> 1);
  // The loop should end when i reaches the halve of the slot size or the
  // offset is larger than the needed size.
  // Note that blocks in the same bucket have the same block id. So the offset
  // is DEFAULT_BUCKET_SIZE times bigger than the actual offset; therefore, we
  // need to multiply slot_begin by the macro DEFAULT_BUCKET_SIZE.

  // Or more simply, the offset + i cannot exceed the real_number.
  for (; (i + offset <= real_number) && (i < limit); i++) {
    sgx_oram::oram_block_t* const block_ptr = slot + i;
    // Fill in the block with metadata first.
    block_ptr->header.type = sgx_oram::ORAM_BLOCK_TYPE_NORMAL;
    block_ptr->header.bid = slot_begin;
    block_ptr->header.address = permutation[offset + i];

    // Assemble the <k, v> pair.
    sgx_oram::oram_position_t* position =
        (sgx_oram::oram_position_t*)malloc(ORAM_POSITION_SIZE);
    assemble_position(header->level, slot_begin, permutation[offset + i],
                      position);
    // Encrypt the position and the store it to the ouside.
    encrypt_position_and_store(position);
    // Then fill in the data.
    memset(block_ptr->data, 0, DEFAULT_ORAM_DATA_SIZE);
    block_ptr->data[0] = block_ptr->header.address;
    // Free the position.
    enclave_utils::safe_free(position);
    // Do not forget to  decrement the numebr of dummy blocks of the slot.
    header->dummy_number--;
  }

  for (; i < slot_size; i++) {
    sgx_oram::oram_block_t* const block_ptr = slot + i;
    // Mark the block as empty.
    block_ptr->header.type = sgx_oram::ORAM_BLOCK_TYPE_DUMMY;
  }

  return SGX_SUCCESS;
}

// This function assembles the slot by the given paramters.
static void assemble_slot(sgx_oram::oram_block_t* slot,
                          sgx_oram::oram_slot_header_t* const header,
                          uint32_t bucket_size, uint32_t way, bool is_leaf,
                          const uint32_t* const permutation,
                          size_t permutation_size, uint32_t* const offset) {
  // if (!is_leaf) {
  //   sgx_status_t status = populate_internal_slot(header, slot);
  //   enclave_utils::check_sgx_status(status, "populate_internal_slot()");
  // } else {
  //   // Intialize the content of the slot.
  //   sgx_status_t status = populate_leaf_slot(header, slot, permutation,
  //                                            permutation_size, *offset);
  //   enclave_utils::check_sgx_status(status, "populate_leaf_slot()");
  //   *offset += bucket_size >> 1;
  // }
  sgx_status_t status =
      populate_slot(header, slot, permutation, permutation_size, *offset);
  enclave_utils::check_sgx_status(status, "populate_slot()");
  *offset += ((header->slot_size) >> 1);
}

// This function fetches the target slot from the outside memory by calculting
// its hash value and then decrypt it in the enclave. Finally, it writes the
// decrypted target slot to the target slot buffer allocate by the caller.
// Now it is cache-enabled.
void get_slot_and_decrypt(const std::string& slot_hash, uint8_t* slot_buffer,
                          size_t slot_size) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  bool cache_enabled = crypto_manager->cache_enabled();

  if (!cache_enabled) {
    // Determine the size of the target slot in ciphertext.
    const size_t ciphertext_size =
        slot_size + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

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

    int64_t begin = enclave_utils::get_current_time();
    status = ocall_read_slot(&slot_size, slot_hash.c_str(), ciphertext,
                             ciphertext_size);
    int64_t end = enclave_utils::get_current_time();
    ocall_latency += (end - begin);

    enclave_utils::check_sgx_status(status, "get_slot_and_decrypt()");

    // Check if the slot is valid.
    if (slot_size == 0) {
      ocall_panic_and_flush("The enclave proxy cannot fetch the target slot.");
    }

    // Decrypt the target slot.
    status = crypto_manager->enclave_aes_128_gcm_decrypt(
        ciphertext, ciphertext_size, slot_buffer);
    // Free the buffer we've just allocated.
    enclave_utils::safe_free(ciphertext);
    enclave_utils::check_sgx_status(status, "enclave_aes_128_gcm_decrypt()");
  } else {
    // We fetch the target slot from the enclave cache.
    std::shared_ptr<EnclaveCache> cache_manager =
        EnclaveCache::get_instance_for_slot_body();
    const std::string ans = cache_manager->read(slot_hash, slot_size);
    // Then decrypt it.
    sgx_status_t status = crypto_manager->enclave_aes_128_gcm_decrypt(
        (uint8_t*)ans.c_str(), ans.size(), slot_buffer);
    enclave_utils::check_sgx_status(status, "enclave_aes_128_gcm_decrypt()");
  }
}

// Returns a std::string to prevent repeated calculation of the slot_hash.
std::string get_slot_header_and_decrypt(uint32_t level, uint32_t offset,
                                        sgx_oram::oram_slot_header_t* header) {
  ENCLAVE_LOG("[enclave] Fetching slot header at level %zu, offset %zu.", level,
              offset);
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  bool cache_enabled = crypto_manager->cache_enabled();
  // Compute the hash value of the target slot.
  const std::string slot_hash = calculate_slot_fingerprint(level, offset);

  if (!cache_enabled) {
    const size_t ciphertext_size =
        ORAM_SLOT_HEADER_SIZE + ORAM_CRYPTO_INFO_SIZE;
    uint8_t* ciphertext = (uint8_t*)malloc(ciphertext_size);
    memset(ciphertext, 0, ciphertext_size);
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    size_t dummy;

    int64_t begin = enclave_utils::get_current_time();
    status = ocall_read_slot_header(&dummy, slot_hash.c_str(), ciphertext,
                                    ciphertext_size);
    int64_t end = enclave_utils::get_current_time();
    ocall_latency += (end - begin);

    enclave_utils::check_sgx_status(status, "get_slot_header_and_decrypt()");

    // Check if the slot is valid.
    if (dummy == 0) {
      ocall_panic_and_flush(
          "The enclave proxy cannot fetch the target slot header.");
    }

    status = crypto_manager->enclave_aes_128_gcm_decrypt(
        ciphertext, ciphertext_size, (uint8_t*)header);
    // Free the buffer we've just allocated.
    enclave_utils::safe_free(ciphertext);
    enclave_utils::check_sgx_status(status, "enclave_aes_128_gcm_decrypt()");

    if (!check_slot_header(header, level)) {
      ocall_panic_and_flush("The slot header is invalid.");
    }
  } else {
    std::shared_ptr<EnclaveCache> cache_manager =
        EnclaveCache::get_instance_for_slot_header();
    std::string ans = cache_manager->read(slot_hash);
    // Then decrypt it.
    sgx_status_t status = crypto_manager->enclave_aes_128_gcm_decrypt(
        (uint8_t*)ans.c_str(), ans.size(), (uint8_t*)header);
    enclave_utils::check_sgx_status(status, "enclave_aes_128_gcm_decrypt()");
    if (!check_slot_header(header, level)) {
      ocall_panic_and_flush("The slot header is invalid (cache enabled).");
    }
  }

  return slot_hash;
}

// This function will calculate the offset for the slot at current level
// based on the value of block id which indicates the path from the root
// to the current slot. To determine the offset, the total level and the
// ways of the ORAM tree are needed. Level starts from 0, so the total level
// should be subtracted by 1.
uint32_t calculate_offset(uint32_t block_id, uint32_t level_cur) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();

  const uint32_t level = crypto_manager->get_oram_config()->level;
  const uint32_t way = crypto_manager->get_oram_config()->way;
  return std::floor(block_id * 1.0 / std::pow(way, level - level_cur - 1));
}

// This function assembles the slot header by the given parameters.
static inline void assemble_slot_header(
    sgx_oram::oram_slot_header_t* const header, uint32_t level, uint32_t offset,
    uint32_t bucket_size, uint32_t begin, uint32_t end, uint32_t internal_size,
    bool is_leaf) {
  header->type = is_leaf ? sgx_oram::ORAM_SLOT_TYPE_LEAF
                         : sgx_oram::ORAM_SLOT_TYPE_INTERNAL;
  header->level = level;
  header->offset = offset;
  header->dummy_number = (is_leaf ? bucket_size : internal_size);
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
        cur_size =
            (uint32_t)(std::ceil(std::pow(way, level - i - 1) * constant));
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
  // print_permutation(permutation, permutation_size);

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
          (sgx_oram::oram_slot_header_t*)malloc(ORAM_SLOT_HEADER_SIZE);
      assemble_slot_header(header, i, j, bucket_size, begin, end,
                           level_size_information[i], is_leaf);

      // Assemble the slot.
      const size_t slot_size = header->slot_size * ORAM_BLOCK_SIZE;
      sgx_oram::oram_block_t* slot = (sgx_oram::oram_block_t*)malloc(slot_size);
      assemble_slot(slot, header, bucket_size, way, is_leaf, permutation,
                    permutation_size, &offset);

      // Epilogue.
      encrypt_header_and_store(header);
      encrypt_slot_and_store((uint8_t*)slot, slot_size, i, j);
      enclave_utils::safe_free_all(2, header, slot);
    }
  }

  enclave_utils::safe_free(level_size_information);
  return SGX_SUCCESS;
}

void encrypt_position_and_store(
    const sgx_oram::oram_position_t* const position) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  // We do not store positions into the cache.
  const std::string position_hash =
      crypto_manager->enclave_sha_256(std::to_string(position->address));
  // Prepare the buffer for the ciphertext.
  const size_t encrypt_position_size =
      ORAM_POSITION_SIZE + ORAM_CRYPTO_INFO_SIZE;
  uint8_t* const encrypted_position =
      (uint8_t*)malloc(ORAM_POSITION_SIZE + ORAM_CRYPTO_INFO_SIZE);

  sgx_status_t status = SGX_ERROR_UNEXPECTED;

  status = crypto_manager->enclave_aes_128_gcm_encrypt(
      (uint8_t*)position, ORAM_POSITION_SIZE, encrypted_position);
  enclave_utils::check_sgx_status(status, "enclave_aes_128_gcm_encrypt()");
  status = ocall_write_position(position_hash.c_str(), encrypted_position,
                                encrypt_position_size);
  enclave_utils::check_sgx_status(status, "ocall_write_position()");

  // Finally, do not forget to free the buffer.
  enclave_utils::safe_free(encrypted_position);
}

void encrypt_header_and_store(
    const sgx_oram::oram_slot_header_t* const header) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  bool cache_enabled = crypto_manager->cache_enabled();
  // Get the level and the offset.
  const uint32_t level = header->level;
  const uint32_t offset = header->offset;
  const std::string slot_hash = calculate_slot_fingerprint(level, offset);

  // Prepare the buffer for the ciphertext.
  const size_t encrypted_header_size =
      ORAM_SLOT_HEADER_SIZE + ORAM_CRYPTO_INFO_SIZE;
  uint8_t* const encrypted_header = (uint8_t*)malloc(encrypted_header_size);
  sgx_status_t status = SGX_ERROR_UNEXPECTED;
  status = crypto_manager->enclave_aes_128_gcm_encrypt(
      (uint8_t*)header, ORAM_SLOT_HEADER_SIZE, encrypted_header);
  enclave_utils::check_sgx_status(status, "enclave_aes_128_gcm_encrypt()");

  if (!cache_enabled) {
    int64_t begin = enclave_utils::get_current_time();
    // Store the encrypted header.
    sgx_status_t status = ocall_write_slot_header(
        slot_hash.c_str(), encrypted_header, encrypted_header_size);
    int64_t end = enclave_utils::get_current_time();
    ocall_latency += (end - begin);

    enclave_utils::check_sgx_status(status, "ocall_write_slot_header()");
  } else {
    // Get the cache instance for storing the header.
    std::shared_ptr<EnclaveCache> cache_manager =
        EnclaveCache::get_instance_for_slot_header();
    const std::string ans = std::string(
        reinterpret_cast<char*>(encrypted_header), encrypted_header_size);
    cache_manager->write(slot_hash, ans, false);
  }

  // Finally, do not forget to free the buffer.
  enclave_utils::safe_free(encrypted_header);
}

// This function encrypts the given slot and then stores the result in the
// external unstrusted memory. All the buffers are allocated by the caller.
void encrypt_slot_and_store(const uint8_t* const slot, size_t slot_size,
                            uint32_t level, uint32_t offset) {
  // ENCLAVE_LOG("[enclave] Encrypting the slot at level %zu, offset %zu...\n",
  //             level, offset);
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  bool cache_enabled = crypto_manager->cache_enabled();
  // Calculate the hash value of the slot by its current level and the
  // offset at the current level.
  const std::string slot_hash = calculate_slot_fingerprint(level, offset);

  // Encrypt the slot.
  const size_t encrypted_slot_size = slot_size + ORAM_CRYPTO_INFO_SIZE;
  uint8_t* const encrypted_slot = (uint8_t*)malloc(encrypted_slot_size);
  sgx_status_t status = SGX_ERROR_UNEXPECTED;
  status = crypto_manager->enclave_aes_128_gcm_encrypt(slot, slot_size,
                                                       encrypted_slot);
  enclave_utils::check_sgx_status(status, "enclave_aes_128_gcm_encrypt()");

  if (!cache_enabled) {
    // Write the slot to the SGX storage.
    sgx_status_t status = ocall_write_slot(slot_hash.c_str(), encrypted_slot,
                                           encrypted_slot_size);
    enclave_utils::check_sgx_status(status, "ocall_write_slot()");
  } else {
    // Write the slot to the cache.
    std::shared_ptr<EnclaveCache> cache_manager =
        EnclaveCache::get_instance_for_slot_body();
    cache_manager->write(slot_hash,
                         std::string(reinterpret_cast<char*>(encrypted_slot),
                                     encrypted_slot_size),
                         true);
  }

  // Finally, do not forget to free the buffer.
  enclave_utils::safe_free(encrypted_slot);
}

sgx_status_t ecall_access_data(int op_type, uint32_t block_address,
                               uint8_t* data, size_t data_len) {
  ENCLAVE_LOG("[enclave] Accessing data at address %d.\n", block_address);
  // ocall_latency = 0;

  const uint64_t begin = enclave_utils::get_current_time();

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
  for (uint32_t i = level - 1; i >= 1; i--) {
    ENCLAVE_LOG("[enclave] Traversing level %d...\n", i);
    // If the current level is the same as the block level, then we should
    // directly access the data; otherwise, we should perform fake access.
    bool condition_s1 = (i == block_level);
    bool condition_s2 = (i - 1 == block_level);
    data_access(static_cast<sgx_oram::oram_operation_t>(op_type), i - 1, data,
                data_len, condition_s1, condition_s2, position);
  }

  // Encrypt the data.
  const size_t encrypted_data_size =
      DEFAULT_ORAM_DATA_SIZE + ORAM_CRYPTO_INFO_SIZE;
  uint8_t* const encrypted_data = (uint8_t*)malloc(encrypted_data_size);

  sgx_status_t status = SGX_ERROR_UNEXPECTED;
  status = crypto_manager->enclave_aes_128_gcm_encrypt(
      data, DEFAULT_ORAM_DATA_SIZE, encrypted_data);
  enclave_utils::check_sgx_status(status, "enclave_aes_128_gcm_encrypt()");

  memcpy(data, encrypted_data, DEFAULT_ORAM_DATA_SIZE);
  enclave_utils::safe_free_all(2, position, encrypted_data);

  const uint64_t end = enclave_utils::get_current_time();

  // Divide the elapsed time by 2,700,000 => to ms.
  ENCLAVE_LOG("[enclave] time used = %u", (end - begin));
  ocall_report_time("[enclave] Access time: {} us.", access_time / 2700);
  ocall_report_time("[enclave] Eviction time: {} us.", eviction_time / 2700);
  ocall_report_time("[enclave] Accumulative Ocall latency: {} us.",
                    ocall_latency / 2700);

  return SGX_SUCCESS;
}

sgx_status_t init_oram(uint32_t* permutation, size_t permutation_size) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  uint32_t* level_size_information = (uint32_t*)malloc(
      sizeof(uint32_t) * crypto_manager->get_oram_config()->level);
  sgx_status_t status = SGX_ERROR_UNEXPECTED;

  if ((status = init_so2_oram(level_size_information)) != SGX_SUCCESS) {
    ENCLAVE_LOG("[enclave] Failed to initialize the ORAM tree.");
    // Safely free the allocated memory.
    enclave_utils::safe_free(level_size_information);
    return status;
  } else if ((status = init_so2_slots(level_size_information, permutation,
                                      permutation_size)) != SGX_SUCCESS) {
    ENCLAVE_LOG("[enclave] Failed to initialize the ORAM slots.");
    enclave_utils::safe_free(level_size_information);
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
  // Set the seg size for the cache.
  std::shared_ptr<EnclaveCache> cache_manager =
      EnclaveCache::get_instance_for_slot_body();
  cache_manager->set_seg_size(crypto_manager->get_oram_config()->seg_size);
  // Begin initialize the slot...
  ENCLAVE_LOG("[enclave] Initializing the slot...");
  ENCLAVE_LOG("[enclave] oram_type is %d.",
              crypto_manager->get_oram_config()->oram_type);
  // Note that the permutation_size is the size of the permutation array in
  // bytes. We need convert it back to the number of elements.
  return init_oram(permutation, permutation_size / sizeof(uint32_t));
}
