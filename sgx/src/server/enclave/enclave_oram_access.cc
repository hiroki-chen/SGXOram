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
#include <enclave/enclave_oram_access.hh>

#include <cstring>

#include <enclave/enclave_crypto_manager.hh>
#include <enclave/enclave_utils.hh>
#include <enclave/enclave_oram.hh>

bool constant = true;

static inline bool is_in_range(uint32_t num,
                               sgx_oram::oram_slot_header_t* const slot) {
  const uint32_t begin = slot->range_begin;
  const uint32_t end = slot->range_end;
  return num >= begin && num < end;
}

void sub_access_s1(bool condition, sgx_oram::oram_slot_header_t* const header,
                   uint8_t* const s1, uint8_t* const block_slot1_target,
                   uint8_t* const block_slot1_evict, uint32_t* const counter,
                   sgx_oram::oram_position_t* const position) {
  ENCLAVE_LOG("[enclave] Invoking sub_access_s1...");
  sgx_oram::oram_block_t* slot_storage = (sgx_oram::oram_block_t*)s1;
  const size_t slot_size = header->slot_size;

  bool should_add = false;

  ENCLAVE_LOG("[enclave] before dummy_number: %d.", header->dummy_number);
  for (size_t i = 0; i < slot_size; i++) {
    // Locate the blocks.
    sgx_oram::oram_block_t* block = slot_storage + i;
    // enclave_utils::print_block(block);
    // Initialize some bool variables.
    // Variable condition_existing stands for whether the target block is
    // existing:
    //  - true: the target block is existing and we want it.
    //  - false: the target block is not existing OR we do not want it.
    // Here, "existing" means that the block is not dummy and the address
    // corresonds to our requested address.
    bool condition_existing =
        condition && (block->header.address == position->address) &&
        (block->header.type ==
         sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_NORMAL);

    // Variable condition_epsilon stands for whether the block should be
    // evicted:
    //  - true: the block should be evicted.
    //  - false: the block should not be evicted.
    // Here, "epsilon" stands for the block is not dummy and the block id is not
    // in the range of this slot.
    bool condition_epsilon =
        !(is_in_range(block->header.bid, header)) &&
        (block->header.type ==
         sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_NORMAL);

    enclave_utils::oblivious_assign(
        condition_existing, (uint8_t*)block_slot1_target, (uint8_t*)block,
        ORAM_BLOCK_SIZE, ORAM_BLOCK_SIZE);

    // Counter is used to track the number of blocks that should be evicted.
    // We strictly guarantee that only one block should be evicted at one time.
    *counter += condition_epsilon;
    bool condition_counter = (*counter <= 1);
    // Copy the data to the target buffer.
    enclave_utils::oblivious_assign(
        condition_epsilon && condition_counter, (uint8_t*)block_slot1_evict,
        (uint8_t*)block, ORAM_BLOCK_SIZE, ORAM_BLOCK_SIZE);
    enclave_utils::oblivious_assign(
        (condition_existing) || (condition_epsilon && condition_counter),
        (bool*)&block->header.type, &constant);
    // Increment the dummy number of the slot if any non-dummy slot is read and
    // removed, which is important for tracking the number of accesses and a
    // reasonable eviction / access strategy.
    //
    // There are two cases:
    //  - The slot is not dummy and this is a real access and the slot is the
    //    target one.
    //  - The slot is not dummy and this slot can be evicted.
    enclave_utils::oblivious_assign(
        (condition_existing || (condition_epsilon && condition_counter)),
        &should_add, &constant);
  }

  header->dummy_number += should_add;
  ENCLAVE_LOG("[enclave] after dummy_number: %d.", header->dummy_number);
}

void sub_access_s2(sgx_oram::oram_operation_t op_type, bool condition,
                   sgx_oram::oram_slot_header_t* const header,
                   uint8_t* const s2,
                   sgx_oram::oram_block_t* const block_slot1_target,
                   uint8_t* const data_star, uint32_t* const counter,
                   uint32_t pos,
                   sgx_oram::oram_position_t* const position_target,
                   sgx_oram::oram_position_t* const position_client) {
  // Get the range of the slot.
  const uint32_t begin = header->range_begin;
  const uint32_t end = header->range_end;
  const size_t slot_size = header->slot_size;
  ENCLAVE_LOG(
      "[enclave] Invoking sub_access_s2 for slot at level %u, offset %u...\n",
      header->level, header->offset);
  // Prepare a buffer for holding the populated boolean variable.
  uint8_t* populated_bool_for_data = (uint8_t*)malloc(DEFAULT_ORAM_DATA_SIZE);
  uint8_t* populated_bool_for_bid = (uint8_t*)malloc(WORD_SIZE);

  // Update dummy_number in advance.
  header->dummy_number -= (block_slot1_target->header.type ==
                           sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_NORMAL);

  // Get the slot storage.
  sgx_oram::oram_block_t* slot_storage = (sgx_oram::oram_block_t*)s2;
  // Then we do an one-pass on the slot S2.
#pragma omp parallel for if (slot_size > 65535)
  for (size_t i = 0; i < slot_size; i++) {
    // Get the block.
    sgx_oram::oram_block_t* block = slot_storage + i;

    // =========== Begin First Part: data processing =========== //
    // Step 1: bl.data = bl.data & ~(pos = 0)
    //  -> Clear the current block for holding the incoming data.
    // Step 2: bl.data = bl.data | (bl1.data & ~pos)
    //  -> Copy the data from the target block to the current block.
    //     if (bl1.data & ~pos) is not zero.
    // Step 3: bl.data = bl.data & ~(c_e & op)
    //  -> Clear the current block for holding the incoming data from the
    //     client.
    // Step 4: bl.data = bl.data | (op & data*)
    //  -> Copy the data from the client to the current block.
    memset(populated_bool_for_data, 0, DEFAULT_ORAM_DATA_SIZE);
    const uint32_t nbid = enclave_utils::uniform_random(begin, end);
    pos -= (block->header.type ==
            sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_DUMMY);
    // The variable bool_existing denotes whether there is a target block in the
    // current slot. If there is, we want to read it or write something into it.
    //
    // condition_existing is true if and only if:
    //  - bl.address = given address,
    //  - bl.type = ORAM_BLOCK_TYPE_NORMAL, and
    //  - this is not a fake operation.
    bool condition_existing =
        (condition) && (block->header.address == position_client->address) &&
        (block->header.type ==
         sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_NORMAL);

    // Populate the buffer.
    enclave_utils::populate_from_bool(!(pos == 0), populated_bool_for_data,
                                      DEFAULT_ORAM_DATA_SIZE);
    enclave_utils::band(block->data, populated_bool_for_data, block->data,
                        DEFAULT_ORAM_DATA_SIZE, DEFAULT_ORAM_DATA_SIZE);

    enclave_utils::populate_from_bool((pos == 0), populated_bool_for_data,
                                      DEFAULT_ORAM_DATA_SIZE);
    enclave_utils::band(block_slot1_target->data, populated_bool_for_data,
                        block_slot1_target->data, DEFAULT_ORAM_DATA_SIZE,
                        DEFAULT_ORAM_DATA_SIZE);
    enclave_utils::bor(block->data, block_slot1_target->data, block->data,
                       DEFAULT_ORAM_DATA_SIZE, DEFAULT_ORAM_DATA_SIZE);

    enclave_utils::populate_from_bool(!(condition_existing && op_type),
                                      populated_bool_for_data,
                                      DEFAULT_ORAM_DATA_SIZE);
    enclave_utils::band(block->data, populated_bool_for_data, block->data,
                        DEFAULT_ORAM_DATA_SIZE, DEFAULT_ORAM_DATA_SIZE);

    enclave_utils::populate_from_bool(op_type, populated_bool_for_data,
                                      DEFAULT_ORAM_DATA_SIZE);
    enclave_utils::band(data_star, populated_bool_for_data,
                        populated_bool_for_data, DEFAULT_ORAM_DATA_SIZE,
                        DEFAULT_ORAM_DATA_SIZE);
    enclave_utils::bor(block->data, populated_bool_for_data, block->data,
                       DEFAULT_ORAM_DATA_SIZE, DEFAULT_ORAM_DATA_SIZE);
    // =========== End First Part: data processing =========== //

    // =========== Begin Second Part: bid processing =========== //
    uint32_t bid_a = 0, bid_b = 0, bid_c = 0;
    // bid1 ← (pos = 0) ∧ bl1.bid
    enclave_utils::populate_from_bool((pos == 0), populated_bool_for_bid,
                                      WORD_SIZE);
    enclave_utils::band((uint8_t*)(&(block_slot1_target->header.bid)),
                        populated_bool_for_bid, (uint8_t*)(&bid_a), WORD_SIZE,
                        WORD_SIZE);
    // bid2 ← (pos ̸ = 0) ∧ ce ∧ op ∧ nbid
    enclave_utils::populate_from_bool(
        (pos != 0) && (condition_existing) &&
            (op_type == sgx_oram::oram_operation_t::ORAM_OPERATION_WRITE),
        populated_bool_for_bid, WORD_SIZE);
    enclave_utils::band((uint8_t*)(&(nbid)), populated_bool_for_bid,
                        (uint8_t*)(&bid_b), WORD_SIZE, WORD_SIZE);
    // bid3 ← (pos ̸ = 0) ∧ ¬ce ∧ bl.bid
    enclave_utils::populate_from_bool((pos != 0) && (!condition_existing),
                                      populated_bool_for_bid, WORD_SIZE);
    enclave_utils::band((uint8_t*)(&(block->header.bid)),
                        populated_bool_for_bid, (uint8_t*)(&bid_c), WORD_SIZE,
                        WORD_SIZE);
    // bl.bid ← bid1 ∨ bid2 ∨ bid3
    enclave_utils::bor((uint8_t*)(&bid_a), (uint8_t*)(&bid_b),
                       (uint8_t*)(&bid_a), WORD_SIZE, WORD_SIZE);
    enclave_utils::bor((uint8_t*)(&bid_a), (uint8_t*)(&bid_c),
                       (uint8_t*)(&bid_a), WORD_SIZE, WORD_SIZE);
    enclave_utils::bor((uint8_t*)(&(block->header.bid)), (uint8_t*)(&bid_a),
                       (uint8_t*)(&(block->header.bid)), WORD_SIZE, WORD_SIZE);
    // =========== End Second Part: bid processing =========== //

    // =========== Begin Third Part: is_dummy processing =========== //
    bool delta_a =
        (pos == 0) && (block_slot1_target->header.type ==
                       sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_DUMMY);
    bool delta_b = (pos != 0) && !(condition_existing) &&
                   (block->header.type ==
                    sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_DUMMY);
    bool delta_c =
        (pos != 0) && (condition_existing) &&
        (op_type == sgx_oram::oram_operation_t::ORAM_OPERATION_WRITE);
    block->header.type =
        static_cast<sgx_oram::oram_block_type_t>(delta_a || delta_b || delta_c);
    // =========== End Third Part: is_dummy processing =========== //

    // enclave_utils::print_block(block);
  }

  // Obliviously update the position map.
  const uint32_t bid_cur =
      enclave_utils::uniform_random(header->range_begin, header->range_end);
  ENCLAVE_LOG("[enclave] bid_cur: %d", bid_cur);
  // Assign the newly sampled bid to the position.
  enclave_utils::oblivious_assign(
      (block_slot1_target->header.type ==
       sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_NORMAL),
      (uint8_t*)&(position_target->bid), (uint8_t*)(&bid_cur), WORD_SIZE,
      WORD_SIZE);
  encrypt_position_and_store(position_target);

  // Finally, we do the one-pass again and read the target data to the client.
  // This time, there is nothing for us to do, i.e., the only thing we need to
  // do is check whether the target block exists.
  for (size_t i = 0; i < slot_size; i++) {
    // Get the block and prepare a buffer for the boolean variable.
    sgx_oram::oram_block_t* block = slot_storage + i;
    // enclave_utils::print_block(block);

    // Check whether this is the target one.
    bool condition_existing =
        (condition) &&
        (op_type == sgx_oram::oram_operation_t::ORAM_OPERATION_READ) &&
        (block->header.address == position_client->address) &&
        (block->header.type ==
         sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_NORMAL);

    enclave_utils::oblivious_assign(condition_existing, data_star, block->data,
                                    DEFAULT_ORAM_DATA_SIZE,
                                    DEFAULT_ORAM_DATA_SIZE);
    // Update dummy_number.
    header->dummy_number += condition_existing;
  }

  enclave_utils::safe_free_all(2, populated_bool_for_data,
                               populated_bool_for_bid);
}

// This functions performs some necessary clean-ups and variables assignments
// for accessing the slot S2. In particular, we sample new bid for the block
// read from S1 and then samples an empty position for holding it. Finally,
// we do oblivious assignment that copies nbid to the bid field of the block.
void sub_access_s1_epilogue(bool condition, uint32_t dummy_number,
                            sgx_oram::oram_block_t* block_slot1_target,
                            sgx_oram::oram_block_t* block_slot1_evict,
                            uint32_t* const counter, uint32_t* const position) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  // Samples two RVs.
  const uint32_t nbid = enclave_utils::uniform_random(
      0, ((crypto_manager->get_oram_config()->number) >> 1) - 1);
  *position = enclave_utils::uniform_random(1, dummy_number);
  // Performs the oblivious assignment.
  enclave_utils::oblivious_assign(condition,
                                  (uint8_t*)&block_slot1_target->header.bid,
                                  (uint8_t*)&nbid, WORD_SIZE, WORD_SIZE);
  // If the current operation is fake, then we do not need to do anything.
  block_slot1_target->header.type =
      static_cast<sgx_oram::oram_block_type_t>(!condition);
  // If there is no block that should be evicted, we explicitly mark the block
  // as dummy.
  block_slot1_evict->header.type =
      static_cast<sgx_oram::oram_block_type_t>(*counter < 1);
  // Reset the counter.
  *counter = 0;
}

void sub_access(sgx_oram::oram_operation_t op_type, bool condition_s1,
                bool condition_s2,
                sgx_oram::oram_slot_header_t* const s1_header,
                sgx_oram::oram_slot_header_t* const s2_header,
                uint8_t* const s1, size_t s1_size, uint8_t* const s2,
                size_t s2_size, uint8_t* const data_star, uint32_t level,
                sgx_oram::oram_position_t* const position) {
  ENCLAVE_LOG("[enclave] Invoking sub_access for level %u...", level);
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
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

  // The only difference between a leaf node and the internal node is their
  // size, so headers are the same. We can just skip the header and directly
  // access the data in the slot.
  sub_access_s1(condition_s1, s1_header, s1, (uint8_t*)block_slot1_target,
                (uint8_t*)block_slot1_evict, &counter, position);

  // Set the type of the slot as per the counter.
  enclave_utils::oblivious_assign(
      counter == 0, (bool*)&block_slot1_evict->header.type, &constant);
  // - Copy the data to the data_star if current operation is read.
  // - Note that we do nothing if the current operation is dummy.
  enclave_utils::oblivious_assign(
      (op_type == sgx_oram::oram_operation_t::ORAM_OPERATION_READ) &&
          (condition_s1),
      data_star, (uint8_t*)block_slot1_target->data, DEFAULT_ORAM_DATA_SIZE,
      DEFAULT_ORAM_DATA_SIZE);
  // - Copy the data_star to the data if current operation is write.
  enclave_utils::oblivious_assign(
      (op_type == sgx_oram::oram_operation_t::ORAM_OPERATION_WRITE) &&
          (condition_s1),
      (uint8_t*)block_slot1_target->data, data_star, DEFAULT_ORAM_DATA_SIZE,
      DEFAULT_ORAM_DATA_SIZE);

  // If there is no target block, we read the block_evict.
  enclave_utils::oblivious_assign(
      !(condition_s1) && (block_slot1_evict->header.type ==
                          sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_NORMAL),
      (uint8_t*)(block_slot1_target), (uint8_t*)(block_slot1_evict),
      DEFAULT_ORAM_DATA_SIZE, DEFAULT_ORAM_DATA_SIZE);

  // Sample new bid and a random position for the blocks and reset the counter.
  uint32_t pos = 0;
  ENCLAVE_LOG("[enclave] S1 HEADER...");

  sub_access_s1_epilogue(condition_s1, s1_header->dummy_number,
                         block_slot1_target, block_slot1_evict, &counter, &pos);
  // After accessing, we need to update the slot.
  ENCLAVE_LOG(
      "[enclave] Slot 1 accessed! Now storing it to the cache / memory...");
  encrypt_slot_and_store(s1, s1_size, s1_header->level, s1_header->offset);

  // Fetch the position for the block_target.
  sgx_oram::oram_position_t* position_target =
      (sgx_oram::oram_position_t*)malloc(ORAM_POSITION_SIZE);
  position_prefetch(position_target, block_slot1_target);
  // get_position_and_decrypt(position_target,
  // block_slot1_target->header.address);

  // Invoke sub_access_s2.
  sub_access_s2(op_type, condition_s2, s2_header, s2, block_slot1_target,
                data_star, &counter, pos, position_target, position);
  encrypt_slot_and_store(s2, s2_size, s2_header->level, s2_header->offset);

  // Eventually, destroy all the allocated memory.
  enclave_utils::safe_free_all(3, block_slot1_target, block_slot1_evict,
                               position_target);
}

void sub_evict_s2(sgx_oram::oram_slot_header_t* const header, uint8_t* const s2,
                  sgx_oram::oram_block_t* const block_evict,
                  uint32_t current_level, uint32_t* const counter) {
  const size_t slot_size = header->slot_size;
  sgx_oram::oram_block_t* slot_storage = (sgx_oram::oram_block_t*)s2;

#pragma omp parallel for if (slot_size > 65535)
  for (size_t i = 0; i < slot_size; i++) {
    sgx_oram::oram_block_t* const block = slot_storage + i;

    bool condition_epsilon = !is_in_range(block->header.bid, header);
    *counter += condition_epsilon;
    bool condition_counter = (*counter <= 1);
    bool condition_normal =
        (block->header.type ==
         sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_NORMAL);
    enclave_utils::oblivious_assign(
        (condition_counter && condition_epsilon && condition_normal),
        (uint8_t*)block_evict, (uint8_t*)block, ORAM_BLOCK_SIZE,
        ORAM_BLOCK_SIZE);

    block->header.type = static_cast<sgx_oram::oram_block_type_t>(
        (condition_counter && condition_epsilon && condition_normal));
    // Increment the dummy number of the current slot.
    header->dummy_number +=
        (condition_counter && condition_epsilon && condition_normal);
  }
}

void sub_evict_s3(sgx_oram::oram_slot_header_t* const header, uint8_t* const s3,
                  sgx_oram::oram_block_t* const block_evict,
                  sgx_oram::oram_position_t* const position_target,
                  uint32_t position) {
  const size_t slot_size = header->slot_size;
  // Reinterpret the memory to oram blocks.
  sgx_oram::oram_block_t* slot_storage = (sgx_oram::oram_block_t*)s3;
  // Prepare a buffer for storing populated boolean variable.
  uint8_t* populated = (uint8_t*)malloc(ORAM_BLOCK_SIZE);

#pragma omp parallel for if (slot_size > 65535)
  for (size_t i = 0; i < slot_size; i++) {
    sgx_oram::oram_block_t* const block = slot_storage + i;
    position -= block->header.type ==
                sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_DUMMY;
    // Position == 0 denotes the case that block_evict can be written to the
    // current block, so we need to clear the current block. To this ends,
    // the condition must be the reverse of the condition position == 0.
    enclave_utils::populate_from_bool((position != 0), populated,
                                      ORAM_BLOCK_SIZE);
    enclave_utils::band((uint8_t*)block, populated, (uint8_t*)block,
                        ORAM_BLOCK_SIZE, ORAM_BLOCK_SIZE);
    enclave_utils::populate_from_bool((position == 0), populated,
                                      ORAM_BLOCK_SIZE);
    enclave_utils::band((uint8_t*)block_evict, populated, populated,
                        ORAM_BLOCK_SIZE, ORAM_BLOCK_SIZE);
    enclave_utils::bor((uint8_t*)block, populated, (uint8_t*)block,
                       ORAM_BLOCK_SIZE, ORAM_BLOCK_SIZE);
    header->dummy_number -=
        (block_evict->header.type ==
         sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_NORMAL);
  }

  // Update the position map.
  const uint32_t bid_cur =
      enclave_utils::uniform_random(header->range_begin, header->range_end);
  enclave_utils::oblivious_assign(
      (block_evict->header.type ==
       sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_NORMAL),
      (uint8_t*)(&position_target->bid), (uint8_t*)(&bid_cur), WORD_SIZE,
      WORD_SIZE);

  enclave_utils::safe_free(populated);
}

// Similar to sub_access_s2_epilogue, this function performs some necessary
// clean-ups and variables assignments for accessing the slot S3.
// A random position will be sampled and the new bid will be assigned to the
// slot read from S2. However, since sub_evict will evict a block to the next
// level, to ensure obliviousness, we need to randomly sample a branch if there
// is no block to evict.
void sub_evict_s2_epilogue(uint32_t dummy_number, uint32_t begin, uint32_t end,
                           sgx_oram::oram_block_t* block_evict,
                           uint32_t* const counter, uint32_t* const position,
                           uint32_t* const bid) {
  bool condition_evict = (*counter < 1);
  block_evict->header.type =
      static_cast<sgx_oram::oram_block_type_t>(condition_evict);
  *position = enclave_utils::uniform_random(1, dummy_number);

  const uint32_t random_branch = enclave_utils::uniform_random(begin, end);
  enclave_utils::oblivious_assign(condition_evict, (uint8_t*)bid,
                                  (uint8_t*)(&random_branch), WORD_SIZE,
                                  WORD_SIZE);
}

// The main entry of the data access.
// In this function, three slots are involved to fetch the block from
// the ORAM tree, although a slot is implicitly accessed by another function
// called by this function.
void data_access(sgx_oram::oram_operation_t op_type, uint32_t current_level,
                 uint8_t* const data, size_t data_size, bool condition_s1,
                 bool condition_s2, sgx_oram::oram_position_t* const position) {
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

  // Fetch the slot header at first.
  sgx_oram::oram_slot_header_t* s1_header =
      (sgx_oram::oram_slot_header_t*)malloc(ORAM_SLOT_HEADER_SIZE);
  sgx_oram::oram_slot_header_t* s2_header =
      (sgx_oram::oram_slot_header_t*)malloc(ORAM_SLOT_HEADER_SIZE);
  const std::string s1_hash =
      get_slot_header_and_decrypt(current_level + 1, offset_s1, s1_header);
  const std::string s2_hash =
      get_slot_header_and_decrypt(current_level, offset_s2, s2_header);

  // Fetch the slot storage at second.
  const size_t s1_size = s1_header->slot_size * ORAM_BLOCK_SIZE;
  const size_t s2_size = s2_header->slot_size * ORAM_BLOCK_SIZE;
  uint8_t* s1_storage = (uint8_t*)malloc(s1_size);
  uint8_t* s2_storage = (uint8_t*)malloc(s2_size);

  // Read the slots from the SGX storage.
  // We may need to put all the slots in a buffer pool so that we can
  // immediately free the unneeded slots after a write opeation.
  get_slot_and_decrypt(s1_hash, (uint8_t*)s1_storage, s1_size);
  get_slot_and_decrypt(s2_hash, (uint8_t*)s2_storage, s2_size);

  // Invoke sub_access.
  sub_access(op_type, condition_s1, condition_s2, s1_header, s2_header,
             s1_storage, s1_size, s2_storage, s2_size, data, current_level,
             position);
  return;
  // Invoke sub_evict.
  ENCLAVE_LOG("[enclave] Invoking sub_evict for level %d...", current_level);
  sub_evict(s2_header, s2_storage, s2_size, current_level, position);

  enclave_utils::safe_free_all(4, s1_storage, s2_storage, s1_header, s2_header);
}

void sub_evict(sgx_oram::oram_slot_header_t* const s2_header, uint8_t* const s2,
               size_t s2_size, uint32_t current_level,
               sgx_oram::oram_position_t* const position) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();

  // Initialize all the needed objects.
  uint32_t counter = 0;
  sgx_oram::oram_block_t* block =
      (sgx_oram::oram_block_t*)malloc(ORAM_BLOCK_SIZE);
  memset(block, 0, ORAM_BLOCK_SIZE);

  // Access slot s2.
  sub_evict_s2(s2_header, s2, block, current_level, &counter);

  ENCLAVE_LOG(
      "[enclave] Slot 2 is accessed!"
      " Now storing it to the cache / memory...");
  // After access, we need store the modified slot to the external memory.
  const uint32_t s2_level = s2_header->level;
  const uint32_t s2_offset = s2_header->offset;
  encrypt_slot_and_store(s2, s2_size, s2_level, s2_offset);

  uint32_t pos;
  uint32_t bid = block->header.bid;
  sub_evict_s2_epilogue(s2_header->dummy_number, s2_header->range_begin,
                        s2_header->range_end, block, &counter, &pos, &bid);
  enclave_utils::safe_free(block);

  // Prepare for accessing the slot S3.
  // We first fetch the header of S3.
  sgx_oram::oram_slot_header_t* s3_header =
      (sgx_oram::oram_slot_header_t*)malloc(ORAM_SLOT_HEADER_SIZE);
  const uint32_t offset = calculate_offset(position->bid, current_level + 1);
  const std::string s3_hash =
      get_slot_header_and_decrypt(current_level + 1, offset, s3_header);

  // Then fetch the storage.
  const size_t s3_size = s3_header->slot_size * ORAM_BLOCK_SIZE;
  uint8_t* s3_storage = (uint8_t*)malloc(s3_size);
  get_slot_and_decrypt(s3_hash, s3_storage, s3_size);

  // Get the position of block_evict.
  sgx_oram::oram_position_t* const position_evict =
      (sgx_oram::oram_position_t*)malloc(ORAM_POSITION_SIZE);
  position_prefetch(position_evict, block);

  // Then we access the slot S3.
  sub_evict_s3(s3_header, s3_storage, block, position_evict, pos);
  // After access, we store the slot to the external memory.
  const uint32_t s3_level = s3_header->level;
  const uint32_t s3_offset = s3_header->offset;
  encrypt_slot_and_store(s3_storage, s3_size, s3_level, s3_offset);
  enclave_utils::safe_free_all(3, s3_header, s3_storage, position_evict);

  // Prepare a dummy buffer for dummy operations.
  uint8_t* const dummy_buffer = (uint8_t*)malloc(DEFAULT_ORAM_DATA_SIZE);
  memset(dummy_buffer, 0, DEFAULT_ORAM_DATA_SIZE);

  // Finally, recursively access all the levels below it.
  const uint32_t level = crypto_manager->get_oram_config()->level;
  for (uint32_t i = current_level + 1; i < level - 1; i++) {
    data_access(sgx_oram::oram_operation_t::ORAM_OPERATION_READ, i,
                dummy_buffer, DEFAULT_ORAM_DATA_SIZE, 0, 0, position);
  }

  enclave_utils::safe_free(dummy_buffer);
}

void position_prefetch(sgx_oram::oram_position_t* const position,
                       const sgx_oram::oram_block_t* const block) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();

  // If block == dummy, we read some position arbitrarily.
  uint32_t address = enclave_utils::uniform_random(
      0, ((crypto_manager->get_oram_config()->number) >> 1) - 1);
  enclave_utils::oblivious_assign(
      block->header.type == sgx_oram::oram_block_type_t::ORAM_BLOCK_TYPE_NORMAL,
      (uint8_t*)(&address), (uint8_t*)(&block->header.address), WORD_SIZE,
      WORD_SIZE);

  get_position_and_decrypt(position, address);
}