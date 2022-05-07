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
#include "oram_controller.h"

#include <algorithm>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/bin_to_hex.h>

#include "base/oram_crypto.h"
#include "base/oram_utils.h"

extern std::shared_ptr<spdlog::logger> logger;

namespace partition_oram {
std::shared_ptr<OramController> OramController::get_instance() {
  static std::shared_ptr<OramController> instance =
      std::shared_ptr<OramController>(new OramController());
  return instance;
}

PathOramController::PathOramController() { ; }

Status PathOramController::read_bucket(uint32_t path, uint32_t level,
                                       p_oram_bucket_t* const bucket) {
  if (path >= number_of_leafs_ || level > tree_level_) {
    return Status::INVALID_ARGUMENT;
  }

  grpc::ClientContext context;

  // Then prepare for RPC call.
  ReadPathRequest request;
  ReadPathResponse response;
  request.set_path(path);
  request.set_level(level);
  grpc::Status status = stub_->read_path(&context, request, &response);

  if (!status.ok()) {
    return Status::SERVER_ERROR;
  }

  const size_t bucket_size = response.bucket_size();
  // Then copy the bucket to the vector.
  for (size_t j = 0; j < bucket_size; j++) {
    oram_block_t* const block = (oram_block_t*)malloc(ORAM_BLOCK_SIZE);
    oram_utils::convert_to_block(response.bucket(j), block);
    bucket->emplace_back(*block);
    oram_utils::safe_free(block);
  }

  return Status::OK;
}

Status PathOramController::write_bucket(uint32_t path, uint32_t level,
                                        const p_oram_bucket_t* const bucket) {
  return Status::OK;
}

Status PathOramController::access(Operation op_type, uint32_t address,
                                  uint8_t* const data) {
  // First we do a sanity check.
  PANIC_IF(op_type == Operation::INVALID, "Invalid operation.");

  // First, we sample a random new path for this block.
  const uint32_t new_path =
      oram_crypto::Cryptor::uniform_random(0, number_of_leafs_ - 1);

  // Next, we shall the get the real path of the current block.
  // @ref Stefanov's paper for full details.
  // Steps: 1-2
  // Randomly remap the position of block a to a new random position.
  // Let x denote the block’s old position.
  const uint32_t x = position_map_[address];
  // Update the position map.
  position_map_[address] = new_path;

  // Step 3-5: Read the whole path from the server into the stash.
  p_oram_path_t bucket_this_path;

  for (size_t i = 0; i <= tree_level_; i++) {
    p_oram_bucket_t bucket_this_level;
    Status status = read_bucket(x, i, &bucket_this_level);
    oram_utils::check_status(
        status, oram_utils::string_concat("Failed to read bucket: ", x));
    bucket_this_path.emplace_back(bucket_this_level);
  }

  // Read all the blocks into the stash.
  for (size_t i = 0; i <= tree_level_; i++) {
    for (size_t j = 0; j < bucket_this_path[i].size(); j++) {
      oram_block_t block = bucket_this_path[i][j];

      // Check if the block is already in the stash.
      // If there is no such block, we add it to the stash.
      //
      // <=> S = S ∪ ReadBucket(P(x, l))
      auto iter = std::find_if(stash_->begin(), stash_->end(),
                               block_eq(block.header.block_id));
      if (iter == stash_->end()) {
        stash_->emplace_back(block);
      }
    }
  }

  // Step 6-9: Update block, if any.
  // If the access is a write, update the data stored for block a.
  auto iter = std::find_if(stash_->begin(), stash_->end(), block_eq(address));
  PANIC_IF(iter == stash_->end(), "Failed to find the block in the stash.");

  // Update the block.
  if (op_type == Operation::WRITE) {
    memcpy(iter->data, data, DEFAULT_ORAM_DATA_SIZE);
  } else {
    memcpy(data, iter->data, DEFAULT_ORAM_DATA_SIZE);
  }

  // STEP 10-15: Write the path.
  //
  // Write the path back and possibly include some additional blocks from the
  // stash if they can be placed into the path. Buckets are greedily filled with
  // blocks in the stash in the order of leaf to root, ensuring that blocks get
  // pushed as deep down into the tree as possible. A block a? can be placed in
  // the bucket at level ? only if the path P(position[a']) to the leaf of block
  // a' intersects the path accessed P(x) at level l.
  // In other words, if P(x, l) = P(position[a'], l).
  for (size_t i = tree_level_; i >= 0; i--) {
    // Find a subset S' of stash such that the element in S' intersects with the
    // current old path of x.
    // I.e., S' ← {(a', data') \in S : P(x, l) = P(position[a'], l)}
    // Select min(|S'|, Z) blocks. If |S'| < Z, then we pad S' with dummy
    // blocks. Expire all blocks in S that are in S'. Write them back.
  }

  return Status::OK;
}

OramController::OramController() { ; }

Status OramController::access(Operation op_type, uint32_t address,
                              oram_block_t* const data) {
  return Status::OK;
}

Status OramController::evict(EvictType evict_type) { return Status::OK; }
}  // namespace partition_oram