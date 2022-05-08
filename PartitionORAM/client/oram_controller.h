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
#ifndef PARTITION_ORAM_CLIENT_ORAM_CONTROLLER_H_
#define PARTITION_ORAM_CLIENT_ORAM_CONTROLLER_H_

#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

#include <grpc++/grpc++.h>

#include "base/oram_defs.h"
#include "base/oram_crypto.h"
#include "protos/messages.grpc.pb.h"

namespace partition_oram {
// This class is the implementation of the ORAM controller for Path ORAM.
class PathOramController {
  uint32_t id_;
  // ORAM parameters.
  uint32_t number_of_leafs_;
  uint32_t tree_level_;
  uint8_t bucket_size_;

  p_oram_position_t position_map_;
  // The stash should be tied to the slots of Partition ORAM, so we use
  // pointers to manipulate the stash.
  p_oram_stash_t* stash_;
  // An object used to call some methods of ORAM storage on the cloud.
  std::shared_ptr<server::Stub> stub_;
  // Cryptography manager.
  std::shared_ptr<oram_crypto::Cryptor> cryptor_;

  // ==================== Begin private methods ==================== //
  Status ReadBucket(uint32_t path, uint32_t level,
                     p_oram_bucket_t* const bucket);
  Status WriteBucket(uint32_t path, uint32_t level,
                      const p_oram_bucket_t& bucket);

  p_oram_stash_t FindSubsetOf(uint32_t current_path);
  // ==================== End private methods ==================== //

 public:
  PathOramController(uint32_t id, uint32_t block_num, uint32_t bucket_size);

  void set_stub(std::shared_ptr<server::Stub> stub) { stub_ = stub; }
  void set_stash(p_oram_stash_t* const stash) { stash_ = stash; }

  Status InitOram(void);
  Status FillWithData(const std::vector<oram_block_t>& data);

  // The meanings of parameters are explained in Stefanov et al.'s paper.
  Status Access(Operation op_type, uint32_t address, uint8_t* const data);

  virtual ~PathOramController() {}
};

// This class is the implementation of the ORAM controller for Partition ORAM.
class OramController {
  size_t partition_size_;
  // Position map: [key] -> [<slot_id, offset>].
  pp_oram_position_t position_map_;
  // Slots: [slot_id] -> [block1, block2, ..., block_n].
  pp_oram_slot_t slots_;
  // Controllers for each slot: [slot_id] -> [controller_1, controller_2, ...,
  //                                          controller_n].
  std::vector<std::unique_ptr<PathOramController>> path_oram_controllers_;
  // Cryptography manager.
  std::shared_ptr<oram_crypto::Cryptor> cryptor_;
  // Stub
  std::shared_ptr<server::Stub> stub_;

  OramController() {}
 
 public:
  static std::unique_ptr<OramController> GetInstance();

  void set_stub(std::shared_ptr<server::Stub> stub) { stub_ = stub; }

  Status Access(Operation op_type, uint32_t address, oram_block_t* const data);
  Status Evict(EvictType evict_type);
  Status Run(uint32_t block_num, uint32_t bucket_size);

  // A reserved interface for testing one of the PathORAM controllers.
  Status TestPathOram(uint32_t controller_id);

  virtual ~OramController() {}
};
}  // namespace partition_oram

#endif // PARTITION_ORAM_CLIENT_ORAM_CONTROLLER_H_