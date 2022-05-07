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
#ifndef ORAM_CONTROLLER_H
#define ORAM_CONTROLLER_H

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
  Status read_bucket(uint32_t path, uint32_t level,
                     p_oram_bucket_t* const bucket);
  Status write_bucket(uint32_t path, uint32_t level,
                      const p_oram_bucket_t* const bucket);
  // ==================== End private methods ==================== //

 public:
  PathOramController();

  void run(const std::string& address,
           const grpc::SslCredentialsOptions& options);

  // The meanings of parameters are explained in Stefanov et al.'s paper.
  Status access(Operation op_type, uint32_t address, uint8_t* const data);

  virtual ~PathOramController() {}
};

// This class is the implementation of the ORAM controller for Partition ORAM.
class OramController {
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

  OramController();  // TODO: should feed in with some parameters?

 public:
  static std::shared_ptr<OramController> get_instance();

  void set_stub(std::shared_ptr<server::Stub> stub) { stub_ = stub; }

  Status access(Operation op_type, uint32_t address, oram_block_t* const data);
  Status evict(EvictType evict_type);

  virtual ~OramController() {}
};
}  // namespace partition_oram

#endif