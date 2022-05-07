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
#ifndef ORAM_SERVER_H
#define ORAM_SERVER_H

#include <string>
#include <memory>

#include <grpc++/grpc++.h>
#include <spdlog/spdlog.h>

#include "oram_storage.h"
#include "base/oram_crypto.h"
#include "protos/messages.grpc.pb.h"
#include "protos/messages.pb.h"

extern std::shared_ptr<spdlog::logger> logger;

namespace partition_oram {
class PartitionORAMService final : public server::Service {
 private:
  friend class ServerRunner;

  PartitionOramStorage storage_;
  std::shared_ptr<oram_crypto::Cryptor> cryptor_;

 public:
  grpc::Status init_oram(grpc::ServerContext* context,
                         const InitOramRequest* request,
                         google::protobuf::Empty* empty) override;

  grpc::Status read_block(grpc::ServerContext* context,
                          const ReadBlockRequest* request,
                          ReadBlockResponse* response) override;

  grpc::Status write_block(grpc::ServerContext* context,
                           const WriteBlockRequest* request,
                           WriteBlockResponse* response) override;

  grpc::Status key_exchange(grpc::ServerContext* context,
                            const KeyExchangeRequest* request,
                            KeyExchangeResponse* response) override;
};

class ServerRunner {
 private:
  std::unique_ptr<PartitionORAMService> service_;

  // Networking configurations.
  std::string address_;
  std::string port_;
  std::shared_ptr<grpc::ServerCredentials> creds_;

  bool is_initialized;

 public:
  ServerRunner(const std::string& address, const std::string& port,
               const std::string& key_path, const std::string& crt_path);

  void run(void);
};
}  // namespace partition_oram

#endif