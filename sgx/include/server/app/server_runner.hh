/*
 Copyright (c) 2021 Haobin Chen

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
#include <unordered_map>
#include <string>

#include <grpc++/grpc++.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <sgx_urts.h>
#include <sgx_key_exchange.h>

#include <messages.grpc.pb.h>
#include <messages.pb.h>

#define DH_HALF_KEY_LEN 32
#define DH_SHARED_KEY_LEN 32
#define SAMPLE_SP_IV_SIZE 12
#define MAX_VERIFICATION_RESULT 2

class SGXORAMService final : public oram::sgx_oram::Service {
 private:
  // Maps between fingerprint and serialized json string.
  std::unordered_map<std::string, std::string> storage;

  sgx_status_t init_enclave(sgx_enclave_id_t* const global_eid);

  sgx_status_t status;

  sgx_enclave_id_t* const global_eid;

 public:
  SGXORAMService() = delete;

  SGXORAMService(sgx_enclave_id_t* const global_eid) : global_eid(global_eid) {}

  virtual ~SGXORAMService() override = default;

  grpc::Status init_enclave(grpc::ServerContext* server_context,
                            const oram::InitRequest* init_request,
                            oram::InitReply* init_reply) override;

  grpc::Status generate_session_key(grpc::ServerContext* server_context,
                                    const oram::InitRequest* init_request,
                                    oram::InitReply* init_reply) override;

  grpc::Status read_block(grpc::ServerContext* server_context,
                          const oram::ReadRequest* read_request,
                          oram::ReadReply* read_reply) override;

  grpc::Status write_block(grpc::ServerContext* server_context,
                           const oram::WriteRequest* write_request,
                           oram::WriteReply* write_reply) override;

  grpc::Status close_connection(grpc::ServerContext* server_context,
                                const oram::CloseRequest* close_request,
                                google::protobuf::Empty* empty) override;
};

class Server final {
 private:
  std::unique_ptr<grpc::Server> server;

  std::unique_ptr<SGXORAMService> service;

 public:
  Server() = default;

  void run(const std::string& address, sgx_enclave_id_t* const global_eid);
};