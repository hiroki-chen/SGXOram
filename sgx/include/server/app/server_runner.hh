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

struct OramConfiguration {
  uint32_t way;
  uint32_t number;
  uint32_t bucket_size;
  uint32_t type;
  uint32_t constant;
  uint32_t round;
  uint32_t level;
  uint32_t oram_type;
};

class SGXORAMService final : public oram::sgx_oram::Service {
 private:
  // This will be the storage for all the slots on the server.
  // The storage is organized as a unordered map where the key is the
  // fingerprint.
  std::unordered_map<std::string, std::string> storage;

  // FIXME: A non-access-pattern-hiding position map.
  std::unordered_map<std::string, std::string> position_map;

  sgx_status_t init_enclave(sgx_enclave_id_t* const global_eid);

  sgx_status_t status;

  sgx_enclave_id_t* const global_eid;

  sgx_ra_context_t context;

  OramConfiguration oram_config;

  friend class Server;

  // Message dispatchers.
  sgx_status_t message_handler_round_one(const std::string& message,
                                         oram::InitReply* reply);

  sgx_status_t message_handler_round_two(const std::string& message,
                                         oram::InitReply* reply);

  sgx_status_t message_handler_round_three(const std::string& message,
                                           oram::InitReply* reply);

  bool check_verification_message(const std::string& message);

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

  grpc::Status init_oram(grpc::ServerContext* server_context,
                         const oram::OramInitRequest* oram_init_request,
                         google::protobuf::Empty* empty) override;

  // ===================================================== //
  // Functions for remote attestation.
  grpc::Status remote_attestation_begin(
      grpc::ServerContext* server_context,
      const oram::InitialMessage* initial_message,
      oram::Message0* reply) override;

  grpc::Status remote_attestation_msg0(grpc::ServerContext* server_context,
                                       const oram::Message0* message0,
                                       oram::Message1* reply) override;

  grpc::Status remote_attestation_msg2(grpc::ServerContext* server_context,
                                       const oram::Message2* message2,
                                       oram::Message3* reply) override;

  grpc::Status remote_attestation_final(
      grpc::ServerContext* server_context,
      const oram::AttestationMessage* message,
      google::protobuf::Empty* empty) override;

  // ===================================================== //

  // grpc::Status remote_attestation(
  //     grpc::ServerContext* server_context,
  //     const oram::InitRequest* remote_attestation_request,
  //     oram::InitReply* remote_attestation_reply) override;

  sgx_status_t generate_epid(uint32_t* extended_epid_group_id);
};

class Server final {
 private:
  std::unique_ptr<grpc::Server> server;

  std::unique_ptr<SGXORAMService> service;

 public:
  Server() = default;

  void run(const std::string& address, sgx_enclave_id_t* const global_eid);

  void store_compressed_slot(const char* const fingerprint,
                             const std::string& compressed_slot);

  std::string get_compressed_slot(const char* const fingerprint) {
    return service->storage[fingerprint];
  }

  bool is_in_storage(const char* const fingerprint) {
    return service->storage.count(fingerprint) > 0;
  }

  std::string get_position(const std::string& address) {
    return service->position_map[address];
  }

  void store_position(const std::string& address, const std::string& position) {
    service->position_map[address] = position;
  }
};