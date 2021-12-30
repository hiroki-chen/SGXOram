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
#include <fstream>
#include <sstream>

#include <configs.hh>
#include <utils.hh>
#include <enclave/enclave_u.h>
#include <server/app/server_runner.hh>
#include <plog/Log.h>

static std::string read_keycert(const std::string& path) {
  std::ifstream file(path, std::ifstream::in);
  std::ostringstream oss;

  if (file.good()) {
    oss << file.rdbuf();
    file.close();
  }
  return oss.str();
}

grpc::Status SGXORAMService::init_enclave(grpc::ServerContext* server_context,
                                          const oram::InitRequest* init_request,
                                          oram::InitReply* init_reply) {
  // First check if the round number is zero.
  const uint32_t round = init_request->round();
  if (round == 0) {
    LOG(plog::info) << "Trying to initialize the enclave with id "
                    << *global_eid;
    if (init_enclave(global_eid) != SGX_SUCCESS) {
      // A toy enclave. We only create it once.
      // If there is need to ensure that the enclave is online, please put this
      // into a loop body.
      const std::string error_message = "Enclave cannot be initialized!";
      return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
    } else {
      init_reply->set_success(true);
      // There is no key currently.
      return grpc::Status::OK;
    }
  } else {
    const std::string error_message = "Request has illed form!";
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  }
}

grpc::Status SGXORAMService::generate_session_key(
    grpc::ServerContext* server_context, const oram::InitRequest* init_request,
    oram::InitReply* init_reply) {
  const uint32_t round = init_request->round();
  LOG(plog::info) << "Begin to generate DH key pair...";

  // Start DHKE.
  if (round == 1u) {
    // Send it to the enclave.
    // Then let the enclave sample keys.
    if (ecall_begin_DHKE(*global_eid, &status) != SGX_SUCCESS) {
      const std::string error_message = "Enclave cannot create an ECC state!";
      return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
    }

    uint8_t pk[sizeof(sgx_ec256_public_t)];
    if (ecall_sample_key_pair(*global_eid, &status, pk,
                              sizeof(sgx_ec256_public_t)) != SGX_SUCCESS) {
      const std::string error_message = "Enclave cannot sample the key pair!";
      return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
    }

    // The public key is sampled. Send it to the client.
    init_reply->set_content(
        std::string((char*)&pk, sizeof(sgx_ec256_public_t)));
    return grpc::Status::OK;
  } else if (round == 2) {
    // Round = 2 denotes that the client has sent its public key to the server.
    const std::string client_pk = init_request->content();
    LOG(plog::debug) << "In server runner: "
                     << sgx_oram::hex_to_string((uint8_t*)(client_pk.data()),
                                                64);
    // Call the enclave.
    if (ecall_compute_shared_key(*global_eid, &status,
                                 (const uint8_t*)client_pk.data(),
                                 client_pk.size()) != SGX_SUCCESS) {
    }

    return grpc::Status::OK;

  } else {
    const std::string error_message = "Request has illed form!";
    return grpc::Status(grpc::FAILED_PRECONDITION, error_message);
  }
}

grpc::Status SGXORAMService::read_block(grpc::ServerContext* server_context,
                                        const oram::ReadRequest* read_request,
                                        oram::ReadReply* read_reply) {
  ;
}

grpc::Status SGXORAMService::write_block(
    grpc::ServerContext* server_context,
    const oram::WriteRequest* write_request, oram::WriteReply* write_reply) {
  ;
}

grpc::Status SGXORAMService::close_connection(
    grpc::ServerContext* server_context,
    const oram::CloseRequest* close_request, google::protobuf::Empty* empty) {
  LOG(plog::info) << "Closing connection... Goodbye!";
  exit(0);
}

void Server::run(const std::string& address,
                 sgx_enclave_id_t* const global_eid) {
  service = std::make_unique<SGXORAMService>(global_eid);
  const std::string servercert = read_keycert(key_path + "/" + "sslcred.crt");
  const std::string serverkey = read_keycert(key_path + "/" + "sslcred.key");

  grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp;
  pkcp.private_key = serverkey;
  pkcp.cert_chain = servercert;

  grpc::SslServerCredentialsOptions ssl_opts;
  ssl_opts.pem_root_certs = "";
  ssl_opts.pem_key_cert_pairs.push_back(pkcp);

  std::shared_ptr<grpc::ServerCredentials> creds;
  creds = grpc::SslServerCredentials(ssl_opts);

  grpc::ServerBuilder builder;
  builder.AddListeningPort(address, grpc::SslServerCredentials(ssl_opts));
  builder.RegisterService(service.get());

  server = (builder.BuildAndStart());
  LOG(plog::info) << "Server listening on " << address;
  server->Wait();
}

sgx_status_t SGXORAMService::init_enclave(sgx_enclave_id_t* const global_eid) {
  // Initialize the enclave by loading into the signed shared object into the
  // main memory.
  if (sgx_oram::init_enclave(global_eid) != 0) {
    LOG(plog::error) << "Cannot initialize the enclave!";
  }

  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  ecall_init_oram_controller(*global_eid, (int*)&ret);
}