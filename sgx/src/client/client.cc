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

#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

#include <plog/Log.h>
#include <configs.hh>
#include <client/client.hh>
#include <client/utils.hh>

static std::string read_keycert(const std::string& path) {
  std::ifstream file(path, std::ifstream::in);
  std::ostringstream oss;

  if (file.good()) {
    oss << file.rdbuf();
    file.close();
  }
  return oss.str();
}

// Initialize a secure channel based on the SSL protocol.
Client::Client(const std::string& address, const std::string& port) {
  // Read the certificate of the server.
  const std::string cacert = read_keycert(key_path + "/" + "sslcred.crt");

  // Create a default SSL ChannelCredentials object.
  grpc::SslCredentialsOptions ssl_opts;
  ssl_opts.pem_root_certs = cacert;
  std::shared_ptr<grpc::ChannelCredentials> ssl_creds =
      grpc::SslCredentials(ssl_opts);
  stub_ = oram::sgx_oram::NewStub(std::shared_ptr<grpc::Channel>(
      grpc::CreateChannel(address + ":" + port, ssl_creds)));
}

int Client::init_enclave(void) {
  LOG(plog::info) << "Trying to initializing the enclave on the server.";

  grpc::ClientContext context;
  oram::InitRequest request;
  request.set_round(0);
  oram::InitReply reply;

  grpc::Status status = stub_->init_enclave(&context, request, &reply);

  if (!status.ok()) {
    LOG(plog::fatal) << status.error_message();

    return -1;
  } else {
    LOG(plog::info) << "The server has initialized the enclave!";

    return 0;
  }
}

int Client::close_connection(void) {
  grpc::ClientContext context;
  oram::CloseRequest request;
  google::protobuf::Empty empty;
  stub_->close_connection(&context, request, &empty);

  return 0;
}

int Client::generate_session_key(void) {
  LOG(plog::info) << "Sending negotiated key to the server.";

  grpc::ClientContext context;
  oram::InitRequest request;
  request.set_round(1);
  oram::InitReply reply;

  grpc::Status status = stub_->generate_session_key(&context, request, &reply);

  if (!status.ok()) {
    LOG(plog::fatal) << status.error_message();

    return -1;
  } else {
    // Extract the secret key.
    const std::string server_pk = reply.content();
    LOG(plog::debug) << "Server's public key received! The pulic key is "
                     << hex_to_string((uint8_t*)server_pk.data(),
                                      server_pk.size());

    // Calculate the shared key and derive secret key from it.

    // Start to send client's public key.
    grpc::ClientContext ctx;
    oram::InitRequest req;
    req.set_round(2);
    req.set_content(
        std::string((char*)&public_key, sizeof(sample_ec256_public_t)));
    status = stub_->generate_session_key(&ctx, req, &reply);

    if (!status.ok()) {
      LOG(plog::fatal) << status.error_message();
      return -1;
    }

    LOG(plog::info) << "Shared key established!";
  }
  return 0;
}
