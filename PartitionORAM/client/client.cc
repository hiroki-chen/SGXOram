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
#include "client.h"

#include <spdlog/spdlog.h>
#include <spdlog/fmt/bin_to_hex.h>

#include "base/oram_utils.h"

extern std::shared_ptr<spdlog::logger> logger;

namespace partition_oram {
void Client::run(void) {
  logger->info("Client started, and the address is given as {}:{}.",
               server_address_, server_port_);

  const std::string address =
      oram_utils::string_concat(server_address_, ":", server_port_);

  // Configure the SSL connection.
  const std::string crt_file = oram_utils::read_key_crt_file(crt_path_);
  grpc::SslCredentialsOptions ssl_opts;
  ssl_opts.pem_root_certs = crt_file;
  std::shared_ptr<grpc::ChannelCredentials> ssl_creds =
      grpc::SslCredentials(ssl_opts);
  stub_ = server::NewStub(grpc::CreateChannel(address, ssl_creds));

  // Initialize the cryptor.
  cryptor_ = oram_crypto::Cryptor::get_instance();

  // Test if crypto is working.
  std::string test_str = "Hello, world!";
  std::string hash;
  cryptor_->digest((uint8_t*)test_str.data(), test_str.size(), &hash);
  logger->info("The hash of {} is {}.", test_str, spdlog::to_hex(hash));
}

int Client::start_key_exchange(void) {
  cryptor_->sample_key_pair();
  auto key_pair = std::move(cryptor_->get_key_pair());

  // Send the public key to the server.
  grpc::ClientContext context;
  KeyExchangeRequest request;
  KeyExchangeResponse response;
  request.set_public_key_client(key_pair.first);

  grpc::Status status = stub_->key_exchange(&context, request, &response);

  if (!status.ok()) {
    logger->error(status.error_message());
  }
  const std::string public_key_server = response.public_key_server();
  logger->info("The server's public key is {}.",
               spdlog::to_hex(public_key_server));

  // Sample the session key based on the server's public key.
  Status oram_status;
  if ((oram_status = cryptor_->sample_session_key(response.public_key_server(),
                                                  0)) != Status::OK) {
    logger->error("Failed to sample session key! Error: {}",
                  error_list.at(oram_status));
  }

  logger->info("The session key sampled.");
  auto session_key = std::move(cryptor_->get_session_key_pair());
  logger->info("The session key for receiving is {}.",
               spdlog::to_hex(session_key.first));
  logger->info("The session key for sending is {}.",
               spdlog::to_hex(session_key.second));
}
}  // namespace partition_oram