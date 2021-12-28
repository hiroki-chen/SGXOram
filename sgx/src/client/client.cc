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
#include <client.hh>

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
  LOG(plog::info) << "The client is initializaing...";

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