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
#ifndef CLIENT_HH
#define CLIENT_HH

#include <memory>

#include <spdlog/logger.h>

#include <messages.grpc.pb.h>
#include <messages.pb.h>
#include <sample_libcrypto/sample_libcrypto.h>
#include <service_provider/service_provider.h>

// Key pairs.
// For our own convenience, the keys are hard-coded in the client.
// These keys are taken from the service provider :)
static const sample_ec256_private_t secret_key = {
    {0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce, 0x3b, 0x66, 0xde,
     0x11, 0x43, 0x9c, 0x87, 0xec, 0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6,
     0xae, 0xea, 0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01}};

static const sample_ec256_public_t public_key = {
    {0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf, 0x85, 0xd0, 0x3a,
     0x62, 0x37, 0x30, 0xae, 0xad, 0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60,
     0x73, 0x1d, 0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38},
    {0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b, 0x26, 0xee, 0xb7,
     0x41, 0xe7, 0xc6, 0x14, 0xe2, 0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2,
     0x9a, 0x28, 0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06}};

extern std::shared_ptr<spdlog::logger> logger;

class Client final : public oram::sgx_oram::Service {
 private:
  std::unique_ptr<oram::sgx_oram::Stub> stub_;

  // The secrey key.
  sample_ec_key_128bit_t secret_key_session;

  // Is initialized
  bool is_initialized;

  std::string encrypt(const std::string& plaintext);

  std::string decrypt(const std::string& ciphertext);
  

 public:
  Client(const std::string& address, const std::string& port);

  int init_enclave(void);

  int close_connection(void);

  int generate_session_key(void);

  int init_oram(void);

  int read_block(uint32_t address);

  int test_oram_cache(void);

  int test_oram(void);
};

#endif