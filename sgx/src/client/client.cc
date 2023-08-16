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
#include <client/client.hh>

#include <chrono>
#include <array>
#include <fstream>
#include <sstream>

#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>
#include <gflags/gflags.h>
#include <sodium.h>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>

#include <configs.hh>
#include <client/utils.hh>

// Declare the external variables captured in the arguments.
DECLARE_uint32(way);
DECLARE_uint32(number);
DECLARE_uint32(bucket_size);
DECLARE_uint32(type);
DECLARE_double(constant);
DECLARE_uint32(round);
DECLARE_uint32(oram_type);
DECLARE_uint32(cache_type);
DECLARE_uint32(access_num);

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
  is_initialized = false;
  // Read the certificate of the server.
  const std::string cacert = read_keycert(key_path + "/" + "sslcred.crt");

  // Create a default SSL ChannelCredentials object.
  grpc::SslCredentialsOptions ssl_opts;
  ssl_opts.pem_root_certs = cacert;
  std::shared_ptr<grpc::ChannelCredentials> ssl_creds =
      grpc::SslCredentials(ssl_opts);
  std::shared_ptr<grpc::Channel> channel = std::shared_ptr<grpc::Channel>(
      grpc::CreateChannel(address + ":" + port, ssl_creds));

  // Wait for the server to start.
  grpc_connectivity_state state;
  do {
    state = channel->GetState(true);
  } while (state == grpc_connectivity_state::GRPC_CHANNEL_IDLE ||
           state == grpc_connectivity_state::GRPC_CHANNEL_CONNECTING);

  stub_ = oram::sgx_oram::NewStub(channel);
}

int Client::init_enclave(void) {
  logger->info("Trying to initializing the enclave on the server.");

  grpc::ClientContext context;
  oram::InitRequest request;
  request.set_round(0);
  oram::InitReply reply;

  grpc::Status status = stub_->init_enclave(&context, request, &reply);

  if (!status.ok()) {
    logger->error(status.error_message());

    return -1;
  } else {
    logger->info("The server has initialized the enclave!");

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

int Client::init_oram(void) {
  grpc::ClientContext context;
  oram::OramInitRequest request;

  const std::string encrypted_verification_message = encrypt("Hello");
  // Set the parameters of the ORAM in the request.
  request.set_way(FLAGS_way);
  request.set_number(FLAGS_number);
  request.set_bucket_size(FLAGS_bucket_size);
  request.set_type(FLAGS_type);
  request.set_constant(FLAGS_constant);
  request.set_round(FLAGS_round);
  request.set_oram_type(FLAGS_oram_type);
  request.set_verification(encrypted_verification_message);

  // Set the permutation of the ORAM in the request.
  uint32_t* permutation = new uint32_t[FLAGS_number];
  for (uint32_t i = 0; i < FLAGS_number; i++) {
    permutation[i] = i;
  }
  // Shuffle it.
  fisher_yates_shuffle(permutation, FLAGS_number);
  for (uint32_t i = 0; i < FLAGS_number; i++) {
    request.add_permutation(permutation[i]);
  }

  // Prin the encrypted verification message.
  std::array<uint8_t, 1024> buffer;
  memcpy(buffer.data(), encrypted_verification_message.data(),
         encrypted_verification_message.size());
  logger->debug("The encrypted verification message is: {}",
                spdlog::to_hex(buffer));
  // Print the LOG.
  logger->info("Sending parameters of the ORAM to the server!");

  google::protobuf::Empty empty;
  stub_->init_oram(&context, request, &empty);

  return 0;
}

int Client::generate_session_key(void) {
  logger->info("Sending negotiated key to the server.");

  grpc::ClientContext context;
  oram::InitRequest request;
  request.set_round(1);
  oram::InitReply reply;

  grpc::Status status = stub_->generate_session_key(&context, request, &reply);

  if (!status.ok()) {
    logger->error(status.error_message());

    return -1;
  } else {
    // Extract the secret key.
    const std::string server_pk = reply.content();
    std::array<uint8_t, 32> server_pk_array;
    memcpy(server_pk_array.data(), server_pk.c_str(), server_pk.size());
    logger->info("Server's public key received! The pulic key is {}.",
                 spdlog::to_hex(server_pk_array));

    // Calculate the shared key.
    sample_ecc_state_handle_t state_handle;
    sample_ecc256_open_context(&state_handle);
    sample_ec256_dh_shared_t shared_key;
    sample_ecc256_compute_shared_dhkey(
        (sample_ec256_private_t*)&secret_key,
        (sample_ec256_public_t*)(server_pk.data()),
        (sample_ec256_dh_shared_t*)&shared_key, state_handle);

    std::array<uint8_t, 32> shared_key_array;
    memcpy(shared_key_array.data(), &shared_key, 32);
    logger->info("Shared key established! The key is {}.",
                 spdlog::to_hex(shared_key_array));

    // Start to send client's public key.
    grpc::ClientContext ctx;
    oram::InitRequest req;
    req.set_round(2);
    req.set_content(
        std::string((char*)&public_key, sizeof(sample_ec256_public_t)));
    status = stub_->generate_session_key(&ctx, req, &reply);

    if (!status.ok()) {
      logger->error(status.error_message());
      return -1;
    }

    // Derive a secret key from the shared key.
    sample_ec_key_128bit_t smk_key;
    if (!derive_key((sample_ec_dh_shared_t*)&shared_key, 0u, &smk_key,
                    &secret_key_session)) {
      logger->error("Cannot derive secret key!");
    }

    std::array<char, sizeof(sample_ec_key_128bit_t)> secret_key_session_buf;
    memcpy(secret_key_session_buf.data(), &secret_key_session,
           sizeof(sample_ec_key_128bit_t));
    logger->info("The session key is established! The key is {}",
                 spdlog::to_hex(secret_key_session_buf));
    is_initialized = true;
    sample_ecc256_close_context(state_handle);
  }

  return 0;
}

std::string Client::encrypt(const std::string& plaintext) {
  if (!is_initialized) {
    logger->info("The client is not initialized!");
    return "";
  }

  const uint8_t* plaintext_ptr = (uint8_t*)plaintext.data();
  size_t ciphertext_length =
      plaintext.size() + SAMPLE_AESGCM_MAC_SIZE + SAMPLE_AESGCM_IV_SIZE;
  uint8_t* ciphertext = (uint8_t*)malloc(ciphertext_length);
  randombytes(ciphertext + SAMPLE_AESGCM_MAC_SIZE, SAMPLE_AESGCM_IV_SIZE);

  // Encrypt the data and then MAC it.
  sample_status_t ret = sample_rijndael128GCM_encrypt(
      (sample_aes_gcm_128bit_key_t*)&secret_key_session, plaintext_ptr,
      plaintext.size(),
      ciphertext + SAMPLE_AESGCM_MAC_SIZE + SAMPLE_AESGCM_IV_SIZE,
      ciphertext + SAMPLE_AESGCM_MAC_SIZE, SAMPLE_AESGCM_IV_SIZE, NULL, 0,
      (sample_aes_gcm_128bit_tag_t*)ciphertext);

  if (ret != SAMPLE_SUCCESS) {
    logger->error("Cannot encrypt the data!");
    return "";
  }

  return std::string((char*)ciphertext, ciphertext_length);
}

std::string Client::decrypt(const std::string& ciphertext) {
  if (!is_initialized) {
    logger->info("The client is not initialized!");
    return "";
  }

  const uint8_t* ciphertext_ptr = (uint8_t*)ciphertext.c_str();
  size_t plaintext_length =
      ciphertext.size() - SAMPLE_AESGCM_MAC_SIZE - SAMPLE_AESGCM_IV_SIZE;
  uint8_t* plaintext = (uint8_t*)malloc(plaintext_length);

  // Decrypt the data and then verify the MAC.
  sample_status_t ret = sample_rijndael128GCM_encrypt(
      (sample_aes_gcm_128bit_key_t*)&secret_key_session,
      ciphertext_ptr + SAMPLE_AESGCM_MAC_SIZE + SAMPLE_AESGCM_IV_SIZE,
      plaintext_length, plaintext, ciphertext_ptr + SAMPLE_AESGCM_MAC_SIZE,
      SAMPLE_AESGCM_IV_SIZE, NULL, 0,
      (sample_aes_gcm_128bit_tag_t*)ciphertext_ptr);

  if (ret != SAMPLE_SUCCESS) {
    logger->error("Cannot decrypt the data!");
    return "";
  }

  const std::string ans = std::string((char*)plaintext, plaintext_length);
  safe_free(plaintext);
  return ans;
}

int Client::read_block(uint32_t address) {
  logger->info("Reading block {}.", address);
  grpc::ClientContext context;
  oram::ReadRequest request;
  request.set_address(address);
  oram::ReadReply reply;

  grpc::Status status = stub_->read_block(&context, request, &reply);

  auto begin = std::chrono::high_resolution_clock::now();
  if (!status.ok() || reply.success() != true) {
    logger->error("Cannot read block {}.", address);
    return -1;
  }

  // Decrypt the data.
  std::string ciphertext = reply.data();
  std::string plaintext = decrypt(ciphertext);
  logger->info("The content of the block is {}", (uint8_t)plaintext.data()[0]);
  uint8_t* buf = (uint8_t*)(malloc(reply.data().size()));
  memcpy(buf, reply.data().data(), reply.data().size());
  free(buf);
  
  auto end = std::chrono::high_resolution_clock::now();

  logger->info(
      "Client-side computation time is {} us.",
      std::chrono::duration_cast<std::chrono::microseconds>(end - begin)
          .count());

  return 0;
}

int Client::test_oram_cache(void) {
  logger->info("Begin testing the cache!");
  grpc::ClientContext context;
  google::protobuf::Empty request;
  google::protobuf::Empty empty_response;

  grpc::Status status =
      stub_->test_oram_cache(&context, request, &empty_response);

  if (!status.ok()) {
    logger->error(status.error_message());
    return -1;
  } else {
    logger->info("The cache functions well!");
    return 0;
  }
}

int Client::test_oram(void) {
  logger->info("Begin testing the ORAM!");

  // End-to-end time.
  auto begin = std::chrono::high_resolution_clock::now();
  for (size_t i = 0; i < FLAGS_access_num; i++) {
    if (read_block(i) != 0) {
      return -1;
    }
  }
  auto end = std::chrono::high_resolution_clock::now();
  auto duration =
      std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
  logger->info("The end-to-end time for reading {} blocks is {} us.",
               FLAGS_access_num, duration.count());

  return 0;
}

int Client::print_storage_information(void) {
  grpc::ClientContext context;
  google::protobuf::Empty empty;

  stub_->print_storage_information(&context, empty, &empty);

  return 0;
}

int Client::destroy_enclave(void) {
  grpc::ClientContext context;
  google::protobuf::Empty empty;

  return stub_->destroy_enclave(&context, empty, &empty).ok() ? 0 : -1;
}