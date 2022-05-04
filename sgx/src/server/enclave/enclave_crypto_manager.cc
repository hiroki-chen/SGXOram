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
#include <enclave/enclave_crypto_manager.hh>

#include <string.h>

#include <stdexcept>

#include <sgx_tcrypto.h>
#include <sgx_trts.h>

#include <enclave/enclave_utils.hh>
#include <enclave/enclave_t.h>

EnclaveCryptoManager::EnclaveCryptoManager() {
  memset(shared_secret_key, 0, SGX_AESGCM_KEY_SIZE);
  is_initialized = false;

  // Generate the random number.
  // A freshly newly generated random number
  // to prevent that the adversary can observe the
  // hash fingerprint of each slot.
  sgx_status_t ret = sgx_read_rand(random_number, DEFAULT_RANDOM_LENGTH);
  check_sgx_status(ret, "enclave_crypto_mananger init()");
}

// Do not use std::make_shared here, because the constructor of
// EnclaveCryptoManager is private, and we cannot call it by
// std::make_shared.
std::shared_ptr<EnclaveCryptoManager> EnclaveCryptoManager::get_instance() {
  static std::shared_ptr<EnclaveCryptoManager> instance(
      new EnclaveCryptoManager());
  return instance;
}

// One should note that the hash value should be immediately represented as a
// hexical std::string since the inferface of OCalls only receive const char* as
// input. So if the hash value is simply a byte array, some bytes will be
// discarded if the application treats it as a const char*.
//
// To see why, please refer to SGX's edl definitions for const char* literal
// strings. The length is implicitly calculated from the first null character to
// the end of the string, which is '\0'.
std::string EnclaveCryptoManager::enclave_sha_256(const std::string& message) {
  // Determine the length of the input message with a random numebr.
  const size_t message_length = message.size() + DEFAULT_RANDOM_LENGTH;
  // Allocate the memory for the message which is used
  // to store the message and the random number. Note
  // that the random number is appended to the message.
  uint8_t* buf = (uint8_t*)malloc(message_length);
  memcpy(buf, message.data(), message.size());
  memcpy(buf + message.size(), random_number, DEFAULT_RANDOM_LENGTH);
  std::string ans;
  ans.resize(SGX_SHA256_HASH_SIZE);

  sgx_status_t status =
      sgx_sha256_msg(buf, message_length, (sgx_sha256_hash_t*)ans.data());

  safe_free(buf);
  check_sgx_status(status, "enclave_sha_256()");

  return to_hex((uint8_t*)ans.c_str(), SGX_SHA256_HASH_SIZE);
}

std::string EnclaveCryptoManager::enclave_aes_128_gcm_encrypt(
    const std::string& message) {
  if (!is_initialized) {
    ENCLAVE_LOG("[enclave] Crypto manager is not initialized.\n");
    return "";
  }

  sgx_status_t status = SGX_ERROR_UNEXPECTED;

  const uint8_t* plaintext = reinterpret_cast<const uint8_t*>(message.data());

  // Prepare a buffer for receiving the ciphertext.
  size_t cipher_len = message.size() + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;
  std::string ciphertext(cipher_len, 0);
  // Generate the IV (nonce). This is directly appended into the raw message and
  // is easy to be discarded.
  status = sgx_read_rand((uint8_t*)ciphertext.data() + SGX_AESGCM_MAC_SIZE,
                         SGX_AESGCM_IV_SIZE);
  check_sgx_status(status, "sgx_read_rand()");

  // Encrypt the data and then MAC it.
  status = sgx_rijndael128GCM_encrypt(
      &shared_secret_key, plaintext, message.size(),
      (uint8_t*)ciphertext.data() + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
      (uint8_t*)ciphertext.data() + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
      NULL, 0, (sgx_aes_gcm_128bit_tag_t*)(ciphertext.data()));

  check_sgx_status(status, "enclave_aes_128_gcm_encrypt()");

  // Cast back to the std::string.
  // We could extract the meaningful fields out of the ciphertext buffer and
  // then reconstruct a string from them. The buffer's layout is:
  //   <GCM_TAG> || <NONCE> || <CIPHERTEXT>
  return ciphertext;
}

std::string EnclaveCryptoManager::enclave_aes_128_gcm_decrypt(
    const std::string& message) {
  if (!is_initialized) {
    ENCLAVE_LOG("[enclave] Crypto manager is not initialized.\n");
    return "";
  }

  const uint8_t* ciphertext = reinterpret_cast<const uint8_t*>(message.data());

  // Prepare the buffer for storing the plaintext.
  size_t message_len =
      message.size() - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE;
  std::string plaintext;
  plaintext.resize(message_len);

  sgx_status_t ret = sgx_rijndael128GCM_decrypt(
      &shared_secret_key, ciphertext + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
      message_len, (uint8_t*)plaintext.data(), ciphertext + SGX_AESGCM_MAC_SIZE,
      SGX_AESGCM_IV_SIZE, NULL, 0, (const sgx_aes_gcm_128bit_tag_t*)ciphertext);

  // Check the integrity of the message.
  // If sanity check fails, we throw an exception, indicating that the message
  // is corrupted, and the client should end the connection.
  check_sgx_status(ret, "enclave_aes_128_gcm_decrypt()");

  // Cast back to the std::string.
  return plaintext;
}

void EnclaveCryptoManager::set_shared_key(
    const sgx_ec_key_128bit_t* shared_key) {
  // Copy the shared key into the enclave.
  memset(&shared_secret_key, 0, sizeof(sgx_ec_key_128bit_t));
  memcpy(&shared_secret_key, shared_key, sizeof(sgx_ec_key_128bit_t));
  // Only if the shared key is set, we can set the flag to true.
  is_initialized = true;
}

void EnclaveCryptoManager::set_oram_config(uint8_t* buffer, size_t size) {
  ENCLAVE_LOG("[enclave] Setting oram config...");
  // Copy the oram config into the enclave.
  oram_config = (sgx_oram::oram_configuration_t*)malloc(size);
  memset(oram_config, 0, size);
  memcpy(oram_config, buffer, size);

  // Check the correctness of the oram config.
  if (oram_config->oram_type != 1) {
    ocall_panic_and_flush("Expected oram type: SO2");
  }
}