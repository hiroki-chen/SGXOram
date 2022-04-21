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
#include <string.h>
#include <stdexcept>

#include <sgx_tcrypto.h>
#include <sgx_trts.h>

#include <enclave/enclave_crypto_manager.hh>
#include <enclave/enclave_utils.hh>
#include <enclave/enclave_t.h>

EnclaveCryptoManager::EnclaveCryptoManager() {
  memset(shared_secret_key, 0, SGX_AESGCM_KEY_SIZE);
  is_initialized = false;
}

std::string EnclaveCryptoManager::enclave_sha_256(const std::string& message) {
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(message.data());
  sgx_sha256_hash_t ans = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_sha256_msg(bytes, message.size(), &ans);

  // Cast back to the std::string.
  return hex_to_string(ans, SGX_SHA256_HASH_SIZE);
}

std::string EnclaveCryptoManager::enclave_aes_128_gcm_encrypt(
    const std::string& message) {
  if (!is_initialized) {
    printf("[enclave] Crypto manager is not initialized.\n");
    return "";
  }

  const uint8_t* plaintext = reinterpret_cast<const uint8_t*>(message.data());

  // Prepare a buffer for receiving the ciphertext.
  size_t cipher_len = message.size() + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;
  uint8_t* ciphertext = (uint8_t*)(malloc(cipher_len));
  // Generate the IV (nonce). This is directly appended into the raw message and
  // is easy to be discarded.
  sgx_read_rand(ciphertext + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);

  // Encrypt the data and then MAC it.
  sgx_status_t ret = sgx_rijndael128GCM_encrypt(
      &shared_secret_key, plaintext, message.size(),
      ciphertext + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
      ciphertext + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE, NULL, 0,
      (sgx_aes_gcm_128bit_tag_t*)(ciphertext));

  if (ret != SGX_SUCCESS) {
    ocall_exception_handler("Cannot encrypt the data");
  }

  // We could extract the meaningful fields out of the ciphertext buffer and
  // then reconstruct a string from them. The buffer's layout is:
  //   <GCM_TAG> || <NONCE> || <CIPHERTEXT>
  return std::string((char*)(ciphertext), cipher_len);
}

std::string EnclaveCryptoManager::enclave_aes_128_gcm_decrypt(
    const std::string& message) {
  if (!is_initialized) {
    printf("[enclave] Crypto manager is not initialized.\n");
    return "";
  }

  const uint8_t* ciphertext = reinterpret_cast<const uint8_t*>(message.data());

  // Prepare the buffer for storing the plaintext.
  size_t message_len =
      message.size() - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE;
  uint8_t* plaintext = (uint8_t*)(malloc(message_len));

  sgx_status_t ret = sgx_rijndael128GCM_decrypt(
      &shared_secret_key, ciphertext + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
      message_len, plaintext, ciphertext + SGX_AESGCM_MAC_SIZE,
      SGX_AESGCM_IV_SIZE, NULL, 0, (const sgx_aes_gcm_128bit_tag_t*)ciphertext);

  // Check the integrity of the message.
  // If sanity check fails, we throw an exception, indicating that the message
  // is corrupted, and the client should end the connection.
  if (ret != SGX_SUCCESS) {
    ocall_exception_handler("AES integrity check failed.");
  }

  return std::string((char*)plaintext, message_len);
}

void EnclaveCryptoManager::set_shared_key(
    const sgx_ec_key_128bit_t* shared_key) {
  // Copy the shared key into the enclave.
  memset(&shared_secret_key, 0, sizeof(sgx_ec_key_128bit_t));
  memcpy(&shared_secret_key, shared_key, sizeof(sgx_ec_key_128bit_t));
  // Only if the shared key is set, we can set the flag to true.
  is_initialized = true;
}