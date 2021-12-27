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
#ifndef ENCLAVE_CRYPTO_MANAGER_HH
#define ENCLAVE_CRYPTO_MANAGER_HH

#include <sgx_tcrypto.h>

#include <string>

/**
 * @brief A class that manages all the interfaces and keys for cryptographic
 *        ends. E.g., sha-256, aes-256, etc.
 *
 */
class EnclaveCryptoManager final {
 private:
  sgx_aes_gcm_128bit_key_t aes_key;

 public:
  /**
   * @brief Construct a new Enclave Crypto Manager object
   *
   */
  EnclaveCryptoManager();

  /**
   * @brief Secure Hash Algorithm with 256 bit-length.
   *
   * @param message
   * @return std::string
   */
  std::string enclave_sha_256(const std::string& message);

  /**
   * @brief Encrypt the message using AES (rijndael) block cipher in Galois /
   *        Counter mode.
   *
   * @note  A very interesting aspect of AES-GCM mode is that it does not
   *        require any padding, which means the output length is exactly the
   *        same as the input length. GCM uses CTR internally. It encrypts a
   *        counter value for each block, but it only uses as many bits as
   *        required from the last block.
   *
   * @param message
   * @return std::string
   */
  std::string enclave_aes_128_gcm_encrypt(const std::string& message);

  std::string enclave_aes_128_gcm_decrypt(const std::string& message);
};

static const std::string candidate =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#endif