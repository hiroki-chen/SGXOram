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

#define DEFAULT_RANDOM_LENGTH 16

#include <string>
#include <memory>

#include <sgx_tcrypto.h>
#include <sgx_ecp_types.h>

#include <basic_models.hh>

/**
 * @brief A class that manages all the interfaces and keys for cryptographic
 *        ends. E.g., sha-256, aes-256, etc.
 *
 */
class EnclaveCryptoManager final {
 private:
  // This key is derived after Diffie-Hellman Key Exchange procedure.
  sgx_aes_gcm_128bit_key_t shared_secret_key;

  // This key is randomly generated as secret key.
  sgx_ec256_private_t secret_key;

  sgx_ec256_public_t public_key;

  // ECC handle.
  sgx_ecc_state_handle_t state_handle;

  // Is fully initialized
  bool is_initialized;

  bool is_cache_enabled;

  uint8_t random_number[DEFAULT_RANDOM_LENGTH];

  // The configuration of the ORAM.
  sgx_oram::oram_configuration_t* oram_config;

  EnclaveCryptoManager();

 public:
  static std::shared_ptr<EnclaveCryptoManager> get_instance(void);

  sgx_ecc_state_handle_t* get_state_handle(void) { return &state_handle; }

  sgx_ec256_private_t* get_secret_key(void) { return &secret_key; }

  sgx_ec256_public_t* get_public_key(void) { return &public_key; }

  sgx_oram::oram_configuration_t* get_oram_config(void) { return oram_config; }

  bool cache_enabled(void) { return is_cache_enabled; }

  /**
   * @brief Set the cache enabled object
   *
   * @param enabled
   */
  void set_cache_enabled(bool enabled) { is_cache_enabled = enabled; }

  /**
   * @brief Set the shared key object
   *
   * @param shared_key
   */
  void set_shared_key(const sgx_ec_key_128bit_t* shared_key);

  /**
   * @brief Set the oram config object
   *
   * @param config
   * @param config_size
   */
  void set_oram_config(uint8_t* config, size_t config_size);

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

#endif  // ENCLAVE_CRYPTO_MANAGER_HH