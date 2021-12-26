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
#include <stdlib.h>
#include <string.h>
#include <stdexcept>

#include <sgx_tcrypto.h>
#include <sgx_trts.h> /* For sgx_read_random. */
#include <sgx_tseal.h>

#include <app/basic_models.hh>
#include <enclave/enclave_crypto_manager.hh>
#include <enclave/enclave.hh>
#include <enclave/enclave_utils.hh>
#include <enclave/enclave_t.h>

/* Hidden functions */
/**
 * @brief Since enclave only allowes for a relatively restricted library which
 * does not include std::random, we need to generate random numbers by the
 * interface provided by the Intel SGX SDK.
 *
 * @param lower
 * @param upper
 * @return uint32_t A random number drawn from a uniform distribution?
 */
static uint32_t uniform_random_helper(const uint32_t& lower,
                                      const uint32_t& upper) {
  uint32_t random_number;
  // Read a random number.
  sgx_read_rand((unsigned char*)&random_number, 4);
  random_number = random_number % (upper + 1 - lower) + lower;
  return random_number;
}

uint32_t uniform_random(uint32_t lower, uint32_t upper) {
  return uniform_random_helper(lower, upper);
}

int ecall_init_oram_controller() {
  crypto_manager = new EnclaveCryptoManager();
  // printf("%s", crypto_manager->enclave_sha256("Hello World!").data());
  const std::string cipher = crypto_manager->enclave_aes_128_gcm_encrypt(
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis eget "
      "lacus condimentum, tincidunt eros id, ultricies dui. Donec placerat "
      "nulla tristique, hendrerit dui et, congue quam. Nunc urna ex, efficitur "
      "eu elit id, commodo pharetra elit. Aliquam ac felis a tellus tempor "
      "scelerisque. Donec varius, enim quis bibendum lobortis, urna neque "
      "interdum orci, ac vulputate lorem arcu ut lacus. Suspendisse potenti. "
      "Nam sodales quis mi elementum malesuada. Lorem ipsum dolor sit amet, "
      "consectetur adipiscing elit. Donec orci lectus, commodo vel elit non, "
      "condimentum vehicula metus. Proin at nulla nisi. Vestibulum vulputate "
      "volutpat urna et aliquam. Donec condimentum odio ipsum, in pharetra sem "
      "euismod eget. Vestibulum eleifend gravida arcu, eu cursus turpis "
      "lacinia venenatis. Ut sollicitudin enim nec nisi congue feugiat. "
      "Vestibulum ante ipsum primis in faucibus orci luctus et ultrices "
      "posuere cubilia curae;");
  sprintf(cipher, true);
  sprintf(crypto_manager->enclave_aes_128_gcm_decrypt(cipher));
  return 0;
}

/**
 * @brief      Seals the plaintext given into the sgx_sealed_data_t structure
 *             given.
 *
 * @details    The plaintext can be any data. uint8_t is used to represent a
 *             byte. The sealed size can be determined by computing
 *             sizeof(sgx_sealed_data_t) + plaintext_len, since it is using
 *             AES-GCM which preserves length of plaintext. The size needs to be
 *             specified, otherwise SGX will assume the size to be just
 *             sizeof(sgx_sealed_data_t), not taking into account the sealed
 *             payload.
 *
 * @param      plaintext      The data to be sealed
 * @param[in]  plaintext_len  The plaintext length
 * @param      sealed_data    The pointer to the sealed data structure
 * @param[in]  sealed_size    The size of the sealed data structure supplied
 *
 * @return     Truthy if seal successful, falsy otherwise.
 */
sgx_status_t ecall_seal(const uint8_t* plaintext, size_t plaintext_len,
                        sgx_sealed_data_t* sealed_data, size_t sealed_size) {
  sgx_status_t status = sgx_seal_data(0, NULL, plaintext_len, plaintext,
                                      sealed_size, sealed_data);
  return status;
}

/**
 * @brief      Unseal the sealed_data given into c-string
 *
 * @details    The resulting plaintext is of type uint8_t to represent a byte.
 *             The sizes/length of pointers need to be specified, otherwise SGX
 *             will assume a count of 1 for all pointers.
 *
 * @param      sealed_data        The sealed data
 * @param[in]  sealed_size        The size of the sealed data
 * @param      plaintext          A pointer to buffer to store the plaintext
 * @param[in]  plaintext_max_len  The size of buffer prepared to store the
 *                                plaintext
 *
 * @return     Truthy if unseal successful, falsy otherwise.
 */
sgx_status_t ecall_unseal(const sgx_sealed_data_t* sealed_data,
                          size_t sealed_size, uint8_t* plaintext,
                          size_t plaintext_len) {
  sgx_status_t status =
      sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t*)plaintext,
                      (uint32_t*)&(plaintext_len));
  return status;
}