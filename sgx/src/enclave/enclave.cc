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
  const std::string cipher = crypto_manager->enclave_aes_128_gcm_encrypt("some long message!!!!fjdsiajfiasjiand okay");
  sprintf(cipher, true);
  sprintf(crypto_manager->enclave_aes_128_gcm_decrypt(cipher));
  return 0;
}