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
#ifndef ORAM_CRYPTO_H
#define ORAM_CRYPTO_H

#include <string>
#include <memory>
#include <utility>

#include <sodium.h>

#include "oram_defs.h"

#define ORAM_CRYPTO_KEY_SIZE crypto_aead_aes256gcm_KEYBYTES
#define ORAM_CRYPTO_RANDOM_SIZE crypto_aead_aes256gcm_NPUBBYTES

#define ull unsigned long long

namespace oram_crypto {
class Cryptor {
  // The symmetric keys are valid only after key negotiation.
  uint8_t session_key_rx_[ORAM_CRYPTO_KEY_SIZE];
  uint8_t session_key_tx_[ORAM_CRYPTO_KEY_SIZE];
  uint8_t random_val_[ORAM_CRYPTO_RANDOM_SIZE];

  // The public key and the secret key.
  uint8_t public_key_[crypto_kx_PUBLICKEYBYTES];
  uint8_t secret_key_[crypto_kx_SECRETKEYBYTES];

  bool is_initialized = false;
  bool is_negotiated = false;

  Cryptor();

  void crypto_prelogue(void);

 public:
  static std::shared_ptr<Cryptor> get_instance(void);

  static uint32_t uniform_random(uint32_t min, uint32_t max);

  partition_oram::Status encrypt(const uint8_t* message, size_t length,
                                 uint8_t* const iv, std::string* const out);
  partition_oram::Status decrypt(const uint8_t* message, size_t length,
                                 const uint8_t* iv, std::string* const out);
  partition_oram::Status digest(const uint8_t* message, size_t length,
                                std::string* const out);
  partition_oram::Status sample_key_pair(void);
  partition_oram::Status sample_session_key(const std::string& peer_pk,
                                            bool type);

  std::pair<std::string, std::string> get_key_pair(void);
  std::pair<std::string, std::string> get_session_key_pair(void);

  virtual ~Cryptor();
};
}  // namespace oram_crypto

#endif  // ORAM_CRYPTO_H