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
#include <enclave/enclave_init.hh>

#include <stdlib.h>
#include <string.h>

#include <stdexcept>
#include <string>

#include <sgx_tcrypto.h>
#include <sgx_tkey_exchange.h>
#include <sgx_trts.h> /* For sgx_read_random. */
#include <sgx_tseal.h>

#include <enclave/enclave_crypto_manager.hh>
#include <enclave/enclave_oram.hh>
#include <enclave/enclave_utils.hh>
#include <enclave/enclave_t.h>

// Used to store the secret passed by the SP in the sample code. The
// size is forced to be 8 bytes. Expected value is
// 0x01,0x02,0x03,0x04,0x0x5,0x0x6,0x0x7
uint8_t g_secret[8] = {0};

#ifdef SUPPLIED_KEY_DERIVATION

#pragma message("Supplied key derivation function is used.")

// Derive two keys from shared key and key id.
bool derive_key(const sgx_ec256_dh_shared_t* p_shared_key, uint8_t key_id,
                sgx_ec_key_128bit_t* first_derived_key,
                sgx_ec_key_128bit_t* second_derived_key) {
  sgx_status_t sgx_ret = SGX_SUCCESS;
  hash_buffer_t hash_buffer;
  sgx_sha_state_handle_t sha_context;
  sgx_sha256_hash_t key_material;

  memset(&hash_buffer, 0, sizeof(hash_buffer_t));
  /* counter in big endian  */
  hash_buffer.counter[3] = key_id;

  /*convert from little endian to big endian */
  for (size_t i = 0; i < sizeof(sgx_ec256_dh_shared_t); i++) {
    hash_buffer.shared_secret.s[i] =
        p_shared_key->s[sizeof(p_shared_key->s) - 1 - i];
  }

  sgx_ret = sgx_sha256_init(&sha_context);
  if (sgx_ret != SGX_SUCCESS) {
    return false;
  }
  sgx_ret = sgx_sha256_update((uint8_t*)&hash_buffer, sizeof(hash_buffer_t),
                              sha_context);
  if (sgx_ret != SGX_SUCCESS) {
    sgx_sha256_close(sha_context);
    return false;
  }
  sgx_ret = sgx_sha256_update((uint8_t*)&ID_U, sizeof(ID_U), sha_context);
  if (sgx_ret != SGX_SUCCESS) {
    sgx_sha256_close(sha_context);
    return false;
  }
  sgx_ret = sgx_sha256_update((uint8_t*)&ID_V, sizeof(ID_V), sha_context);
  if (sgx_ret != SGX_SUCCESS) {
    sgx_sha256_close(sha_context);
    return false;
  }
  sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
  if (sgx_ret != SGX_SUCCESS) {
    sgx_sha256_close(sha_context);
    return false;
  }
  sgx_ret = sgx_sha256_close(sha_context);

  assert(sizeof(sgx_ec_key_128bit_t) * 2 == sizeof(sgx_sha256_hash_t));
  memcpy(first_derived_key, &key_material, sizeof(sgx_ec_key_128bit_t));
  memcpy(second_derived_key,
         (uint8_t*)&key_material + sizeof(sgx_ec_key_128bit_t),
         sizeof(sgx_ec_key_128bit_t));

  // memset here can be optimized away by compiler, so please use memset_s on
  // windows for production code and similar functions on other OSes.
  memset(&key_material, 0, sizeof(sgx_sha256_hash_t));

  return true;
}

// isv defined key derivation function id
#define ISV_KDF_ID 2

sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
                            uint16_t kdf_id, sgx_ec_key_128bit_t* smk_key,
                            sgx_ec_key_128bit_t* sk_key,
                            sgx_ec_key_128bit_t* mk_key,
                            sgx_ec_key_128bit_t* vk_key) {
  bool derive_ret = false;

  if (NULL == shared_key) {
    return SGX_ERROR_INVALID_PARAMETER;
  }

  if (ISV_KDF_ID != kdf_id) {
    // fprintf(stderr, "\nError, key derivation id mismatch in [%s].",
    // __FUNCTION__);
    return SGX_ERROR_KDF_MISMATCH;
  }

  derive_ret = derive_key(shared_key, DERIVE_KEY_SMK_SK, smk_key, sk_key);
  if (derive_ret != true) {
    // fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
    return SGX_ERROR_UNEXPECTED;
  }

  derive_ret = derive_key(shared_key, DERIVE_KEY_MK_VK, mk_key, vk_key);
  if (derive_ret != true) {
    // fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
    return SGX_ERROR_UNEXPECTED;
  }
  return SGX_SUCCESS;
}
#else
#pragma message("Default key derivation function is used.")
#endif

// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param b_pse Indicates whether the ISV app is using the
//              platform services.
// @param p_context Pointer to the location where the returned
//                  key context is to be copied.
//
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

sgx_status_t SGXAPI enclave_init_ra(int b_pse, sgx_ra_context_t* p_context) {
  // isv enclave call to trusted key exchange library.
  sgx_status_t ret;
#ifdef SUPPLIED_KEY_DERIVATION
  ret = sgx_ra_init_ex(&g_sp_pub_key, b_pse, key_derivation, p_context);
#else
  ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
#endif
  ENCLAVE_LOG("[enclave] Initializing the remote attestation context...");
  return ret;
}

// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API

sgx_status_t SGXAPI enclave_ra_close(sgx_ra_context_t context) {
  sgx_status_t ret;
  ret = sgx_ra_close(context);
  return ret;
}

// Verify the mac sent in att_result_msg from the SP using the
// MK key. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
//
// @param context The trusted KE library key context.
// @param p_message Pointer to the message used to produce MAC
// @param message_size Size in bytes of the message.
// @param p_mac Pointer to the MAC to compare to.
// @param mac_size Size in bytes of the MAC
//
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESCMAC function.
// @return SGX_ERROR_MAC_MISMATCH - MAC compare fails.

sgx_status_t verify_att_result_mac(sgx_ra_context_t context, uint8_t* p_message,
                                   size_t message_size, uint8_t* p_mac,
                                   size_t mac_size) {
  sgx_status_t ret;
  sgx_ec_key_128bit_t mk_key;

  if (mac_size != sizeof(sgx_mac_t)) {
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }
  if (message_size > UINT32_MAX) {
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }

  do {
    uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

    ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
    if (SGX_SUCCESS != ret) {
      break;
    }
    ret = sgx_rijndael128_cmac_msg(&mk_key, p_message, (uint32_t)message_size,
                                   &mac);
    if (SGX_SUCCESS != ret) {
      break;
    }
    if (0 == consttime_memequal(p_mac, mac, sizeof(mac))) {
      ret = SGX_ERROR_MAC_MISMATCH;
      break;
    }

  } while (0);

  return ret;
}

// Generate a secret information for the SP encrypted with SK.
// Input pointers aren't checked since the trusted stubs copy
// them into EPC memory.
//
// @param context The trusted KE library key context.
// @param p_secret Message containing the secret.
// @param secret_size Size in bytes of the secret message.
// @param p_gcm_mac The pointer the the AESGCM MAC for the
//                 message.
//
// @return SGX_ERROR_INVALID_PARAMETER - secret size if
//         incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESGCM function.
// @return SGX_ERROR_UNEXPECTED - the secret doesn't match the
//         expected value.

sgx_status_t put_secret_data(sgx_ra_context_t context, uint8_t* p_secret,
                             uint32_t secret_size, uint8_t* p_gcm_mac) {
  sgx_status_t ret = SGX_SUCCESS;
  sgx_ec_key_128bit_t sk_key;

  do {
    if (secret_size != 8) {
      ret = SGX_ERROR_INVALID_PARAMETER;
      break;
    }

    ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    if (SGX_SUCCESS != ret) {
      break;
    }

    uint8_t aes_gcm_iv[12] = {0};
    ret = sgx_rijndael128GCM_decrypt(
        &sk_key, p_secret, secret_size, &g_secret[0], &aes_gcm_iv[0], 12, NULL,
        0, (const sgx_aes_gcm_128bit_tag_t*)(p_gcm_mac));

    uint32_t i;
    bool secret_match = true;
    for (i = 0; i < secret_size; i++) {
      if (g_secret[i] != i) {
        secret_match = false;
      }
    }

    if (!secret_match) {
      ret = SGX_ERROR_UNEXPECTED;
    }

    // Once the server has the shared secret, it should be sealed to
    // persistent storage for future use. This will prevents having to
    // perform remote attestation until the secret goes stale. Once the
    // enclave is created again, the secret can be unsealed.
  } while (0);
  return ret;
}

sgx_status_t verify_secret_data(sgx_ra_context_t context, uint8_t* p_secret,
                                uint32_t secret_size, uint8_t* p_gcm_mac,
                                uint32_t max_verification_length,
                                uint8_t* p_ret) {
  sgx_status_t ret = SGX_SUCCESS;
  sgx_ec_key_128bit_t sk_key;

  do {
    ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    if (SGX_SUCCESS != ret) {
      break;
    }

    uint8_t* decrypted = (uint8_t*)malloc(sizeof(uint8_t) * secret_size);
    uint8_t aes_gcm_iv[12] = {0};

    ret = sgx_rijndael128GCM_decrypt(
        &sk_key, p_secret, secret_size, decrypted, &aes_gcm_iv[0], 12, NULL, 0,
        (const sgx_aes_gcm_128bit_tag_t*)(p_gcm_mac));

    if (SGX_SUCCESS == ret) {
      if (decrypted[0] == 0) {
        if (decrypted[1] != 1) {
          ret = SGX_ERROR_INVALID_SIGNATURE;
        }
      } else {
        ret = SGX_ERROR_UNEXPECTED;
      }
    }

  } while (0);

  return ret;
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
sgx_status_t SGXAPI ecall_seal(const uint8_t* plaintext, size_t plaintext_len,
                               sgx_sealed_data_t* sealed_data,
                               size_t sealed_size) {
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
sgx_status_t SGXAPI ecall_unseal(const sgx_sealed_data_t* sealed_data,
                                 size_t sealed_size, uint8_t* plaintext,
                                 size_t plaintext_len) {
  sgx_status_t status =
      sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t*)plaintext,
                      (uint32_t*)&(plaintext_len));
  return status;
}

/**
 * @brief Start to create a context for Diffie-Hellman Key Exchange for this
 * session.
 *
 * @return sgx_status_t
 */
sgx_status_t SGXAPI ecall_begin_DHKE() {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  // Create a ecc system for this session.
  ENCLAVE_LOG("[enclave] Creating a new ECC system...\n");
  sgx_status_t status =
      sgx_ecc256_open_context(crypto_manager->get_state_handle());
  return status;
}

/**
 * @brief Sample a key pair for the connection between enclave and the client.
 *
 * @param pubkey
 * @param pubkey_size
 * @return sgx_status_t
 */
sgx_status_t SGXAPI ecall_sample_key_pair(uint8_t* pubkey, size_t pubkey_size) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  // Sample the key pairs.
  sgx_status_t status = sgx_ecc256_create_key_pair(
      crypto_manager->get_secret_key(), crypto_manager->get_public_key(),
      *crypto_manager->get_state_handle());
  // Copy the public key to the untrusted memory and let the server send the key
  // to the client.
  memcpy(pubkey, crypto_manager->get_public_key(), sizeof(sgx_ec256_public_t));

  // Print debug information.
  std::string pk = std::move(
      enclave_utils::hex_to_string((uint8_t*)(crypto_manager->get_public_key()),
                                   sizeof(sgx_ec256_public_t)));
  std::string sk = std::move(
      enclave_utils::hex_to_string((uint8_t*)(crypto_manager->get_secret_key()),
                                   sizeof(sgx_aes_gcm_128bit_key_t)));
  ENCLAVE_LOG("[enclave] Key pair sampled! PK: %s, SK: %s", pk.data(),
              sk.data());

  return status;
}

sgx_status_t SGXAPI ecall_compute_shared_key(const uint8_t* pubkey,
                                             size_t pubkey_size) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  sgx_ec256_dh_shared_t shared_key;
  sgx_ec256_public_t client_public_key;
  memcpy(&client_public_key, pubkey, sizeof(sgx_ec256_public_t));

  std::string pub = std::move(enclave_utils::hex_to_string(
      (uint8_t*)(&client_public_key), sizeof(sgx_ec256_public_t)));
  ENCLAVE_LOG("[enclave] Client public key: %s", pub.data());

  sgx_status_t status = sgx_ecc256_compute_shared_dhkey(
      crypto_manager->get_secret_key(), &client_public_key, &shared_key,
      *crypto_manager->get_state_handle());
  std::string shared = std::move(enclave_utils::hex_to_string(
      (uint8_t*)(&shared_key), sizeof(sgx_aes_gcm_128bit_key_t)));
  ENCLAVE_LOG("[enclave] Shared key computed: %s", shared.data());

  // Derive secret keys from the shared key.
  // The first key is used to MAC the message while the second key is used for
  // encryption.
  sgx_ec_key_128bit_t first_derived_key;
  sgx_ec_key_128bit_t second_derived_key;

  if (!derive_key(&shared_key, 0u, &first_derived_key, &second_derived_key)) {
    ENCLAVE_LOG("[enclave] Cannot derive the session key!");
    return SGX_ERROR_UNEXPECTED;
  }

  crypto_manager->set_shared_key(&second_derived_key);
  ENCLAVE_LOG("[enclave] The session key is established! The key is %s",
              enclave_utils::hex_to_string((uint8_t*)(&second_derived_key),
                                           sizeof(sgx_ec_key_128bit_t))
                  .data());

  return status;
}

sgx_status_t SGXAPI ecall_check_verification_message(uint8_t* message,
                                                     size_t message_size) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();

  const size_t decrypted_message_size = message_size - ORAM_CRYPTO_INFO_SIZE;
  uint8_t* const decrypted_message = (uint8_t*)malloc(decrypted_message_size);
  sgx_status_t status = crypto_manager->enclave_aes_128_gcm_decrypt(
      message, message_size, decrypted_message);
  enclave_utils::check_sgx_status(status, "enclave_aes_128_gcm_decrypt()");

  ENCLAVE_LOG("[enclave] Decrypted message size %zu, : %s", decrypted_message_size, decrypted_message);

  if (std::string(reinterpret_cast<char*>(decrypted_message),
                  decrypted_message_size)
          .compare("Hello") != 0) {
    ENCLAVE_LOG("[enclave] The verification message is not correct!");
    enclave_utils::safe_free(decrypted_message);
    return SGX_ERROR_UNEXPECTED;
  } else {
    ENCLAVE_LOG("[enclave] The verification message is correct!");
    enclave_utils::safe_free(decrypted_message);
    return SGX_SUCCESS;
  }
}

sgx_status_t ecall_should_enable_cache(int should_enable) {
  std::shared_ptr<EnclaveCryptoManager> crypto_manager =
      EnclaveCryptoManager::get_instance();
  crypto_manager->set_cache_enabled(should_enable);
  ENCLAVE_LOG("[enclave] Successfully set the cache status to %d!",
              should_enable);
  return SGX_SUCCESS;
}