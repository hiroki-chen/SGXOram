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
#ifndef ENCLAVE_INIT_HH
#define ENCLAVE_INIT_HH

#include <sgx_urts.h>
#include <string>

#include <enclave/enclave_crypto_manager.hh>

// isv defined key derivation function id
#define ISV_KDF_ID 2

typedef enum _derive_key_type_t {
  DERIVE_KEY_SMK_SK = 0,
  DERIVE_KEY_MK_VK,
} derive_key_type_t;

const char ID_U[] = "SGXRAENCLAVE";
const char ID_V[] = "SGXRASERVER";

// This is the public EC key of the SP. The corresponding private EC key is
// used by the SP to sign data used in the remote attestation SIGMA protocol
// to sign channel binding data in MSG2. A successful verification of the
// signature confirms the identity of the SP to the ISV app in remote
// attestation secure channel binding. The public EC key should be hardcoded in
// the enclave or delivered in a trustworthy manner. The use of a spoofed public
// EC key in the remote attestation with secure channel binding session may lead
// to a security compromise. Every different SP the enclave communicates to
// must have a unique SP public key. Delivery of the SP public key is
// determined by the ISV. The TKE SIGMA protocol expects an Elliptical Curve key
// based on NIST P-256
static const sgx_ec256_public_t g_sp_pub_key = {
    {0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf, 0x85, 0xd0, 0x3a,
     0x62, 0x37, 0x30, 0xae, 0xad, 0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60,
     0x73, 0x1d, 0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38},
    {0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b, 0x26, 0xee, 0xb7,
     0x41, 0xe7, 0xc6, 0x14, 0xe2, 0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2,
     0x9a, 0x28, 0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06}};

typedef struct _hash_buffer_t {
  uint8_t counter[4];
  sgx_ec256_dh_shared_t shared_secret;
  uint8_t algorithm_id[4];
} hash_buffer_t;

// Derive two keys from shared key and key id.
bool derive_key(const sgx_ec256_dh_shared_t* p_shared_key, uint8_t key_id,
                sgx_ec_key_128bit_t* first_derived_key,
                sgx_ec_key_128bit_t* second_derived_key);

sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
                            uint16_t kdf_id, sgx_ec_key_128bit_t* smk_key,
                            sgx_ec_key_128bit_t* sk_key,
                            sgx_ec_key_128bit_t* mk_key,
                            sgx_ec_key_128bit_t* vk_key);

#endif // ENCLAVE_INIT_HH