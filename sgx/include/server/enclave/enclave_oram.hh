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

#ifndef ENCLAVE_ORAM_HH
#define ENCLAVE_ORAM_HH

#include <sgx_urts.h>

sgx_status_t init_oram(uint32_t* permutation, size_t permutation_size);

void encrypt_slot_and_store(uint8_t* const slot, size_t slot_size,
                            uint32_t level, uint32_t offset,
                            bool cache_enabled = true);

uint32_t calculate_offset(uint32_t block_id, uint32_t level_cur);

void get_slot_and_decrypt(uint32_t level, uint32_t offset, uint8_t* slot_buffer,
                          size_t slot_size, bool cache_enabled = true);

#endif  // ENCLAVE_ORAM_HH