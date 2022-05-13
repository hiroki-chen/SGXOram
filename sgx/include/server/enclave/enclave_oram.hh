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
#include <string>

#include <sgx_urts.h>

#include <basic_models.hh>

sgx_status_t init_oram(uint32_t* permutation, size_t permutation_size);

void encrypt_slot_and_store(const uint8_t* const slot, size_t slot_size,
                            uint32_t level, uint32_t offset);

void encrypt_position_and_store(
    const sgx_oram::oram_position_t* const position);

void encrypt_header_and_store(const sgx_oram::oram_slot_header_t* const header);

void assemble_position(uint32_t level, uint32_t bid, uint32_t address,
                       sgx_oram::oram_position_t* const position);

void get_position_and_decrypt(sgx_oram::oram_position_t* const position,
                              uint32_t block_address);

uint32_t calculate_offset(uint32_t block_id, uint32_t level_cur);

void get_slot_and_decrypt(const std::string& slot_hash, uint8_t* slot_buffer,
                          size_t slot_size);

std::string get_slot_header_and_decrypt(uint32_t level, uint32_t offset,
                                        sgx_oram::oram_slot_header_t* header);

std::string calculate_slot_fingerprint(uint32_t level, uint32_t offset);

#endif  // ENCLAVE_ORAM_HH