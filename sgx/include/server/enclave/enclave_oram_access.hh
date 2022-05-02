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
#ifndef ENCLAVE_ORAM_ACCESS_HH
#define ENCLAVE_ORAM_ACCESS_HH

#include <cstddef>

#include <basic_models.hh>

void sub_access(sgx_oram::oram_operation_t op_type, bool condition_s1,
                bool condition_s2, uint8_t* const s1, size_t s1_size,
                uint8_t* const s2, size_t s2_size, uint8_t* const data_star,
                uint32_t level, sgx_oram::oram_position_t* const position);

void sub_access_s1(bool condition, uint8_t* const s1, const size_t slot_size,
                   uint8_t* const block_slot1_target,
                   uint8_t* const block_slot1_evict, uint32_t* const counter,
                   sgx_oram::oram_position_t* const position);

void sub_access_s2(sgx_oram::oram_operation_t op_type, bool condition,
                   uint8_t* const s2, const size_t slot_size,
                   sgx_oram::oram_block_t* const block_slot1_target,
                   uint8_t* const data_star, uint32_t* const counter,
                   uint32_t pos, sgx_oram::oram_position_t* const position);

void sub_access_s1_epilogue(bool condition, uint32_t dummy_number,
                            sgx_oram::oram_block_t* block_slot1_target,
                            sgx_oram::oram_block_t* block_slot1_evict,
                            uint32_t* const counter, uint32_t* const position);

void sub_evict_s2(uint8_t* const s2, size_t slot_size,
                  sgx_oram::oram_block_t* const block_evict,
                  uint32_t current_level, uint32_t* const counter);

void sub_evict_s3(uint8_t* const s3, size_t slot_size,
                  sgx_oram::oram_block_t* const block_evict, uint32_t position);

void sub_evict_s2_epilogue(uint32_t dummy_number, uint32_t begin, uint32_t end,
                           sgx_oram::oram_block_t* block_evict,
                           uint32_t* const counter, uint32_t* const position,
                           uint32_t* const bid);

void data_access(sgx_oram::oram_operation_t op_type, uint32_t current_level,
                 uint8_t* const data, size_t data_size, bool condition_s1,
                 bool condition_s2, sgx_oram::oram_position_t* const position);

void sub_evict(uint8_t* const s2, uint32_t current_level,
               sgx_oram::oram_position_t* const position);

#endif