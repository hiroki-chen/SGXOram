/*
 Copyright (c) 2022 Haobin Chen and Siyi Lv

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
#include <algorithm>
#include <cmath>

#include <sgx_urts.h>

#include <enclave/enclave_t.h>
#include <enclave/enclave_utils.hh>
#include <enclave/enclave_oram.hh>

static sgx_status_t init_so2_oram(sgx_oram::oram_configuration_t* oram_config,
                                  uint32_t* level_size_information) {
  printf(
      "[enclave] The ORAM controller is initializing the SGX storage tree "
      "level by level...\n");

  uint32_t sgx_size = 0;
  uint32_t cur_size = 1;

  const uint32_t way = oram_config->way;
  const uint32_t type = oram_config->type;
  const uint32_t constant = oram_config->constant;
  const uint32_t level = oram_config->level;

  for (uint32_t i = 0; i < oram_config->level; i++) {
    const uint32_t cur_slot_num = (uint32_t)std::pow(way, i);

    switch (type) {
      case 0: {
        cur_size *= (uint32_t)(std::ceil(std::min(way, i + 1) * constant));
        break;
      }
      case 1: {
        cur_size = way;
        break;
      }
      case 2: {
        cur_size = (uint32_t)(std::ceil(std::pow(way, level - i) * constant));
        break;
      }
    }

    sgx_size += cur_size * cur_slot_num;
    level_size_information[i] = cur_size;
  }

  // Print the size of the ORAM tree.
  printf("[enclave] The size of the ORAM tree is %u.\n", sgx_size);
  return SGX_SUCCESS;
}

static sgx_status_t init_so2_slots(sgx_oram::oram_configuration_t* oram_config) {
  printf("[enclave] The ORAM controller is initializing the SGX storage slots "
         "for each level...\n");
  const uint32_t level = oram_config->level;
  const uint32_t way = oram_config->way;
  const uint32_t cur_slot_num = (uint32_t)std::pow(way, level);

  for (uint32_t i = 0; i < level; i++) {
    const uint32_t cur_slot_num = (uint32_t)std::pow(way, i);
  
    for (uint32_t j = 0; j < cur_slot_num; j++) {
      sgx_oram::oram_slot_t slot;
      slot.header.level = i;
      slot.header.dummy_number;
    }
  }
}

sgx_status_t ecall_access_data(int op_type, uint8_t* data, size_t data_len) {
  return SGX_SUCCESS;
}

sgx_status_t init_oram(sgx_oram::oram_configuration_t* oram_config) {
  if (oram_config->oram_type == 1) {
    uint32_t* level_size_information =
        (uint32_t*)malloc(sizeof(uint32_t) * oram_config->level);
    sgx_status_t status = SGX_ERROR_UNEXPECTED;

    if ((status = init_so2_oram(oram_config, level_size_information)) !=
        SGX_SUCCESS) {
      printf("[enclave] Failed to initialize the ORAM tree.");
      // Safely free the allocated memory.
      safe_free(level_size_information);
      return status;
    } else if ((status = init_so2_slots(oram_config)) != SGX_SUCCESS) {
      printf("[enclave] Failed to initialize the ORAM slots.");
      safe_free(level_size_information);
      return status;
    }

  } else {
    // The ORAM type is incorrect. We report an error.
    printf("[enclave] The ORAM type is incorrect.\n");
    return SGX_ERROR_INVALID_ATTRIBUTE;
  }
}