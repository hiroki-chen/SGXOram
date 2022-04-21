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

namespace sgx_oram {
  typedef struct _oram_configuration_t oram_configuration_t;
}

sgx_status_t init_oram(sgx_oram::oram_configuration_t* oram_config);

#endif