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
#include <app/app.hh>
#include <enclave/enclave_u.h>

#include <iostream>

int init_enclave(sgx_enclave_id_t* const id)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_launch_token_t launch_token = { 0 };
    int updated = 0;

    // It is the caller's responsibility to give us the global enclave id.
    if ((ret = sgx_create_enclave(enclave_path.c_str(), 1, &launch_token, &updated, id, nullptr))
        != SGX_SUCCESS) {
        return -1;
    }

    return 0;
}

void ecall_print_something(sgx_enclave_id_t* const id)
{
    print_something(*id);
}

int destroy_enclave(sgx_enclave_id_t* const id)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if ((ret = sgx_destroy_enclave(*id)) != SGX_SUCCESS) {
        return -1;
    }

    return 0;
}

void ocall_print_something(void)
{
    std::cout << "Hello World!" << std::endl;
}