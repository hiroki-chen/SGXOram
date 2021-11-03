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
#include <iostream>

static sgx_enclave_id_t global_eid = 0;

int SGX_CDECL main(int argc, const char** argv)
{
    (void)(argc);
    (void)(argv);
    
    if (init_enclave(&global_eid) != 0) {
        std::cerr << "Cannot initialize the enclave!" << std::endl;
    }

    // Call the enclave function.
    ecall_print_something(&global_eid);

    if (destroy_enclave(&global_eid) != 0) {
        std::cerr << "Cannot destroy the enclave!" << std::endl;
    }

    return 0;
}