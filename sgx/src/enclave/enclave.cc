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
#include <app/basic_models.hh>
#include <enclave/enclave.hh>
#include <enclave/enclave_t.h>

#include <string.h>

#include <sgx_trts.h> /* For sgx_read_random. */

/* Interfaces for the applicaiton. */
/**
 * @brief Oblivious Access S1 implemented inside the enclave.
 * 
 * @param op 
 * @param flag 
 * @param slot 
 * @param slot_len 
 * @param data 
 * @param level 
 * @param position 
 * @param position_len 
 * @param block_number
 */
void obli_access_s1(uint16_t op, uint16_t flag,
    char* slot_arr, size_t slot_len,
    char* data,
    uint32_t level,
    char* block_arr, size_t block_len,
    char* position_arr, size_t position_len,
    uint32_t block_number)
{
    // First we need to deserialize the objects from char pointers.
    sgx_oram::Slot* const slot = reinterpret_cast<sgx_oram::Slot*>(slot_arr);
    sgx_oram::Position* const position = reinterpret_cast<sgx_oram::Position*>(position_arr);

    const uint32_t offset = position->offset;
    sgx_oram::Block data1(true), data2(true);
    // Case 1: Find a desired block.
    for (uint32_t i = 0; i < slot->storage.size(); i++) {
        if (flag == true && i == offset && slot->storage[i].is_dummy == false /* Necessary condition */) {
            const uint32_t nbid = uniform_random(0, block_number - 1);
            data1 = slot->storage[i];
            data1.bid = nbid;
            strncpy(data, data1.data.c_str(), data1.data.size());
            slot->dummy_number ++;
            slot->storage[i].is_dummy = true;

            block_arr = reinterpret_cast<char*>(&data1);
            return;
        }
    }

    // Case 2: Find block that should be evicted.
    for (uint32_t i = 0; i < slot->storage.size(); i++) {
        if (slot->storage[i].is_dummy == false) {
            data2 = slot->storage[i];
            slot->storage[i].is_dummy = true;
            slot->dummy_number ++;

            block_arr = reinterpret_cast<char*>(&data2);
            return;
        }
    }

    block_arr = reinterpret_cast<char*>(&data2);
    return;
}

void obli_access_S2(uint16_t op, uint16_t flag, char* slot, size_t slot_len, char* data1, size_t block_len, char* data, uint32_t level, char* position, size_t position_len)
{

}
void obli_access_s3(uint32_t rbid, char* data2, size_t block_len, char* slot, size_t slot_len, uint32_t level, char* position, size_t position_len)
{

}

uint32_t uniform_random(uint32_t lower, uint32_t upper)
{
    return uniform_random_helper(lower, upper);
}

void test_pointer(char* data)
{
    sgx_oram::Block block(true);
    block.data = "Hello World!";
    *data = 'H';
}

/* Hidden functions */
/**
 * @brief Since enclave only allowes for a relatively restricted library which does not include std::random,
 *        we need to generate random numbers by the interface provided by the Intel SGX SDK.
 * 
 * @param lower 
 * @param upper 
 * @return uint32_t A random number drawn from a uniform distribution?
 */
uint32_t uniform_random_helper(const uint32_t& lower, const uint32_t& upper)
{
    uint32_t random_number;
    // Read a random number.
    sgx_read_rand((unsigned char*)&random_number, 4);
    random_number = random_number % (upper + 1 - lower) + lower;
    return random_number;
}