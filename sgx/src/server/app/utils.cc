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
#include <algorithm>
#include <iostream>
#include <random>
#include <memory>
#include <fstream>

#include <gzip/compress.hpp>
#include <gzip/decompress.hpp>
#include <app/server_runner.hh>
#include <plog/Log.h>

#include <enclave/enclave_u.h>
#include <utils.hh>
#include <configs.hh>

extern std::unique_ptr<Server> server_runner;

void ocall_write_slot(const char* slot_finger_print, const uint8_t* data,
                      size_t data_len) {
  LOG(plog::debug) << "The fingerprint for the slot is: " << slot_finger_print;

  const char* data_ptr = reinterpret_cast<const char*>(data);
  std::string compressed_data = gzip::compress(data_ptr, data_len);
  server_runner->store_compressed_slot(slot_finger_print, compressed_data);
}

// Debug function.
void ocall_printf(const char* message) { LOG(plog::debug) << message; }

// Exception handler.
void ocall_exception_handler(const char* err_msg) {
  throw std::runtime_error(err_msg);
}

void ocall_read_position(const char* position_finderprint, uint8_t* position,
                         size_t position_size) {
  return;
}

void ocall_write_position(const char* position_finderprint,
                          const uint8_t* position, size_t position_size) {
  return;
}

size_t ocall_read_slot(const char* slot_finger_print, uint8_t* data,
                       size_t data_len) {
  LOG(plog::debug) << "The fingerprint for the slot is: " << slot_finger_print;

  // Check if the slot is in the memory.
  bool is_in_memory = server_runner->is_in_storage(slot_finger_print);

  if (is_in_memory) {
    std::string compressed_data =
        server_runner->get_compressed_slot(slot_finger_print);
    const char* data_ptr =
        reinterpret_cast<const char*>(compressed_data.data());
    std::string decompressed_data =
        gzip::decompress(data_ptr, compressed_data.size());

    const size_t decompressed_size = decompressed_data.size();
    memcpy(data, decompressed_data.data(), decompressed_size);
    return decompressed_size;
  } else {
    LOG(plog::debug) << "Slot not found in memory.";

    // TODO: Find the slot in the directory called data.
    return 0;
  }
}

namespace sgx_oram {
std::vector<std::string> generate_random_strings(const uint32_t& number,
                                                 const uint32_t& length) {
  std::vector<std::string> ans;

  for (uint32_t i = 0; i < number; i++) {
    std::string s;
    for (uint32_t j = 0; j < 32; j++) {
      const uint32_t pos = untrusted_uniform_random(0, candidate.size() - 1);
      s.push_back(candidate[pos]);
    }
    ans.push_back(s);
  }

  return ans;
}

std::vector<std::string> get_data_from_file(std::ifstream* const file) {
  LOG(plog::debug) << "Reading data from file is started!";
  std::vector<std::string> ans;
  while (!(*file).eof()) {
    std::string s;
    std::getline(*file, s);
    ans.push_back(s);
  }
  LOG(plog::debug) << "Reading data from file is finished!";

  return ans;
}

uint32_t untrusted_uniform_random(const uint32_t& lower,
                                  const uint32_t& upper) {
  if (lower == upper) {
    return lower;
  }
  std::random_device rd;
  std::mt19937 engine(rd());
  std::uniform_int_distribution<uint32_t> dist(lower, upper);
  return dist(engine);
}

int init_enclave(sgx_enclave_id_t* const id) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_launch_token_t launch_token = {0};
  int updated = 0;

  // It is the caller's responsibility to give us the global enclave id.
  if ((ret = sgx_create_enclave(enclave_path.c_str(), 1, &launch_token,
                                &updated, id, nullptr)) != SGX_SUCCESS) {
    return -1;
  }

  return 0;
}

std::string hex_to_string(const uint8_t* array, const size_t& len) {
  std::string ans;

  for (size_t i = 0; i < len; i++) {
    // To hex.
    uint8_t num = array[i];
    ans += digits[num & 0xf];
    ans += digits[num >> 4];
  }

  return ans;
}

int destroy_enclave(sgx_enclave_id_t* const id) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  if ((ret = sgx_destroy_enclave(*id)) != SGX_SUCCESS) {
    return -1;
  }

  return 0;
}

void safe_free(void* ptr) {
  if (ptr != nullptr) {
    free(ptr);
  }
}

}  // namespace sgx_oram