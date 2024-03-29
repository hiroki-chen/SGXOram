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
#include <app/utils.hh>

#include <cstring>
#include <algorithm>
#include <iostream>
#include <random>
#include <memory>
#include <iomanip>
#include <fstream>

#include <lz4.h>
#include <gflags/gflags.h>
#include <spdlog/spdlog.h>
#include <spdlog/fmt/bin_to_hex.h>
#include <unistd.h>

#include <app/server_runner.hh>
#include <enclave/enclave_u.h>
#include <configs.hh>

extern std::unique_ptr<Server> server_runner;

DECLARE_bool(verbose);

void ocall_printf(const char* message) {
  // If the flag is set, print the message.
  // This is used for debugging.
  logger->debug(message);
}

void ocall_report_time(const char* message, int64_t tick) {
  // Report the elapsed time by converting the tick to timepoint.
  logger->info(message, tick);
}

void ocall_panic_and_flush(const char* reason) {
  logger->error("A fatal error happened in the enclave, the reason is: {}.",
                reason);
  logger->flush();

  // Destroy the enclave.
  sgx_destroy_enclave(*server_runner->get_enclave_id());
  abort();
}

void ocall_flush_log() {
  logger->info("logger is forced to flush here.");
  logger->flush();
}

static const std::string get_machine_name(void) {
  char hostname[256];
  gethostname(hostname, sizeof(hostname));
  return std::string(hostname);
}

static std::string get_current_time(void) {
  time_t rawtime;
  struct tm* timeinfo;
  char buffer[80];

  time(&rawtime);
  timeinfo = localtime(&rawtime);

  strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
  return std::string(buffer);
}

// Exception handler, but reserved. Please do not use.
// We strongly recommend you to use the exception handler provided by the
// SGX SDK, i.e., you should not use this function for exception handling,
// unless you are defintely sure what you are doing.
// For reasons why C++ exceptions are not an ideal solution, please refer to
// the link provided by Google's C++ coding guideline:
//
//    https://google.github.io/styleguide/cppguide.html#Exceptions
void ocall_exception_handler(const char* err_msg) {
  throw std::runtime_error(err_msg);
}

std::string compress_data(const std::string& data) {
  // Compress the source std::string with lz4 compression libarary.
  // The compressed data will be stored in the destination std::string.
  // The destination std::string will be resized to the correct size.
  std::string compressed_data;
  const size_t max_allowed_size = LZ4_compressBound(data.size());
  compressed_data.resize(max_allowed_size);
  const size_t compressed_size = LZ4_compress_default(
      data.data(), compressed_data.data(), data.size(), compressed_data.size());
  compressed_data.resize(compressed_size);
  return compressed_data;
}

std::string decompress_data(const std::string& data) {
  // Decompress the source std::string with lz4 compression library.
  std::string decompressed_data;
  const size_t max_allowed_size = data.size() * 2;
  decompressed_data.resize(max_allowed_size);
  const size_t decompressed_size =
      LZ4_decompress_safe(data.data(), decompressed_data.data(), data.size(),
                          decompressed_data.size());
  decompressed_data.resize(decompressed_size);
  return decompressed_data;
}

size_t ocall_read_position(const char* position_fingerprint, uint8_t* position,
                           size_t position_size) {
  if (!server_runner->is_position_in_storage(position_fingerprint)) {
    logger->error("Position with fingerprint {} is not found!",
                  position_fingerprint);

    // We return 0 to indicate a failure.
    return 0;
  }
  const std::string position_str =
      server_runner->get_position(position_fingerprint);

  // Decompress the position.
  const std::string decompressed_position = decompress_data(position_str);
  // Copy the decompressed position to the position buffer.
  memcpy(position, decompressed_position.data(), decompressed_position.size());
  return decompressed_position.size();
}

void ocall_write_position(const char* position_fingerprint,
                          const uint8_t* position, size_t position_size) {
  // The position must be encrypted, and the position_fingerprint should be the
  // hash value.
  const std::string position_str(reinterpret_cast<const char*>(position),
                                 position_size);
  // logger->debug("Position: {}", position_fingerprint);
  // logger->debug("Ciphertext: {}", spdlog::to_hex(position_str));
  // Compress the position.
  const std::string compressed_position = compress_data(position_str);
  server_runner->store_position(position_fingerprint, compressed_position);
}

void ocall_write_slot(const char* slot_finger_print, const uint8_t* data,
                      size_t data_len) {
  // Compress the data and then store it to the server.
  std::string compressed_data =
      compress_data(std::string((char*)data, data_len));
  server_runner->store_compressed_slot(slot_finger_print, compressed_data);
}

void ocall_write_slot_seg(const char* slot_fingerprint, size_t offset,
                          const uint8_t* data, size_t data_len, int finished) {
  uint8_t* slot = server_runner->get_slot_buf();

  if (offset == 0) {
    memset(slot, 0, slot_buf_size);
    server_runner->reset_cur_size();
  }

  server_runner->add_cur_size(data_len);
  memcpy(slot + offset, data, data_len);

  if (finished) {
    // Write the whole thing back.
    ocall_write_slot(slot_fingerprint, slot, server_runner->get_cur_size());
    return;
  }
}

void ocall_write_slot_header(const char* slot_finger_print, const uint8_t* data,
                             size_t data_len) {
  // Compress the data and then store it to the server.
  std::string compressed_data =
      compress_data(std::string((char*)data, data_len));
  server_runner->store_compressed_slot_header(slot_finger_print,
                                              compressed_data);
}

size_t ocall_read_slot(const char* slot_finger_print, uint8_t* data,
                       size_t data_len) {
  // Check if the slot is in the memory.
  bool is_in_memory = server_runner->is_body_in_storage(slot_finger_print);

  if (is_in_memory) {
    std::string compressed_data =
        server_runner->get_compressed_slot(slot_finger_print);
    std::string decompressed_data = decompress_data(compressed_data);
    const size_t decompressed_size = decompressed_data.size();
    memcpy(data, decompressed_data.data(), decompressed_size);
    return decompressed_size;
  } else {
    logger->error("The requested slot is not in the memory!");
    // Returns 0 to indicate that the slot is not found.
    // The enclave will simply crash or handle the error.
    return 0;
  }
}

size_t ocall_read_slot_seg(const char* slot_finger_print, size_t offset,
                           uint8_t* data, size_t data_len) {
  uint8_t* slot = server_runner->get_slot_buf();
  if (offset == 0) {
    memset(slot, 0, slot_buf_size);
    size_t total_size = ocall_read_slot(slot_finger_print, slot, data_len);
  }

  memcpy(data, slot + offset, data_len);
  return data_len;
}

size_t ocall_read_slot_header(const char* slot_finger_print, uint8_t* data,
                              size_t size) {
  logger->debug("[OCall] Reading slot header: {}",
                std::string(slot_finger_print));
  // Check if the slot header is in the memory.
  bool is_in_memory = server_runner->is_header_in_storage(slot_finger_print);
  if (is_in_memory) {
    std::string compressed_data =
        server_runner->get_compressed_slot_header(slot_finger_print);
    std::string decompressed_data = decompress_data(compressed_data);
    const size_t decompressed_size = decompressed_data.size();
    memcpy(data, decompressed_data.data(), decompressed_size);
    return decompressed_size;
  } else {
    logger->error("The requested slot header is not in the memory!");
    return 0;
  }
}

int ocall_is_body_in_storage(const char* slog_fingerprint) {
  return server_runner->is_body_in_storage(slog_fingerprint);
}

int ocall_is_header_in_storage(const char* slog_fingerprint) {
  return server_runner->is_header_in_storage(slog_fingerprint);
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
  logger->info("Reading data from file is started!");
  std::vector<std::string> ans;
  while (!(*file).eof()) {
    std::string s;
    std::getline(*file, s);
    ans.push_back(s);
  }
  logger->info("Reading data from file is finished!");

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
  std::stringstream ss;
  for (size_t i = 0; i < len; i++) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)array[i];
  }
  return ss.str();
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

std::string get_log_file_name(void) {
  std::string ans;
  ans += get_machine_name();
  ans += "_";
  ans += get_current_time();
  ans += ".log";
  return ans;
}

}  // namespace sgx_oram