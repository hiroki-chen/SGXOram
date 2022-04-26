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
#include <enclave/enclave_utils.hh>

#include <sgx_urts.h>

#include <enclave/enclave_u.h>

// Error code for SGX API calls
static sgx_error_list sgx_errlist = {
    {SGX_ERROR_UNEXPECTED, "Unexpected error occurred."},
    {SGX_ERROR_INVALID_PARAMETER, "Invalid parameter."},
    {SGX_ERROR_OUT_OF_MEMORY, "Out of memory."},
    {SGX_ERROR_ENCLAVE_LOST,
     "Power transition occurred. Please refer to the sample "
     "\"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE, "Invalid enclave image."},
    {SGX_ERROR_INVALID_ENCLAVE_ID, "Invalid enclave identification."},
    {SGX_ERROR_INVALID_SIGNATURE, "Invalid enclave signature."},
    {SGX_ERROR_OUT_OF_EPC, "Out of EPC memory."},
    {SGX_ERROR_NO_DEVICE,
     "Invalid SGX device. Please make sure SGX module is enabled in the BIOS, "
     "and install SGX driver afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflicted."},
    {SGX_ERROR_INVALID_METADATA, "Invalid enclave metadata."},
    {SGX_ERROR_DEVICE_BUSY, "SGX device was busy."},
    {SGX_ERROR_INVALID_ATTRIBUTE, "Enclave was not authorized."},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file."},
    {SGX_ERROR_MEMORY_MAP_FAILURE, "Failed to reserve memory for the enclave."},
};

// A safe free is always used to free memory allocated by the enclave and is
// very important to avoid memory leaks, especially in the enclave because
// its memory is extremely limited.
void safe_free(void* ptr) {
  if (ptr != nullptr) {
    free(ptr);
  } else {
    ENCLAVE_LOG("[enclave] ptr is nullptr.\n");
  }
}

std::string hex_to_string(const uint8_t* array, const size_t& len) {
  // Convert the array of bytes into a hex string.
  // The delimiter is the space character; also, we insert a linebreak every 20
  // bytes. Do not use std::stringstream.
  std::string ans = "\n0000: ";
  for (size_t i = 0; i < len; i++) {
    // Convert every byte into a hex string.
    ans += digits[array[i] >> 4];
    ans += digits[array[i] & 0xf];

    if (i % 20 == 19) {
      ans += '\n';
      ans.append("00" + std::to_string(i + 1) + ": ");
    } else {
      ans += ' ';
    }
  }
  ans += '\n';
  return ans;
}

void string_to_hex(const std::string& in, uint8_t* out) {
  // The output length is specified by in.size().
  for (size_t i = 0; i < in.size(); i += 2) {
    // To binary.
    uint8_t num = 0;
    num += digits.find(in[i]);
    num += digits.find(in[i + 1]) << 4;
    out[i / 2] = num;
  }
}

void printf(const char* fmt, ...) {
  char buf[BUFSIZ] = {'\0'};
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  ocall_printf(buf);
}

void sprintf(const std::string& str, bool hex) {
  if (hex) {
    ENCLAVE_LOG("%s",
                hex_to_string((const uint8_t*)str.data(), str.size()).data());
  } else {
    ENCLAVE_LOG("%s", str.data());
  }
}

void band(const uint8_t* lhs, const uint8_t* rhs, uint8_t* out) {
  for (size_t i = 0; i < 32; i++) {
    out[i] = lhs[i] & rhs[i];
  }
}

void bor(const uint8_t* lhs, const uint8_t* rhs, uint8_t* out) {
  for (size_t i = 0; i < 32; i++) {
    out[i] = lhs[i] | rhs[i];
  }
}

size_t read_slot(sgx_oram::oram_slot_t* slot, const char* fingerprint) {
  const size_t size = ocall_read_slot(fingerprint, (uint8_t*)(slot),
                                      sizeof(sgx_oram::oram_slot_t));

  if (size == 0) {
    // The slot is not found or something went wrong.
    ENCLAVE_LOG("033[31m The slot for %s is not found.\n033[0m", fingerprint);
  }
  return size;
}

void check_sgx_status(const sgx_status_t& status, const std::string& reason) {
  if (status != SGX_SUCCESS) {
    ENCLAVE_LOG("[enclave] %s triggered an SGX error: %s\n", reason.data(),
                sgx_errlist[status].data());
    ocall_panic_and_flush(reason.c_str());
    abort();
  }
}