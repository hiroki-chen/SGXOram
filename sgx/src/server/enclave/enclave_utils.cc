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

#include <cassert>

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
    {SGX_ERROR_MAC_MISMATCH, "The MAC verification failed."},
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

void safe_free_all(size_t count, ...) {
  va_list ap;
  va_start(ap, count);
  for (size_t i = 0; i < count; i++) {
    void* ptr = va_arg(ap, void*);
    safe_free(ptr);
  }
  va_end(ap);
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

    if (i % 32 == 31) {
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

void populate_from_bool(bool condition, uint8_t* __restrict__ out, size_t size) {
  // Populate the output array with the condition.
  for (size_t i = 0; i < size; i++) {
    out[i] = populate_from_bool(condition);
  }
}

uint8_t populate_from_bool(bool condition) {
  uint8_t ans;

  for (size_t i = 0; i < 8; i++) {
    ans |= condition << i;
  }

  return ans;
}

void band(const uint8_t* __restrict__ lhs, const uint8_t* __restrict__ rhs,
          uint8_t* __restrict__ out, size_t lhs_size, size_t rhs_size) {
  // A sanity check.
  if (lhs_size != rhs_size) {
    ENCLAVE_LOG("[enclave] lhs_size != rhs_size.\n");
    return;
  } else if (lhs_size % WORD_SIZE != 0 || rhs_size % WORD_SIZE != 0) {
    ENCLAVE_LOG("[enclave] size is %lu, which is not a multiple of 32.\n",
                lhs_size);
    ENCLAVE_LOG("[enclave] lhs or rhs is not aligned to 32.\n");
    return;
  }
  // Performs bitwise AND operation on two arrays in 32-bit chunks.
  // We assume that the arrays are of the same size multiple of 32.
  // Please pad the arrays with zeros **in advance** if necessary.
  for (size_t i = 0; i < lhs_size; i += WORD_SIZE) {
    out[i] = lhs[i] & rhs[i];
    out[i + 1] = lhs[i + 1] & rhs[i + 1];
    out[i + 2] = lhs[i + 2] & rhs[i + 2];
    out[i + 3] = lhs[i + 3] & rhs[i + 3];
  }
}

void bor(const uint8_t* __restrict__ lhs, const uint8_t* __restrict__ rhs,
         uint8_t* __restrict__ out, size_t lhs_size, size_t rhs_size) {
  // A sanity check.
  if (lhs_size != rhs_size) {
    ENCLAVE_LOG("[enclave] lhs_size != rhs_size.\n");
    return;
  } else if (lhs_size % WORD_SIZE != 0 || rhs_size % WORD_SIZE != 0) {
    ENCLAVE_LOG("[enclave] lhs or rhs is not aligned to 32.\n");
    return;
  }
  // Performs bitwise OR operation on two arrays in 32-bit chunks.
  // We assume that the arrays are of the same size multiple of 32.
  // Please pad the arrays with zeros **in advance** if necessary.
  for (size_t i = 0; i < lhs_size; i += WORD_SIZE) {
    out[i] = lhs[i] | rhs[i];
    out[i + 1] = lhs[i + 1] | rhs[i + 1];
    out[i + 2] = lhs[i + 2] | rhs[i + 2];
    out[i + 3] = lhs[i + 3] | rhs[i + 3];
  }
}

void check_sgx_status(const sgx_status_t& status, const std::string& reason) {
  if (status != SGX_SUCCESS) {
    ENCLAVE_LOG("[enclave] %s triggered an SGX error: %s\n", reason.data(),
                sgx_errlist[status].data());
    ocall_panic_and_flush(reason.c_str());
    abort();
  }
}

std::string enclave_strcat(const std::string& str, ...) {
  va_list ap;
  va_start(ap, str);
  std::string ans = str;
  while (true) {
    const char* next = va_arg(ap, const char*);
    if (next == nullptr) {
      break;
    }
    ans += next;
  }
  va_end(ap);
  return ans;
}

void oblivious_assign(bool condition, uint8_t* __restrict__ lhs,
                      uint8_t* __restrict__ rhs, size_t lhs_size,
                      size_t rhs_size) {
  // Pre-allocate two buffers for receiving the final output.
  uint8_t* res1 = (uint8_t*)malloc(lhs_size);
  uint8_t* res2 = (uint8_t*)malloc(lhs_size);
  // Convert condition to byte array.
  uint8_t* cond_positive = (uint8_t*)malloc(lhs_size);
  uint8_t* cond_negative = (uint8_t*)malloc(lhs_size);
  memset(cond_positive, populate_from_bool(condition), lhs_size);
  memset(cond_negative, populate_from_bool(!condition), lhs_size);

  band(cond_positive, rhs, res1, rhs_size, rhs_size);
  band(cond_negative, lhs, res2, lhs_size, lhs_size);

  // This is equivalent to lhs = (~condition & lhs) | (condition & rhs).
  bor(res1, res2, lhs, lhs_size, rhs_size);
  safe_free_all(4, res1, res2, cond_positive, cond_negative);
}

void oblivious_assign(bool condition, bool* lhs, bool* rhs) {
  *lhs = (!condition & *lhs) | (condition & *rhs);
}

uint32_t uniform_random(uint32_t lower, uint32_t upper) {
  assert(upper >= lower &&
         "upper bound must be greater than or equal to lower "
         "bound");
  // We sample a random number and them map it to the range [lower, upper] in a
  // uniform way by scaling.
  uint32_t range = upper - lower;
  uint32_t scale = RAND_MAX / range;

  uint32_t ans = 0;
  do {
    // Generate random number from sgx_rand_read.
    sgx_status_t status = sgx_read_rand((uint8_t*)&ans, sizeof(ans));
    check_sgx_status(status, "sgx_read_rand()");
  } while (ans >= scale * range);  // since scale is truncated, pick a new val
                                   // until it's lower than scale * range
  return ans / scale + lower;
}