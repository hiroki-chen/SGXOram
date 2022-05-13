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
#include <cmath>

#include <sgx_urts.h>

#include <enclave/enclave_t.h>
namespace enclave_utils {
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
    ans += kDigits[array[i] >> 4];
    ans += kDigits[array[i] & 0xf];

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
    num += kDigits.find(in[i]);
    num += kDigits.find(in[i + 1]) << 4;
    out[i / 2] = num;
  }
}

void print_block(sgx_oram::oram_block_t* const block) {
  ENCLAVE_LOG("------------------------------");
  ENCLAVE_LOG("[enclave] Block: ");
  ENCLAVE_LOG("[enclave]  - address: %d", block->header.address);
  ENCLAVE_LOG("[enclave]  - type: %d", (int)block->header.type);
  ENCLAVE_LOG("[enclave]  - bid: %d", block->header.bid);
  ENCLAVE_LOG("[enclave]  - data[0]: %d", block->data[0]);
  ENCLAVE_LOG("------------------------------");
}

void print_slot_metadata(const sgx_oram::oram_slot_header_t* const header) {
  ENCLAVE_LOG("------------------------------");
  ENCLAVE_LOG("[enclave] Slot metadata: ");
  ENCLAVE_LOG("[enclave]  - type: %d", (int)header->type);
  ENCLAVE_LOG("[enclave]  - level: %u", header->level);
  ENCLAVE_LOG("[enclave]  - offset: %u", header->offset);
  ENCLAVE_LOG("[enclave]  - range: [%u, %u]", header->range_begin,
              header->range_end);
  ENCLAVE_LOG("[enclave]  - dummy_number: %u", header->dummy_number);
  ENCLAVE_LOG("[enclave]  - slot_size: %u", header->slot_size);
  ENCLAVE_LOG("------------------------------");
}

void print_permutation(const uint32_t* permutation, uint32_t size) {
  ENCLAVE_LOG("------------------------------");
  for (uint32_t i = 0; i < size; ++i) {
    ENCLAVE_LOG("%u ", permutation[i]);
  }
  ENCLAVE_LOG("------------------------------");
}

std::string to_hex(const uint8_t* array, const size_t& len) {
  // Convert the array of bytes into a hex string.
  std::string ans;
  for (size_t i = 0; i < len; i++) {
    // Convert every byte into a hex string.
    ans += kDigits[array[i] >> 4];
    ans += kDigits[array[i] & 0xf];
  }
  return ans;
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

void populate_from_bool(bool condition, uint8_t* out, size_t size) {
  // Populate the output array with the condition.
  for (size_t i = 0; i < size; i++) {
    out[i] = populate_from_bool(condition);
  }
}

uint8_t populate_from_bool(bool condition) {
  uint8_t ans = 0;

  for (size_t i = 0; i < 8; i++) {
    ans |= condition << i;
  }

  return ans;
}

void band(const uint8_t* __restrict__ lhs, const uint8_t* __restrict__ rhs,
          uint8_t* out, size_t lhs_size, size_t rhs_size) {
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

#pragma omp parallel for if (lhs_size >= 65535)
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
         uint8_t* out, size_t lhs_size, size_t rhs_size) {
  // A sanity check.
  if (lhs_size != rhs_size) {
    ENCLAVE_LOG("[enclave] lhs_size != rhs_size.\n");
    return;
  } else if (lhs_size % WORD_SIZE != 0 || rhs_size % WORD_SIZE != 0) {
    ENCLAVE_LOG("[enclave] lhs or rhs is not aligned to 32.\n");
    return;
  }

#pragma omp parallel for if (lhs_size >= 65535)
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
  if (upper < lower) {
    ocall_panic_and_flush(
        "Cannot perform uniform_random because upper < lower!");
  }

  // @ref Chromium's base/rand_util.cc for the implementation.
  uint32_t range = upper - lower + 1;
  uint32_t max_acceptable_value =
      (std::numeric_limits<uint32_t>::max() / range) * range - 1;
  // We sample a random number and them map it to the range [lower, upper]
  // (inclusive) in a uniform way by scaling.
  uint32_t value;
  do {
    // Use a strong RNG to generate a random number.
    sgx_status_t status = sgx_read_rand((uint8_t*)&value, sizeof(value));
    check_sgx_status(status, "sgx_read_rand");
  } while (value > max_acceptable_value);

  value = value % range + lower;
  return value;
}

bool is_equal(uint8_t* const lhs, uint8_t* const rhs, const size_t& len) {
  for (size_t i = 0; i < len; i++) {
    if (lhs[i] != rhs[i]) {
      ENCLAVE_LOG("[enclave] Different bytes at index %zu.\n", i);
      return false;
    }
  }
  return true;
}

uint64_t get_current_time(void) {
  uint32_t hi, lo;

  __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));

  return ((uint64_t)hi << 32) | (uint64_t)lo;
}

void slot_segment_write(const char* slot_fingerprint, const uint8_t* const slot,
                        size_t slot_size, size_t seg_size) {
  // Write the slot in segments.
  size_t seg_num = std::floor(slot_size * 1. / seg_size);

  for (size_t i = 0; i < seg_num; i++) {
    sgx_status_t status = ocall_write_slot_seg(
        slot_fingerprint, i * seg_size, slot + i * seg_size, seg_size, 0);
    check_sgx_status(status, "ocall_write_slot_seg()");
  }

  // Write the last segment.
  size_t last_seg_size = slot_size % seg_size;
  if (last_seg_size != 0) {
    ocall_write_slot_seg(slot_fingerprint, seg_num * seg_size,
                         slot + seg_num * seg_size, last_seg_size, 1);
  }
}

void slot_segment_read(const char* slot_fingerprint, uint8_t* slot,
                       size_t slot_size, size_t seg_size) {
  // Read the slot in segments.
  size_t seg_num = std::floor(slot_size * 1. / seg_size);
  size_t dummy;
  for (size_t i = 0; i < seg_num; i++) {
    sgx_status_t status = ocall_read_slot_seg(
        &dummy, slot_fingerprint, i * seg_size, slot + i * seg_size, seg_size);
    check_sgx_status(status, "ocall_read_slot_seg()");
  }

  // Read the last segment.
  size_t last_seg_size = slot_size % seg_size;
  if (last_seg_size != 0) {
    sgx_status_t status =
        ocall_read_slot_seg(&dummy, slot_fingerprint, seg_num * seg_size,
                            slot + seg_num * seg_size, last_seg_size);
    check_sgx_status(status, "ocall_read_slot_seg()");
  }
}

}  // namespace enclave_utils