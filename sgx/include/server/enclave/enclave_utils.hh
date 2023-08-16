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
#ifndef ENCLAVE_UTILS_HH
#define ENCLAVE_UTILS_HH

// #include <chrono>
#include <type_traits>
#include <string>
#include <unordered_map>

#include <sgx_urts.h>

#include <basic_models.hh>

extern int64_t ocall_latency;

#ifndef ENCLAVE_LOG
#define ENCLAVE_LOG(format, ...) \
  { enclave_utils::printf(format, ##__VA_ARGS__); }
#endif

namespace enclave_utils {

using sgx_error_list = std::unordered_map<sgx_status_t, std::string>;

static const std::string kDigits = "0123456789abcdef";

#if __cplusplus >= 201703L
/** @addtogroup String concatenation helpers with arbitrary elements.
 *  @warning This is not supported by current SGX libstdc++ libraries (C++14).
 *
 *  @{
 */
template <typename T>
inline std::string to_string(T&& val) {
  if constexpr (std::is_arithmetic<T>::value) {
    return std::to_string(val);
  } else if constexpr (std::is_same<std::decay_t<T>, const char*>::value) {
    return std::string(val);
  } else {
    return "";
  }
}

inline std::string strcat_helper(const std::string& string) { return string; }

// Concatenate a list of strings into a single string.
// Example: strcat({"hello", "world"}) -> "helloworld"
template <class T, class... Args>
inline std::string strcat_helper(const std::string& string, T&& val,
                                 Args&&... args) {
  return strcat_helper(string + to_string(std::forward<T>(val)),
                       (std::forward<Args>(args))...);
}

template <class... Args>
inline std::string enclave_strcat(Args&&... args) {
  std::string string;
  return strcat_helper(string, (std::forward<Args>(args))...);
}
/** @} */
#endif

/**
 * @brief Cast an unsigned char array to hexical std::string with format.
 *
 * @param array
 * @param len
 * @return std::string
 */
std::string hex_to_string(const uint8_t* array, const size_t& len = 32);

/**
 * @brief Cast a char array to the hexical std::string without format.
 *
 * @param array
 * @param len
 * @return std::string
 */
std::string to_hex(const uint8_t* array, const size_t& len = 32);

/**
 * @brief Cast a hexcial string to char array.
 *
 * @param in
 * @param out
 */
void string_to_hex(const std::string& in, uint8_t* out);

/**
 * @brief A debug function for printing the buffer inside the enclave.
 *
 * @param fmt
 * @param ...
 */
void printf(const char* fmt, ...);

/**
 * @brief A special interface for std::string type.
 *
 * @param str
 * @param hex
 */
void sprintf(const std::string& str, bool hex = false);

/**
 * @brief Print the block.
 *
 * @param block
 */
void print_block(const sgx_oram::oram_block_t* const block);

/**
 * @brief Print the slot header.
 *
 * @param header
 */
void print_slot_metadata(const sgx_oram::oram_slot_header_t* const header);

/**
 * @brief Print the slot.
 *
 * @param header
 * @param slot
 * @param size
 */
void print_slot_body(const sgx_oram::oram_slot_header_t* const header,
                     const sgx_oram::oram_block_t* const slot, size_t size);

/**
 * @brief Print the permutation.
 *
 * @param permutation
 * @param size
 */
void print_permutation(const uint32_t* permutation, uint32_t size);

/**
 * @brief Safe free the memory.
 *
 * @param ptr
 */
void safe_free(void* ptr);

/**
 * @brief Safe free the all memory.
 *
 * @param count the number of pointers
 * @param ...
 */
void safe_free_all(size_t count, ...);

bool is_equal(uint8_t* const lhs, uint8_t* const rhs, const size_t& len);

// NOTE: THE SIZE OF ALL BUFFERS IS MULTIPLE OF 32.
// Potential acceleration can be SIMD or AVX2 instruction set.
// FIXME: All these functions cannot be declared as '' within the
// enclave
//        because the enclave is not compiled with -fno-strict-aliasing.
void band(const uint8_t* __restrict__ lhs, const uint8_t* __restrict__ rhs,
          uint8_t* out, size_t lhs_size, size_t rhs_size);

void bor(const uint8_t* __restrict__ lhs, const uint8_t* __restrict__ rhs,
         uint8_t* out, size_t lhs_size, size_t rhs_size);

void bneg(const uint8_t* __restrict__ lhs, uint8_t* __restrict__ out,
          size_t lhs_size);

void populate_from_bool(bool condition, uint8_t* out, size_t size);

uint8_t populate_from_bool(bool condition);

void check_sgx_status(const sgx_status_t& status, const std::string& location);

void slot_segment_write(const char* slot_fingerprint, const uint8_t* const slot,
                        size_t slot_size, size_t seg_size = 65535);

void slot_segment_read(const char* slot_fingerprint, uint8_t* slot,
                       size_t slot_size, size_t seg_size = 65535);

/**
 * @brief Assigns rhs to lhs when condition is true. We implicitly assume
 * that the size of the lhs variable is always the same as the size of the
 * rhs variable.
 *
 * @param condition
 * @param lhs
 * @param rhs
 * @param lhs_size
 * @param rhs_size
 */
void oblivious_assign(bool condition, uint8_t* __restrict__ lhs,
                      uint8_t* __restrict__ rhs, size_t lhs_size,
                      size_t rhs_size);

/**
 * @brief This is an alternative for boolean oblivious assignment.
 *
 * @param condition
 * @param lhs
 * @param rhs
 */
void oblivious_assign(bool condition, bool* lhs, bool* rhs);

/**
 * @brief Concatenate arbitrary arguments into a string.
 *
 * @param str ...
 * @return std::string
 */
std::string enclave_strcat(const std::string& str, ...);

/**
 * @brief Sample a random number in [lower, upper] using SGX's random library.
 *
 * @param lower
 * @param upper
 * @return uint32_t
 */
uint32_t uniform_random(uint32_t lower, uint32_t upper);

/**
 * @brief Get the time source from the CPU using assembly language.
 * @note  std::chrono is disabled in the enclave and we cannot use it for now.
 *
 * @return uint64_t
 */
uint64_t get_current_time(void);

}  // namespace enclave_utils
#endif  // ENCLAVE_UTILS_HH