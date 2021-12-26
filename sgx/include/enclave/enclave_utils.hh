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

#include <type_traits>
#include <string>

static const std::string digits = "0123456789abcdef";
/** @addtogroup String concatenation helpers with arbitrary elements.
 *
 *  @{
 */
template <typename T>
inline std::string to_string(T&& val) {
  if constexpr (std::is_arithmetic<T>::value) {
    return std::to_string(val);
  } else if constexpr (std::is_same<std::decay_t<T>, const char*>::value) {
    return std::string(val);
  }
}

inline std::string strcat_helper(const std::string& string) { return string; }

template <class T, class... Args>
inline std::string strcat_helper(const std::string& string, T&& val,
                                 Args&&... args) {
  return strcat_helper(string + to_string(std::forward<T>(val)),
                       (std::forward<Args>(args))...);
}

template <class... Args>
inline std::string strcat(Args&&... args) {
  std::string string;
  return strcat_helper(string, (std::forward<Args>(args))...);
}

/** @} */

/**
 * @brief Cast an unsigned char array to hexical std::string.
 *
 * @param array
 * @param len
 * @return std::string
 */
std::string hex_to_string(const uint8_t* array, const size_t& len = 32);

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

#endif