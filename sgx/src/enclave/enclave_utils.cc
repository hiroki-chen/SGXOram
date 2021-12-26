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
#include <enclave/enclave_u.h>

std::string hex_to_string(const uint8_t* array, const size_t& len) {
  std::string ans;

  for (uint8_t i = 0; i < len; i++) {
    // To hex.
    uint8_t num = array[i];
    ans += digits[num & 0xf];
    ans += digits[num >> 4];
  }

  return ans;
}

void string_to_hex(const std::string& in, uint8_t* out) {
  // The output length is specified by in.size().
  uint32_t j = 0;
  for (uint32_t i = 0; i < in.size(); i += 2) {
    if (std::isalpha(in[i])) {
      out[j] = (10 + in[i] - 'a') << 4;
    } else {
      out[j] = (in[i] - '0') << 4;
    }

    if (std::isalpha(in[i + 1])) {
      out[j] += (10 + in[i + 1] - 'a');
    } else {
      out[j] += (in[i + 1] - '0');
    }
    j++;
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
    printf("%s", hex_to_string((const uint8_t*)str.data(), str.size()).data());
  } else {
    printf("%s", str.data());
  }
}