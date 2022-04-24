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
#include <random>

#include <utils.hh>

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

void convert_endian(uint8_t* array, const size_t& len) {
  for (size_t i = 0; i < len; i++) {
    // To hex.
    uint8_t num = array[i];
    array[i] = 0;
    array[i] |= (num & 0xf0);
    array[i] |= (num & 0x0f) << 4;
  }
}

void safe_free(void* ptr) {
  if (ptr != nullptr) {
    free(ptr);
  }
}

void fisher_yates_shuffle(uint32_t* array, const size_t& len) {
  // Initialize the random number generator.
  std::random_device rd;
  std::mt19937 gen(rd());
  // Intialize the uniform distribution.
  std::uniform_int_distribution<> dis(0, len - 1);
  for (size_t i = len - 1; i > 0; i--) {
    size_t j = dis(gen);
    uint32_t tmp = array[i];
    array[i] = array[j];
    array[j] = tmp;
  }
}