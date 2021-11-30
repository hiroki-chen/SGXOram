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
#include <plog/Log.h>

#include <algorithm>
#include <iostream>
#include <random>
#include <utils.hh>

namespace sgx_oram {
std::vector<std::string> generate_random_strings(const uint32_t& number,
                                                 const uint32_t& length) {
  std::vector<std::string> ans;

  for (uint32_t i = 0; i < number; i++) {
    std::string s;
    for (uint32_t j = 0; j < 32; j++) {
      const uint32_t pos = uniform_random(0, candidate.size() - 1);
      s.push_back(candidate[pos]);
    }
    ans.push_back(s);
  }

  return ans;
}

std::vector<Block> convert_to_blocks(const std::vector<std::string>& data) {
  std::vector<Block> ans;

  uint32_t i = 0;
  std::transform(
      data.begin(), data.end(), std::back_inserter(ans),
      [&i](const std::string& s) { return Block(false, s, i, i++); });

  std::random_device rd;
  std::mt19937 engine(rd());
  std::shuffle(ans.begin(), ans.end(), engine);

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

uint32_t uniform_random(const uint32_t& lower, const uint32_t& upper) {
  if (lower == upper) {
    return lower;
  }

  std::random_device rd;
  std::mt19937 engine(rd());
  std::uniform_int_distribution<uint32_t> dist(lower, upper);
  return dist(engine);
}

std::vector<uint32_t> to_p_nary(uint32_t number, uint32_t base, uint32_t pad) {
  std::vector<uint32_t> ans;

  // Iteratre until number becomes zero.
  while (number != 0) {
    uint32_t cur = number % base;
    ans.emplace_back(cur);
    number /= base;
  }

  std::vector<uint32_t> pad_vec;
  size_t i = ans.size();
  for (; i <= pad; i++) {
    pad_vec.push_back(0);
  }

  pad_vec.insert(pad_vec.end(), ans.begin(), ans.end());

  return pad_vec;
}

// Friend operator.
plog::Record& operator<<(plog::Record& record, const Slot& slot) {
  const auto storage = slot.storage;
  record << "Slot range: [" << slot.range.first << ", " << slot.range.second
         << "] "
         << "Slot size: " << slot.storage.size()
         << " dummy number: " << slot.dummy_number;
  for (auto item : storage) {
    if (!item.is_dummy) {
      record << std::endl
             << " data: " << item.data << " bid: " << item.bid
             << " address: " << item.address << std::endl;
    }
  }
  return record;
}

plog::Record& operator<<(plog::Record& record, const Position& position) {
  record << "level: " << position.level_cur << ", offset: " << position.offset
         << ", bid_cur: " << position.bid_cur
         << ", bid_dst: " << position.bid_dst
         << ", slot_num: " << position.slot_num;

  return record;
}

std::ostream& operator<<(std::ostream& os, const std::vector<uint32_t>& vec) {
  for (auto num : vec) {
    os << num << " ";
  }
  os << std::endl;
  return os;
}

}  // namespace sgx_oram
