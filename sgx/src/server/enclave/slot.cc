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
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <app/basic_models.hh>

void sgx_oram::Slot::add_block(const Block& block, const uint32_t& pos) {
  // LOG(plog::debug) << pos << ", " << storage.size() << "\n";
  storage[pos] = block;
  // If this is a real block then we need the decrease the value of dummy_num.
  if (block.is_dummy == false) {
    dummy_number--;
  }
}

void sgx_oram::Slot::set_range(const uint32_t& begin, const uint32_t& end) {
  range.first = begin;
  range.second = end;
}

void sgx_oram::Slot::set_level(const uint32_t& level) { this->level = level; }

bool sgx_oram::Slot::in(const uint32_t& bid) {
  return range.first <= bid && bid <= range.second;
}

sgx_oram::Block::Block(const bool& is_dummy) : is_dummy(is_dummy) {}

sgx_oram::Slot::Slot(const uint32_t& size) {
  storage = std::vector<Block>(size, Block(true));
  dummy_number = size;
}

sgx_oram::Block sgx_oram::Block::from_json(const std::string& json) {
  // Create a json DOM from the string.
  rapidjson::Document document;
  document.Parse(json.data());

  // Then fill in each field.
  Block block;
  block.address = document["address"].GetUint();
  block.bid = document["bid"].GetUint();
  block.data = document["data"].GetString();
  block.is_dummy = document["is_dummy"].GetBool();
}

sgx_oram::Block sgx_oram::Block::from_value(const rapidjson::Value& value) {}

std::string sgx_oram::Block::to_json(void) const {
  std::string ans;

  {
    // Create string buffer to quickly dump json from object.
    rapidjson::StringBuffer string_buffer;
    // The writer is just a wrapper.
    rapidjson::Writer<rapidjson::StringBuffer> writer(string_buffer);

    writer.StartObject();
    // Fill the value field.
    writer.Key("address");
    writer.Uint(address);
    writer.Key("bid");
    writer.Uint(bid);
    writer.Key("data");
    writer.String(data.c_str());
    writer.Key("is_dummy");
    writer.Uint(is_dummy);
    writer.EndObject();

    // Get the string from the string buffer.
    ans = string_buffer.GetString();
  }  // Destroy after this scope.

  return ans;
}

sgx_oram::Slot sgx_oram::Slot::from_json(const std::string& json) {
  // Create a json DOM from the string.
  rapidjson::Document document;
  document.Parse(json.data());

  // Create an empty slot object.
  Slot slot;

  // Begin to retrive data.
  slot.dummy_number = document["dummy_number"].GetUint();
  slot.level = document["level"].GetUint();
  slot.range = std::make_pair(document["range_left"].GetUint(),
                              document["range_right"].GetUint());

  // Iterate over the block and call block::from_json.
  assert(document["storage"].IsArray() && "Json format is corrupted!");
  const rapidjson::Value& storage_array = document["storage"].GetArray();
  for (auto iter = storage_array.Begin(); iter != storage_array.End(); iter++) {
    slot.storage.emplace_back(Block::from_value(*iter));
  }
}