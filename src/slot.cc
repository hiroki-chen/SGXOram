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
#include <models.hh>

void sgx_oram::Slot::add_block(const Block& block, const uint32_t& pos)
{
    // LOG(plog::debug) << pos << ", " << storage.size() << "\n";
    storage[pos] = block;
    // If this is a real block then we need the decrease the value of dummy_num.
    if (block.is_dummy == false) {
        dummy_number --;
    }
}

void sgx_oram::Slot::set_range(const uint32_t& begin, const uint32_t& end)
{
    range.first = begin;
    range.second = end;
}

void sgx_oram::Slot::set_level(const uint32_t& level)
{
    this->level = level;
}

bool sgx_oram::Slot::in(const uint32_t& bid)
{
    return range.first <= bid && bid <= range.second;
}

sgx_oram::Block::Block(const bool& is_dummy)
    : is_dummy(is_dummy)
{
}

sgx_oram::Slot::Slot(const uint32_t& size)
{
    storage = std::vector<Block>(size, Block(true));
    dummy_number = size;
}