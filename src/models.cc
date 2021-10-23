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
#include <cmath>

#include <models.hh>

sgx_oram::Block::Block(const bool& is_dummy, const std::string& data, const uint32_t& bid)
    : is_dummy(is_dummy)
    , data(data)
    , bid(bid)
{
}

sgx_oram::Block::Block(const bool& is_dummy)
    : is_dummy(is_dummy)
{
}

sgx_oram::Slot::Slot(const uint32_t& size)
{
    storage.reserve(size);
}

sgx_oram::Oram::Oram(const uint32_t& p, const uint32_t& block_number)
    : p(p)
    , level(std::ceil(std::log(block_number) / std::log(p)))        // \log_{p}{N} = \log_{N} / \log_{p}
    , block_number(block_number)
{
}