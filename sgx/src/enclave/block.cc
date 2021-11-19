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
#include <app/basic_models.hh>

sgx_oram::Position::Position(
    const uint32_t& level_cur,
    const uint32_t& offset,
    const uint32_t& bid_cur,
    const uint32_t& bid_dst)
    : level_cur(level_cur)
    , offset(offset)
    , bid_cur(bid_cur)
    , bid_dst(bid_dst)
{
}

sgx_oram::Block::Block(const bool& is_dummy, const std::string& data, const uint32_t& bid, const uint32_t& address)
    : is_dummy(is_dummy)
    , data(data)
    , bid(bid)
    , address(address)
{
}