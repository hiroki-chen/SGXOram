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
#include <models.hh>
using sgx_oram::Oram;
using sgx_oram::Parser;

int main(int argc, const char** argv)
{
    try {
        Parser* const parser = new Parser(argc, argv);
        parser->parse();
        Oram* const oram_controller = new Oram(parser->get_result());
    } catch (const std::exception& e) {
        PLOG(plog::error) << e.what();
        exit(1);
    }

    return 0;
}