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


sgx_oram::Parser::Parser(const int& argc, const char** argv)
    : argc(argc)
    , argv(argv)
{
    options = new cxxopts::Options("Simulator",
        " ------ The SGX-Based ORAM Created by Data Security Lab at Nankai University -----\n"
        " Authored by Haobin Chen and Siyi Lv\n"
        " Copyright ©️ Nankai University");

    options->add_options()
        ("c,constant", "The constant multiplicated with the slot size.", cxxopts::value<double>()->default_value("1"))
        ("f,file", "The file path of the data you want to load into the SGX.", cxxopts::value<std::string>()->default_value("./input.data"))
        ("n,number", "The number of the total blocks.", cxxopts::value<uint32_t>()->default_value("100000"))
        ("r,round", "The round of test", cxxopts::value<uint32_t>()->default_value("4"))
        ("v,verbose", "Enable verbose mode", cxxopts::value<bool>()->default_value("false"))
        ("w,way", "The number of ways in the SGX tree.", cxxopts::value<uint32_t>()->default_value("8"))
        ("h,help", "Print usage information.")
    ;
}

void sgx_oram::Parser::parse(void)
{
    result = options->parse(argc, argv);

    if (result.count("help")) {
        std::cout << options->help() << std::endl;
        exit(0);
    }
}