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
#include <plog/Appenders/ColorConsoleAppender.h>
#include <plog/Formatters/TxtFormatter.h>
#include <plog/Initializers/RollingFileInitializer.h>
#include <plog/Log.h>

#include <vector>

using sgx_oram::Config;
using sgx_oram::Oram;
using sgx_oram::Parser;

static plog::RollingFileAppender<plog::TxtFormatter> file_appender("./log/oram.log"); // Create the 1st appender.
static plog::ColorConsoleAppender<plog::TxtFormatter> consoler_appender; // Create the 2nd appender.

int main(int argc, const char** argv)
{
    // Create a logger.
    plog::init(plog::debug, &file_appender).addAppender(&consoler_appender);
    std::vector<uint32_t> real_block_numbers = { 10000, 100000 };
    std::vector<uint32_t> ways = { 8, 16, 32, 64, 128 };
    std::vector<uint32_t> rounds = { 5, 10, 20, 50, 100 };
    std::vector<double> constants = { 1.0, 1.2, 1.5, 1.8, 2.0, 2.5 };

    for (uint32_t real_block_number : real_block_numbers) {
        for (uint32_t way : ways) {
            for (uint32_t round : rounds) {
                for (double constant : constants) {
                    Config config;
                    config.constant = constant;
                    config.p = way;
                    config.type = 0;
                    config.verbose = false;
                    config.round = round;
                    config.real_block_num = real_block_number;
                    try {
                        Oram* const oram_controller = new Oram(config);
                        oram_controller->run_test();
                    } catch (const std::runtime_error& e) {
                        PLOG(plog::error) << "\033[1;91;107m"
                                          << e.what()
                                          << "\033[0m";
                    }
                }
            }
        }
    }
}