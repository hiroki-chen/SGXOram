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
#include <plog/Appenders/ColorConsoleAppender.h>
#include <plog/Formatters/TxtFormatter.h>
#include <plog/Initializers/RollingFileInitializer.h>
#include <plog/Log.h>
#include <app/models.hh>

#include <enclave/enclave_u.h>
#include <utils.hh>

using sgx_oram::Oram;
using sgx_oram::Parser;

static sgx_enclave_id_t global_eid = 0;

static plog::RollingFileAppender<plog::TxtFormatter> file_appender("./log/oram.log"); // Create the 1st appender.
static plog::ColorConsoleAppender<plog::TxtFormatter> consoler_appender; // Create the 2nd appender.

int main(int argc, const char** argv)
{
    // Create a logger.
    plog::init(plog::debug, &file_appender).addAppender(&consoler_appender);
    /* try {
        Parser* const parser = new Parser(argc, argv);
        parser->parse();
        Oram* const oram_controller = new Oram(parser->get_result());
        oram_controller->run_test();
    } catch (const std::exception& e) {
        PLOG(plog::error) << e.what();
        exit(1);
    }*/
    if (sgx_oram::init_enclave(&global_eid) != 0) {
        LOG(plog::error) << "Cannot initialize the enclave!";
    }

    char data[sizeof(sgx_oram::Block)];
    memset(data, 0, sizeof(sgx_oram::Block));
    test_pointer(global_eid, data);
    
    LOG(plog::info) << "Content: " << data;
    return 0;
}