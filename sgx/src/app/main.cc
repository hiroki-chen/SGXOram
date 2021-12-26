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

static plog::RollingFileAppender<plog::TxtFormatter> file_appender(
    "./log/oram.log");  // Create the 1st appender.
static plog::ColorConsoleAppender<plog::TxtFormatter>
    consoler_appender;  // Create the 2nd appender.

int SGX_CDECL main(int argc, const char** argv) {
  // Nullify the input arguments.
  (void)(argc);
  (void)(argv);
  // Create a logger.
  plog::init(plog::debug, &file_appender).addAppender(&consoler_appender);

  // Initialize the enclave by loading into the signed shared object into the
  // main memory.
  if (sgx_oram::init_enclave(&global_eid) != 0) {
    LOG(plog::error) << "Cannot initialize the enclave!";
  }

  int ret = SGX_ERROR_UNEXPECTED;
  ecall_init_oram_controller(global_eid, &ret);

  return 0;
}