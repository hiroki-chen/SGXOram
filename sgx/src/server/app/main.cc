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
#include <gflags/gflags.h>
#include <sgx_urts.h>

#include <plog/Log.h>
#include <plog/Appenders/ColorConsoleAppender.h>
#include <plog/Formatters/TxtFormatter.h>
#include <plog/Initializers/RollingFileInitializer.h>
#include <app/models.hh>
#include <app/server_runner.hh>

// Configurations for the server.
DEFINE_string(address, "localhost", "The server's IP address");
DEFINE_string(port, "1234", "The server's port");

// Configurations for the ORAM should be sent by the client?

static sgx_enclave_id_t global_eid = 0;

static plog::RollingFileAppender<plog::TxtFormatter> file_appender(
    "./log/oram.log");  // Create the 1st appender.
static plog::ColorConsoleAppender<plog::TxtFormatter>
    consoler_appender;  // Create the 2nd appender.

// A global variable.
std::unique_ptr<Server> server_runner;

int SGX_CDECL main(int argc, char** argv) {
  // Parse the command line arguments.
  gflags::SetUsageMessage("The SGX-Based Doubly Oblibvious RAM by Nankai University.");
  gflags::SetVersionString("0.0.1");
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  // Nullify the input arguments.
  (void)(argc);
  (void)(argv);
  // Create a logger.
  plog::init(plog::debug, &file_appender).addAppender(&consoler_appender);

  // Run the server.
  try {
    server_runner = std::make_unique<Server>();
    server_runner->run(FLAGS_address + ":" + FLAGS_port, &global_eid);
  } catch (const std::exception& e) {
    LOG(plog::fatal) << e.what();
  }

  gflags::ShutDownCommandLineFlags();
  return 0;
}