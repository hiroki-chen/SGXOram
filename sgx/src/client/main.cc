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

#include <gflags/gflags.h>

#include <client.hh>

// Flags for the network communication.
DEFINE_string(address, "localhost", "The server's IP address");
DEFINE_string(port, "1234", "The server's port");

// Flags for the configuration of the ORAM.
DEFINE_uint32(way, 32, "The number of ways of the ORAM tree");
DEFINE_uint32(number, 1e6, "The number of total blocks in the ORAM tree");
DEFINE_uint32(bucket_size, 128, "The number of blocks in each bucket");
DEFINE_uint32(type, 0, "The type of the ORAM tree");
DEFINE_double(constant, 1.0, "A special constant for the ORAM tree");
DEFINE_uint32(round, 1, "The number of rounds of the ORAM access");
DEFINE_uint32(oram_type, 1, "The type of the ORAM used by the client.");

static plog::RollingFileAppender<plog::TxtFormatter> file_appender(
    "./log/oram.log");  // Create the 1st appender.
static plog::ColorConsoleAppender<plog::TxtFormatter>
    consoler_appender;  // Create the 2nd appender.

int main(int argc, char** argv) {
  // Parse the command line arguments.
  gflags::SetUsageMessage(
      "The SGX-Based Doubly Oblibvious RAM by Nankai University.");
  gflags::SetVersionString("0.0.1");
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  // Create a logger.
  plog::init(plog::debug, &file_appender).addAppender(&consoler_appender);

  try {
    std::unique_ptr<Client> client =
        std::make_unique<Client>(FLAGS_address, FLAGS_port);
    client->init_enclave();
    client->generate_session_key();
    client->init_oram();
    // Put all the needed operations below.
    client->close_connection();
  } catch (const std::exception& e) {
    LOG(plog::fatal) << e.what();
  }

  gflags::ShutDownCommandLineFlags();
  return 0;
}