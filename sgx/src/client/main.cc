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
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <client/client.hh>
#include <client/utils.hh>
#include <configs.hh>

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
DEFINE_uint32(access_num, 100, "The number of accesses to the ORAM.");
DEFINE_int32(log_level, spdlog::level::level_enum::info,
             "The log level of the client.");
DEFINE_bool(log_to_stderr, false, "Enable logging to stderr");

std::shared_ptr<spdlog::logger> logger;
// Create a file sink.
std::shared_ptr<spdlog::sinks::rotating_file_sink_mt> file_sink =
    std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        client_log_dir + "/" + client_name + "_" + get_log_file_name(),
        client_log_size, client_log_num);

std::vector<spdlog::sink_ptr> sinks;

int main(int argc, char** argv) {
  // Parse the command line arguments.
  gflags::SetUsageMessage(
      "The SGX-Based Doubly Oblibvious RAM by Nankai University.");
  gflags::SetVersionString("0.0.1");
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  // Initialize all sinks.
  file_sink->set_level(static_cast<spdlog::level::level_enum>(FLAGS_log_level));
  file_sink->set_pattern(log_pattern);
  sinks.emplace_back(file_sink);

  if (FLAGS_log_to_stderr) {
    std::shared_ptr<spdlog::sinks::stdout_color_sink_mt> console_sink =
        std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(
        static_cast<spdlog::level::level_enum>(FLAGS_log_level));
    sinks.emplace_back(console_sink);
  }

  // Initialize the logger.
  logger =
      std::make_shared<spdlog::logger>(client_name, begin(sinks), end(sinks));
  spdlog::set_default_logger(logger);

  try {
    std::unique_ptr<Client> client =
        std::make_unique<Client>(FLAGS_address, FLAGS_port);
    client->init_enclave();
    client->generate_session_key();
    client->init_oram();
    // client->test_oram_cache();
    // Put all the needed operations below.
    client->test_oram();
    client->print_storage_information();
    client->close_connection();
    // client->destroy_enclave();
  } catch (const std::exception& e) {
    (e.what());
  }

  gflags::ShutDownCommandLineFlags();
  return 0;
}