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
#include <chrono>

#include <gflags/gflags.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <sgx_urts.h>
#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <configs.hh>
#include <app/utils.hh>
#include <app/server_runner.hh>

using sgx_oram::get_log_file_name;
using std::literals::chrono_literals::operator""s;

// Defines an error handler.
void handler(int sig) {
  // Flush the log to capture all error information.
  logger->flush();
  // Print the stack trace.
  void* array[10];
  size_t size;

  // get void*'s for all entries on the stack
  size = backtrace(array, 10);

  // print out all the frames to stderr
  fprintf(stderr, "Error: signal %d:\n", sig);
  backtrace_symbols_fd(array, size, STDERR_FILENO);
  exit(1);
}

std::shared_ptr<spdlog::sinks::rotating_file_sink_mt> file_sink =
    std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        server_log_dir + "/" + server_name + "_" + get_log_file_name(),
        server_log_size, server_log_num);

// Configurations for the server.
DEFINE_string(address, "localhost", "The server's IP address");
DEFINE_string(port, "1234", "The server's port");
DEFINE_bool(verbose, true, "Whether to print verbose information");
DEFINE_bool(cache_enabled, true, "Whether to enable the enclave cache");
DEFINE_bool(log_to_stderr, false, "Enable logging to stderr");
DEFINE_uint32(seg_size, 0,
              "The size of the slot segment (0 => disable segmentation)");
DEFINE_int32(log_level, spdlog::level::level_enum::info,
             "The log level (0 => trace, 1 => debug, ...)");

// Configurations for the enclave.
static sgx_enclave_id_t global_eid = 0;
// A global variable.
std::unique_ptr<Server> server_runner;

std::shared_ptr<spdlog::logger> logger;
std::vector<spdlog::sink_ptr> sinks;

int SGX_CDECL main(int argc, char** argv) {
  signal(SIGSEGV, handler);
  signal(SIGABRT, handler);
  signal(SIGINT, handler);
  // Parse the command line arguments.
  gflags::SetUsageMessage(
      "The SGX-Based Doubly Oblibvious RAM by Nankai University.");
  gflags::SetVersionString("0.0.1");
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  // Initialize the sink.
  file_sink->set_pattern(log_pattern);
  sinks.emplace_back(file_sink);

  if (FLAGS_log_to_stderr) {
    std::shared_ptr<spdlog::sinks::stdout_color_sink_mt> stdout_sink =
        std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    sinks.emplace_back(stdout_sink);
  }

  // Initialize the logger.
  logger =
      std::make_shared<spdlog::logger>("server", sinks.begin(), sinks.end());
  logger->set_level(static_cast<spdlog::level::level_enum>(FLAGS_log_level));
  spdlog::set_default_logger(logger);

  // Nullify the input arguments.
  (void)(argc);
  (void)(argv);

  // Run the server.
  try {
    server_runner = std::make_unique<Server>();
    server_runner->run(FLAGS_address + ":" + FLAGS_port, &global_eid);
  } catch (const std::exception& e) {
    logger->error(e.what());
  }

  gflags::ShutDownCommandLineFlags();
  return 0;
}