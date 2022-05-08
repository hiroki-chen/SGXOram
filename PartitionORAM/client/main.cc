/*
 Copyright (c) 2022 Haobin Chen

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
#include <memory>

#include <gflags/gflags.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "oram_client.h"

DEFINE_string(address, "localhost", "The address of the server.");
DEFINE_string(port, "1234", "The port of the server.");
DEFINE_string(crt_path, "", "The path of the certificate file.");

// ORAM PARAMS.
DEFINE_uint32(block_num, 1e6, "The number of blocks.");
DEFINE_uint32(bucket_size, 4, "The size of the bucket.");

std::shared_ptr<spdlog::logger> logger = spdlog::stdout_color_mt("oram_client");

int main(int argc, char* argv[]) {
  gflags::SetUsageMessage("The PartitionORAM Client");
  gflags::SetVersionString("0.0.1");
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  spdlog::set_default_logger(logger);
  spdlog::set_level(spdlog::level::debug);
  spdlog::flush_every(std::chrono::seconds(3));

  std::unique_ptr<partition_oram::Client> client =
      std::make_unique<partition_oram::Client>(
          FLAGS_address, FLAGS_port, FLAGS_crt_path, FLAGS_bucket_size,
          FLAGS_block_num);
  client->Run();
  client->StartKeyExchange();
  client->SendHello();
  client->InitOram();
  client->TestOram();
  
  client->CloseConnection();

  gflags::ShutDownCommandLineFlags();
  return 0;
}