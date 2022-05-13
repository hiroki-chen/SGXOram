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
#ifndef CONFIG_HH
#define CONFIG_HH

#include <string>

static const std::string key_path = "./key";

static const std::string enclave_path =
    "./build/server/enclave/enclave_signed.so";

static const std::string log_pattern =
    "[%c] [Thread: %t | Process: %P | Name: %n] [%l] %v";

static const std::string server_log_dir = "./log";
static const std::string server_name = "server.bin";
static constexpr uint32_t server_log_size = 1024 * 1024 * 10;
static constexpr uint32_t server_log_num = 10;

static const std::string client_log_dir = "./log";
static const std::string client_name = "client.bin";
static constexpr uint32_t client_log_size = 1024 * 1024 * 10;
static constexpr uint32_t client_log_num = 10;

static constexpr uint32_t slot_buf_size = 102400000;

#endif  // CONFIG_HH