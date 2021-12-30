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
#include <client.hh>
#include <plog/Log.h>
#include <plog/Appenders/ColorConsoleAppender.h>
#include <plog/Formatters/TxtFormatter.h>
#include <plog/Initializers/RollingFileInitializer.h>

#include <gflags/gflags.h>

static plog::RollingFileAppender<plog::TxtFormatter> file_appender(
    "./log/oram.log");  // Create the 1st appender.
static plog::ColorConsoleAppender<plog::TxtFormatter>
    consoler_appender;  // Create the 2nd appender.

int main(int argc, const char** argv) {
  // Create a logger.
  plog::init(plog::debug, &file_appender).addAppender(&consoler_appender);

  try {
    std::unique_ptr<Client> client =
        std::make_unique<Client>("localhost", "1234");
    client->init_enclave();
    client->generate_session_key();

    // Put all the needed operations below.
    
    client->close_connection();
  } catch (const std::exception& e) {
    LOG(plog::fatal) << e.what();
  }

    return 0;
}