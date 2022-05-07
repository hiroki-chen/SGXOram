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
#ifndef ORAM_STATUS_H
#define ORAM_STATUS_H

#include <unordered_map>

namespace partition_oram {
  enum Status {
    OK = 0,
    INVALID_ARGUMENT = 1,
    INVALID_OPERATION = 2,
    OUT_OF_MEMORY = 3,
    FILE_NOT_FOUND = 4,
    FILE_IO_ERROR = 5,
  };

  static const std::unordered_map<Status, std::string> error_list = {
    {OK, "OK"},
    {INVALID_ARGUMENT, "Invalid argument"},
    {INVALID_OPERATION, "Invalid operation"},
    {OUT_OF_MEMORY, "Out of memory"},
    {FILE_NOT_FOUND, "File not found"},
    {FILE_IO_ERROR, "File I/O error"},
  };
} // namespace partition_oram

#endif // ORAM_STATUS_H