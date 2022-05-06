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
#include "oram_storage.h"

#include <cmath>

namespace partition_oram {
BinaryTree::BinaryTree(size_t num_of_blocks) {
  // Calculate the height of the tree that could sufficiently contain all the blocks.
  height = std::ceil(std::log(num_of_blocks) / std::log(2)) - 1;
  size = std::pow(2, height + 1) - 1;
}
}  // namespace partition_oram