#!/bin/bash
# Copyright (c) 2021 Haobin Chen
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

if [ -e ./output.txt ];
then
  rm ./output.txt
fi

set -x

./build/Simulator -r 10 -t 2 -c 1.0 -n 1280 -w 32 -b 64
./build/Simulator -r 10 -t 2 -c 1.0 -n 2145304 -w 32 -b 128
./build/Simulator -r 10 -t 2 -c 1.0 -n 34095632 -w 64 -b 128
./build/Simulator -r 10 -t 2 -c 1.0 -n 67650064 -w 64 -b 256
./build/Simulator -r 10 -t 2 -c 1.0 -n 2147483648 -w 128 -b 256
./build/Simulator -r 10 -t 2 -c 1.0 -n 4294967296 -w 128 -b 512

echo "Experiment done!"