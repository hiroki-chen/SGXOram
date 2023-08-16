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

# set -x # Set echo on.
declare -a ways=("4" "8" "16" "32" "64" "128")
declare -a bucket_sizes=("4" "6" "7" "8")
declare -a block_nums=("10000" "100000" "1000000" "10000000")
if [ -e ./output.txt ]
then
  rm ./output.txt
fi

declare -i i=1
for way in "${ways[@]}"
do
  for bucket_size in "${bucket_sizes[@]}"
  do
    for block_num in "${block_nums[@]}"
    do
      # -w 64 -n 200000 -r 100 -t 0 -c 2.0 -b 6
      echo "Batch ${i} starts."
      echo "./build/Simulator -w "${way}" -n "${block_num}" -b "${bucket_size}" -c 1.5 -r 10 -t 0"
      ./build/Simulator -w "${way}" -n "${block_num}" -b "${bucket_size}" -c 1.5 -r 10 -t 0
      echo "Experiment ${i} ends."
      i+=1
    done
  done
done

echo "Experiment done."
