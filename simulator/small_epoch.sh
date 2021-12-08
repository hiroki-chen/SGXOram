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

# This shell script is for running small batches to test the SGX-based recursive oblivious RAM.

if [[ -z COMPILE_MODE ]];
then
    echo "Compile mode not set. Usage: $$export COMPILE_MODE=DEBUG"
    exit
else
    make test MODE=${COMPILE_MODE}
fi

# Removes the output file.
if [ "$(find . -regex ".*.txt") != ''" ];
then
    rm -rf *.txt
fi

declare -a ways=("16" "32" "64")
declare -a bucket_sizes=("32" "64" "128")
declare -a block_nums=("1000" "10000" "50000")
declare -a rounds=("10" "100")
declare -a constants=("1.0" "1.5" "2.0")

for way in "${ways[@]}";
do
    for bucket_size in "${bucket_sizes[@]}";
    do
        if ((${bucket_size} < ${way}));
        then
            continue
        else
            
            for block_num in "${block_nums[@]}";
            do
                for round in "${rounds[@]}";
                do
                    for constant in "${constants[@]}";
                    do
                        cmd="./build/Simulator -w ${way} -n ${block_num} -r ${round} -b ${bucket_size} -t 2 -c ${constant}"
                        # Invoke the binary the run the experiment.
                        echo "Experiment setting: ${cmd}"
                        ${cmd}

                        # Check the return value.
                        if [ $? != 0 ];
                        then
                          echo "This batch returns an error. A block may be lost due to overflown slot."
                          echo "Error: ${cmd}" >> err.txt
                        fi
                    done
                done
            done
        fi
    done
done
