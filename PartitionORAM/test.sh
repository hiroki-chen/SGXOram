#!/bin/bash
# Copyright (c) 2022 Haobin Chen
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

MAGENTA='\033[1;35m'
NC='\033[0m' # No Color

printf "${MAGENTA}[+] Begin testing the Partition ORAM by different numbers of blocks...${NC}\n"

# set -x;

file="$(date).log";
touch "$file";

# Check if the environment variable is set.
if [[ -z ${https_proxy} ]]; then
    echo "Unsetting the proxy.";
    unset ${https_proxy};
fi

for ((i=6; i<=20; i++)); do
    block=$(echo "$((2 ** ${i}))");
    printf "${MAGENTA}    Testing block number: ${block}...${NC}\n";
    
    # Start the server in the background.
    ./bin/server --log_level=2 > ./log-server.log &
    
    # Wait for the server to start.
    sleep 1;
    
    ./bin/client --block_num=${block} --log_level=2 > ./log-client.log;
    client_pid=$!;
    
    wait ${client_pid};
    
    # Extract the running time by ms.
    running_time=$(grep "Time elapsed per block:" ./log-client.log | awk '{ for (i=1;i<=NF;i++) { if ($i == "ms.") { print $(i-1) } } }');
    echo "[+] Running time: ${running_time} ms for block number: ${block}." >> "./${file}";
done

printf "${MAGENTA}[+] Successfully tested the Partition ORAM. Goodbye.${NC}\n";