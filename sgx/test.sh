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

printf "${MAGENTA}[+] Begin testing the SO2 ORAM by different numbers of blocks...${NC}\n"

file="./test/$(date).log";
touch "$file";
client_src="./test/param.txt";

# Check if the environment variable is set.
if [[ -z ${https_proxy} ]]; then
    echo "Unsetting the proxy.";
    unset ${https_proxy};
fi

line=1;

for ((i=6; i<=21; i++)); do
    block=$(echo "$((2 ** ${i}))");
    printf "${MAGENTA}    Testing block number: ${block}...${NC}\n";
    
    # Start the server in the background.
    ./build/bin/server.bin --port=5678 --seg_size=0 --cache_enabled=1 --log_level=2 --log_to_stderr > ./test/log-server.log &

    sleep 3;
    
    # Read a line from the file.
    client_cmd=$(awk 'NR=='${line}'{print $0}' ${client_src});
    
    # Start the client.
    eval '${client_cmd}' > ./test/log-client.log;
    
    # Extract the end-to-end latency.
    latency=$(grep "The time for reading" ./test/log-client.log | awk '{ for (i=1;i<=NF;i++) { if ($i == "us.") { print $(i-1) } } }');
    echo "[+] End-to-end latency for block_num ${block}: ${latency} us" >> "$file";
    
    # Extract the server latency.
    latency=$(grep "The server has read the block" ./test/log-server.log | awk '{ for (i=1;i<=NF;i++) { if ($i == "microsecond.") { print $(i-1) } } }' | head);
    echo "[+] Server latency for block_num ${block}: ${latency} us" >> "$file";
    
    # Extract the access time.
    access_time=$(grep "Access time:" ./test/log-server.log | awk '{ for (i=1;i<=NF;i++) { if ($i == "us.") { print $(i-1) } } }');
    echo "[+] Access time for block_num ${block}: ${access_time} us" >> "$file";
    
    # Extract the eviction time.
    eviction_time=$(grep "Eviction time:" ./test/log-server.log | awk '{ for (i=1;i<=NF;i++) { if ($i == "us.") { print $(i-1) } } }');
    echo "[+] Eviction time for block_num ${block}: ${eviction_time} us" >> "$file";
    
    # Extract the ocall latency.
    ocall_latency=$(grep "Accumulative Ocall latency:" ./test/log-server.log | awk '{ for (i=1;i<=NF;i++) { if ($i == "us.") { print $(i - 1) } } }');
    echo "[+] Accumulative ocall latency for block_num ${block}: ${ocall_latency} us" >> "$file";
    
    # Extract the storage.
    storage=$(grep "The size of the storage is" ./test/log-server.log | awk '{ for (i=1;i<=NF;i++) { if ($i == "MB.") { print $(i-1) } } }');
    echo "[+] Storage for block_num ${block}: ${storage} MB" >> "$file";
    
    # Append an empty line.
    echo "" >> "$file";

    line=$(($line + 1));
done

printf "${MAGENTA}[+] Successfully tested the SO2 ORAM. Goodbye.${NC}\n";
