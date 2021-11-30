#!/bin/bash
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
