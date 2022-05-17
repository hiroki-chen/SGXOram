# Implementation of the Partition ORAM

This is the reference implementation of the paper appearing on NDSS symposium: **Towards Practical Oblivious RAM. E. Stefanov, E. Shi, and D. Song.** We are using PathORAM as the Blackbox ORAM.

The code is constructed upon some important libraries:

* Google's `gRPC` library for remote process call (strongly recommended that the library is built from source).
* Google's `abseil` library for some advanced tools for C++ (If you build gRPC from source, then libabseil is automatically installed on your computer).
* `spdlog` for logging.
* `Libsodium` for cryptographic tools.

You can install dependencies manually or by the shell script `deps.sh` if you are running Ubuntu. Note that C++17 is required, and `gRPC` library should be built by C++17.
 
