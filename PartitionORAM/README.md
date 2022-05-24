# Implementation of the Partition ORAM

This is the reference implementation of the paper appearing on NDSS symposium: **Towards Practical Oblivious RAM. E. Stefanov, E. Shi, and D. Song.** We are using PathORAM as the Blackbox ORAM.

The code is constructed upon some important libraries:

* Google's `gRPC` library for remote process call (strongly recommended that the library is built from source).
* Google's `abseil` library for some advanced tools for C++ (If you build gRPC from source, then libabseil is automatically installed on your computer).
* `spdlog` for logging.
* `Libsodium` for cryptographic tools.

You can run the test by the following command:

```sh
chmod -x ./test.sh;
cd ./build;
../test.sh;
```

The output will be sent to the file in the `./build` directory with the current timestamp.
