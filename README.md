# SGXOram by Nankai University

## Project Layout

```shell
.
├── sgx
│   ├── build
│   ├── include
│   ├── key
│   └── src
└── simulator
    ├── include
    └── src
```

SGX ORAM simulation and evaluation

目前的这个版本是采用了将所有的块装进叶节点的方式来初始化的，而且是1,2,6,...这种类型的大小设置。

## Usage of the SIMULATOR

* GCC >= v5.0.
* Make sure that your compiler supports C++11 standards.

```shell
make all CXX=<your-compiler>;
```

e.g.

```shell
make all CXX=g++;
make test CXX=clang++;
```

Then run the executable file in the command line by:

```shell
------ The SGX-Based ORAM Created by Data Security Lab at Nankai University -----
 Authored by Haobin Chen and Siyi Lv
 Copyright ©️ Nankai University
Usage:
  Simulator [OPTION...]

  -c, --constant arg  The constant multiplicated with the slot size. 
                      (default: 1)
  -f, --file arg      The file path of the data you want to load into the 
                      SGX. (default: ./input.data)
  -n, --number arg    The number of the total blocks. (default: 100000)
  -r, --round arg     The round of test (default: 4)
  -v, --verbose       Enable verbose mode
  -w, --way arg       The number of ways in the SGX tree. (default: 8)
  -h, --help          Print usage information.
  ```

## NOTES ON THE SGX-VERSION ORAM -- How to install Intel (R) Software Guard eXtensions on Linux machines

Take Ubuntu 18.04LTS as an example.

1. Clone the git repository to a path:

```sh
mkdir -p ~/sgx_toolkit && cd ~/sgx_toolkit
git clone https://github.com/intel/linux-sgx.git
```

2. Install dependencies by:

```shell
  sudo apt-get install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip
  cd ./linux-sgx
  export https_proxy=http://<your proxy address>:<port> # This is necessary or wget cannot receive anything :(
  make preparation
  make sdk
```

3. Install the binary file and the headers to the path `/usr/local`:

```shell
  cd ./linux/installer/bin
  sudo -s
  ./sgx_linux_x64_sdk_2.15.100.3.bin
  Input the directory which you want to install in: /usr/local
  cp -r /usr/local/sgxsdk/include/** /usr/local/include
```

4. Before compiling the source files, make sure that the envirenment variables are set correctly by:

```
  source /usr/local/sgxsdk/environment
```

5. Then you could write Makefiles and invoke compilation:

```
  make SGX_MODE=SIM
```
