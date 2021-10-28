# SGXOram by Nankai University
SGX ORAM implementation and evaluation

## Usage
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