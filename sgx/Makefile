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

# Specify the path of the binary files.
SGX_SDK ?= /usr/local/sgxsdk
SGX_SIGN ?= $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R ?= $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_MODE ?= SIM
SGX_DEBUG ?= 1
SGX_ARCH ?= x64

# Specify some paths.
SGX_LIBRARY_PATH ?= $(SGX_SDK)/lib64
INCLUDE_PATH := ./include
SRC_PATH := ./src
BUILD_PATH := ./build
KEY_PATH := ./key

# Include the SGX's official buildenv.mk
include $(SGX_SDK)/buildenv.mk

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_FLAGS += -O0 -g
else
	SGX_COMMON_FLAGS += -O2
endif 

# Compilation flags for building the enclave application.
SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++14

# App settings
ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_C_Flags := -fPIC -Wno-attributes -I$(INCLUDE_PATH)

ifeq ($(SGX_DEBUG), 1)
    App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
endif 

App_Cpp_Files := $(wildcard $(SRC_PATH)/app/*.cc)
App_Cpp_Flags := $(App_C_Flags)
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name)  # -lpthread 
App_Cpp_Objects := $(patsubst $(SRC_PATH)/app/%.cc, $(BUILD_PATH)/app/%.o, $(App_Cpp_Files))
App_Name := $(BUILD)/app/app.bin

######## Enclave Settings ########
ifeq ($(SGX_MODE), SIM)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := $(wildcard $(SRC_PATH)/enclave/*.cc)
Enclave_Cpp_Objects := $(patsubst $(SRC_PATH)/enclave/%.cc, $(BUILD_PATH)/enclave/%.o, $(Enclave_Cpp_Files))

Enclave_Include_Paths := -I$(INCLUDE_PATH)/enclave -I$(SGX_SDK)/include \
						 -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc \
					-fvisibility=hidden -fpie -ffunction-sections \
					-fdata-sections $(MITIGATION_CFLAGS) \
					-fstack-protector-strong

Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++
Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack

Enclave_Link_Flags := $(MITIGATION_LDFLAGS) $(Enclave_Security_Link_Flags) \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_TRUSTED_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=$(SRC_PATH)/enclave/enclave.lds

Enclave_Name := $(BUILD_PATH)/enclave/enclave.so
Signed_Enclave_Name := $(BUILD_PATH)/enclave/enclave_signed.so
Enclave_Config_File := ./config.xml

# Configure the untrusted application
App_Cpp_Files := $(wildcard $(SRC_PATH)/app/*.cc)
App_Cpp_Objects := $(patsubst $(SRC_PATH)/app/%.cc, $(BUILD_PATH)/app/%.o, $(App_Cpp_Files))

App_Include_Paths := -I$(INCLUDE_PATH) -I$(SGX_SDK)/include
App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags)
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread 
App_Name := $(BUILD_PATH)/app/app.bin

ifeq ($(SGX_MODE), SIM)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
endif
endif

.PHONY: all enclave mk create_proxy create_key sign clean
mk:
ifeq ("$(wildcard $(BUILD_PATH))", "")
	@mkdir -p $(BUILD_PATH)/enclave $(BUILD_PATH)/app
	@printf "\033[1;93;49mMAKE DIRECTORY => $(BUILD_PATH)\033[0m\n"
endif
ifeq ("$(wildcard $(KEY_PATH))", "")
	@mkdir -p $(KEY_PATH)
	@printf "\033[1;93;49mMAKE DIRECTORY => $(KEY_PATH)"
endif

# Generate proxy interfaces.
create_proxy: $(SRC_PATH)/enclave/enclave.edl
	@$(SGX_EDGER8R) $< --untrusted-dir $(SRC_PATH)/enclave --trusted-dir $(SRC_PATH)/enclave
	@printf "\033[1;93;49mProxy files generated.\033[0m\n"
# Move the generated headers to the include path.
	@mv $(SRC_PATH)/enclave/*.h $(INCLUDE_PATH)/enclave
	@printf "\033[1;93;49mMoved headers to $(INCLUDE_PATH).\033[0m\n"

# Compile proxy functions.
$(BUILD_PATH)/enclave/enclave_t.o: $(SRC_PATH)/enclave/enclave_t.c
	@$(CC) $(Enclave_C_Flags) $(SGX_COMMON_CFLAGS) -c $< -o $@
	@printf "\033[1;93;49mCC  =>  $@\033[0m\n"

$(BUILD_PATH)/enclave/enclave_u.o: $(SRC_PATH)/enclave/enclave_u.c
	@$(CC) $(Enclave_C_Flags) $(SGX_COMMON_CFLAGS) -c $< -o $@
	@printf "\033[1;93;49mCC  =>  $@\033[0m\n"

# Compile the enclave.
$(BUILD_PATH)/enclave/%.o: $(SRC_PATH)/enclave/%.cc
	@$(CXX) $(Enclave_Cpp_Flags) $(SGX_COMMON_CXXFLAGS) -c $< -o $@
	@printf "\033[1;93;49mCXX =>  $@\033[0m\n"

# Link the object files and generate a shared object.
$(Enclave_Name): $(BUILD_PATH)/enclave/enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@printf "\033[1;93;49mLINK =>  $@\033[0m\n"

$(BUILD_PATH)/app/%.o: $(SRC_PATH)/app/%.cc
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): $(BUILD_PATH)/enclave/enclave_u.o $(App_Cpp_Objects)
	$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

# Create a RSA private key.
# !The exponential must be 3 for the enclave.
$(KEY_PATH)/key.pem:
	@openssl genrsa -3 -out $(KEY_PATH)/key.pem 3072
	@printf "\033[1;93;49mKEYGEN =>  $@\033[0m\n"

$(Signed_Enclave_Name): $(Enclave_Name) $(KEY_PATH)/key.pem
	@$(SGX_SIGN) sign -key $(KEY_PATH)/key.pem \
					  -enclave $(Enclave_Name) -out $@ \
					  -config $(Enclave_Config_File)

enclave: mk create_proxy $(Signed_Enclave_Name)
	@printf "\033[1;93;49mEnclave created!\033[0m\n"

all: enclave $(App_Name)
	@printf "\033[1;93;49mBuilding the application and the enclave...\033[0m\n"

clean:
	@rm -r $(BUILD_PATH) $(KEY_PATH)