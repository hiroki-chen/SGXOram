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
SGX_SDK ?= $(shell echo $SGX_SDK)
SGX_SIGN ?= $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R ?= $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_MODE ?= SIM
SGX_DEBUG ?= 1
SGX_ARCH ?= x64

# Specify some paths.
SGX_LIBRARY_PATH ?= $(SGX_SDK)/lib64
INCLUDE_PATH := ../../include/server
COMMON_INCLUDE_PATH := ../../include
SRC_PATH := $(CURDIR)
BUILD_PATH := ../../build/server
KEY_PATH := ../../key
GRPC_PATH := /usr/local/grpc

# Must recompile the project if these parameters are changed.
BUCKET_SIZE ?= 32
# Maybe this should be multipled with a constant c.
SLOT_SIZE ?= 16
CONSTANT ?= 16

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
                    -Wmissing-include-dirs -Wfloat-equal -Wundef \
                    -Wcast-align -Wno-cast-qual -Wno-unused-variable \
										-Wno-unused-parameter -Werror \
										-I$(INCLUDE_PATH) -I$(COMMON_INCLUDE_PATH)\
									  -DSUPPLIED_KEY_DERIVATION \
										-DDEFAULT_BUCKET_SIZE=$(BUCKET_SIZE) -DDEFAULT_SLOT_SIZE=$(SLOT_SIZE)

SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++1z

# App settings
ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

ifeq ($(SUPPLIED_KEY_DERIVATION), 1)
  SGX_COMMON_FLAGS += -DSUPPLIED_KEY_DERIVATION
endif

App_C_Flags := -fPIC -Wno-attributes -fopenmp -I$(INCLUDE_PATH)

ifeq ($(SGX_DEBUG), 1)
    App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
endif

PROTO_OBJ := $(wildcard ../../build/proto/*.o)

App_Cpp_Files := $(wildcard $(SRC_PATH)/app/*.cc)
App_Cpp_Flags := $(App_C_Flags)
App_Link_Flags := -L../../lib -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread -lsgx_pthread\
								  -lsgx_ukey_exchange -lservice_provider\
								  `pkg-config $(GRPC_PATH)/lib/pkgconfig/grpc++.pc --libs`\
									`pkg-config /usr/local/grpc/lib/pkgconfig/protobuf.pc --libs`\
           				-lpthread\
           				-Wl,--no-as-needed -lgrpc++_reflection -Wl,--as-needed\
           				-ldl -lgflags -llz4

App_Cpp_Objects := $(patsubst $(SRC_PATH)/app/%.cc, $(BUILD_PATH)/app/%.o, $(App_Cpp_Files))
App_Dependencies := $(patsubst %.o,%.d,$(App_Cpp_Objects))
App_Name := $(BUILD_PATH)/../bin/server.bin

-include $(App_Dependencies)

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_epid_sim -lsgx_quote_ex_sim
else
	App_Link_Flags += -lsgx_epid -lsgx_quote_ex
endif

######## Enclave Settings ########
ifeq ($(SGX_MODE), SIM)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name = sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := $(wildcard $(SRC_PATH)/enclave/*.cc)
Enclave_Cpp_Objects := $(patsubst $(SRC_PATH)/enclave/%.cc, $(BUILD_PATH)/enclave/%.o, $(Enclave_Cpp_Files))
Enclave_Denpendencies := $(patsubst %.o,%.d,$(Enclave_Cpp_Objects))

-include $(Enclave_Denpendencies)

Enclave_Include_Paths := -I$(INCLUDE_PATH) -I$(INCLUDE_PATH)/enclave -I$(SGX_SDK)/include \
						 -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc\
					-fvisibility=hidden -fpie -ffunction-sections \
					-fdata-sections $(MITIGATION_CFLAGS) \
					-fstack-protector-strong -fopenmp

Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++
Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack

Enclave_Link_Flags := $(MITIGATION_LDFLAGS) $(Enclave_Security_Link_Flags) \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_TRUSTED_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_pthread -lsgx_omp -lsgx_tcxx  -lsgx_tkey_exchange \
		   -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=$(SRC_PATH)/enclave/enclave.lds

Enclave_Name := $(BUILD_PATH)/enclave/enclave.so
Signed_Enclave_Name := $(BUILD_PATH)/enclave/enclave_signed.so
Enclave_Config_File := $(CURDIR)/config.xml

# Configure the untrusted application
App_Cpp_Files := $(wildcard $(SRC_PATH)/app/*.cc)
App_Cpp_Objects := $(patsubst $(SRC_PATH)/app/%.cc, $(BUILD_PATH)/app/%.o, $(App_Cpp_Files))
App_Cpp_Objects += $(Common_Object_Files) $(PROTO_OBJ)

App_Include_Paths := -I$(INCLUDE_PATH) -I$(SGX_SDK)/include
App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)

######## Service Provider Settings ########
Service_Provider_Name := $(BUILD_PATH)/service_provider/libservice_provider.so
SP_Crypto_Library_Name := sample_libcrypto
ServiceProvider_Cpp_Files := $(wildcard $(SRC_PATH)/service_provider/*.cpp)
ServiceProvider_Cpp_Objects := $(patsubst $(SRC_PATH)/service_provider/%.cpp, $(BUILD_PATH)/service_provider/%.o, $(ServiceProvider_Cpp_Files))
ServiceProvider_Include_Paths := -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx 

ServiceProvider_C_Flags := -fPIC -Wno-attributes -I$(INCLUDE_PATH) -I$(COMMON_INCLUDE_PATH)/service_provider -I$(COMMON_INCLUDE_PATH)/sample_libcrypto
ServiceProvider_Cpp_Flags := $(ServiceProvider_C_Flags)
ServiceProvider_Link_Flags :=  -shared $(SGX_COMMON_CFLAGS) -L../../lib -l$(SP_Crypto_Library_Name)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -g -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags)

ifeq ($(SGX_MODE), SIM)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
endif
endif

.PHONY: all enclave mk create_proxy create_key sign clean test_sgx
mk:
ifeq ("$(wildcard $(BUILD_PATH))", "")
	@mkdir -p $(BUILD_PATH)/enclave $(BUILD_PATH)/app $(BUILD_PATH)/common
	@printf "\033[1;93;49mMAKE DIRECTORY => $(BUILD_PATH)\033[0m\n"
endif
ifeq ("$(wildcard $(KEY_PATH))", "")
	@mkdir -p $(KEY_PATH)
	@printf "\033[1;93;49mMAKE DIRECTORY => $(KEY_PATH)\033[0m\n"
endif
ifeq ("$(wildcard $(BUILD_PATH)/test_sgx)", "")
	@mkdir -p $(BUILD_PATH)/test_sgx
endif
ifeq ("$(wildcard $(BUILD_PATH)/service_provider)", "")
	@mkdir -p $(BUILD_PATH)/service_provider
endif

# Generate proxy interfaces.
create_proxy: $(SRC_PATH)/enclave/enclave.edl
	@$(SGX_EDGER8R) $< --untrusted-dir $(SRC_PATH)/enclave --trusted-dir $(SRC_PATH)/enclave --search-path $(SGX_SDK)/include
	@printf "\033[1;93;49mProxy files generated.\033[0m\n"
# Move the generated headers to the include path.
	@mv $(SRC_PATH)/enclave/*.h $(INCLUDE_PATH)/enclave
	@printf "\033[1;93;49mMoved headers to $(INCLUDE_PATH).\033[0m\n"

# Compile common files.

# Compile proxy functions.
$(BUILD_PATH)/enclave/enclave_t.o: $(SRC_PATH)/enclave/enclave_t.c
	@$(CC) $(Enclave_C_Flags) -MMD -MP $(SGX_COMMON_CFLAGS) -c $< -o $@
	@printf "\033[1;93;49mCC  =>  $@\033[0m\n"

$(BUILD_PATH)/enclave/enclave_u.o: $(SRC_PATH)/enclave/enclave_u.c
	@$(CC) $(Enclave_C_Flags) -MMD -MP $(SGX_COMMON_CFLAGS) -c $< -o $@
	@printf "\033[1;93;49mCC  =>  $@\033[0m\n"

# Compile the enclave.
$(BUILD_PATH)/enclave/%.o: $(SRC_PATH)/enclave/%.cc
	@$(CXX) $(Enclave_Cpp_Flags) -MMD -MP $(SGX_COMMON_CXXFLAGS) -c $< -o $@
	@printf "\033[1;93;49mCXX =>  $@\033[0m\n"

# Link the object files and generate a shared object.
$(Enclave_Name): $(BUILD_PATH)/enclave/enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@printf "\033[1;93;49mLINK =>  $@\033[0m\n"

$(BUILD_PATH)/app/%.o: $(SRC_PATH)/app/%.cc
	@$(CXX) $(SGX_COMMON_CXXFLAGS) -MMD -MP $(App_Cpp_Flags) -c $< -o $@
	@printf "\033[1;93;49mCXX  <=  $<\033[0m\n"

$(App_Name): $(BUILD_PATH)/enclave/enclave_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@printf "\033[1;93;49mLINK =>  $@\033[0m\n"

# Service provider settings.
$(BUILD_PATH)/service_provider/%.o: $(SRC_PATH)/service_provider/%.cpp
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(ServiceProvider_Cpp_Flags) -c $< -o $@
	@printf "\033[1;93;49mCXX  <=  $<\033[0m\n"

$(Service_Provider_Name): $(ServiceProvider_Cpp_Objects)
	@$(CXX) $^ -o $@ $(ServiceProvider_Link_Flags)
	@printf "\033[1;93;49mLINK =>  $@\033[0m\n"
	@cp $(Service_Provider_Name) ../../lib
	@printf "\033[1;93;49mCP <=  $@\033[0m\n"

# Create a RSA private key.
# !The exponential must be 3 for the enclave.
$(KEY_PATH)/key.pem:
	@openssl genrsa -3 -out $(KEY_PATH)/key.pem 3072 &> /dev/null
	@printf "\033[1;93;49mKEYGEN =>  $@\033[0m\n"

$(Signed_Enclave_Name): $(Enclave_Name) $(KEY_PATH)/key.pem
	@$(SGX_SIGN) sign -key $(KEY_PATH)/key.pem \
					  -enclave $(Enclave_Name) -out $@ \
					  -config $(Enclave_Config_File) \
						> $(BUILD_PATH)/enclave/sign.log 2>&1

enclave: mk create_proxy $(Signed_Enclave_Name)
	@printf "\033[1;93;49mEnclave created!\033[0m\n"

all: enclave $(App_Name) $(Service_Provider_Name)
	@printf "\033[1;93;49mBuilding the application and the enclave...\033[0m\n"
	@printf "\033[1;93;49mLink => $(word 2,$^)\033[0m\n"

$(SRC_PATH)/test_sgx/main.c: mk

$(BUILD_PATH)/test_sgx/main.o: $(SRC_PATH)/test_sgx/main.c
	@$(CC) -Werror -Wextra -Wno-uninitialized -O2 -c $< -o $@
	@printf "\033[1;93;49mCC =>  $<\033[0m\n"

# Test if the CPU supports SGX features.
test_sgx: $(BUILD_PATH)/test_sgx/main.o
	@$(CC)	-o $(BUILD_PATH)/test_sgx/test.bin $<
	@printf "\033[1;93;49mGEN =>  $(BUILD_PATH)/test_sgx/test.bin\033[0m\n"
	@$(CURDIR)/$(BUILD_PATH)/test_sgx/test.bin

clean:
	@rm -r $(BUILD_PATH) $(KEY_PATH)
