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
.PHONY: clean all check_sgx protobuf

PROTO_PATH := $(CURDIR)/protos
PROTO_SRC := $(wildcard $(PROTO_PATH)/messages.proto)
INCLUDE_PATH := $(CURDIR)/include
BUILD_PATH := $(CURDIR)/build
PROTOC := $(shell which protoc)

SRC_FILE := $(PROTO_PATH)/messages.pb.cc $(PROTO_PATH)/messages.grpc.pb.cc 
OBJ_FILE := $(patsubst $(PROTO_PATH)/%.cc, $(BUILD_PATH)/%.o, $(SRC_FILE))

CXX ?= g++
CXX_FLAGS ?= -std=c++17 -Wall -Wextra -fPIC -I$(INCLUDE_PATH)

ifeq ($(MODE), DEBUG)
	CXX_FLAGS += -O0 -g
else
	CXX_FLAGS += -O2 -g
endif

all: mkdir $(SRC_FILE) server client
	@printf "\033[1;93;49mCreated server and client.\033[0m\n"

protobuf: $(SRC_FILE)
	

mkdir:
ifeq ("$(wildcard $(BUILD_PATH))", "")
	@mkdir -p $(BUILD_PATH)/bin
	@mkdir -p $(BUILD_PATH)/proto
	@printf "\033[1;93;49mMAKE DIRECTORY => $(BUILD_PATH)\033[0m\n"
endif

$(SRC_FILE): $(PROTO_SRC)
	@$(PROTOC) --cpp_out=$(PROTO_PATH) -I $(PROTO_PATH) $(PROTO_SRC)
	@$(PROTOC) --grpc_out=$(PROTO_PATH) --plugin=protoc-gen-grpc=$(shell which grpc_cpp_plugin) -I $(PROTO_PATH) $(PROTO_SRC)
	@mv $(CURDIR)/protos/*.h $(INCLUDE_PATH)
	@printf "\033[1;93;49mGenerated protobuf files.\033[0m\n"

$(BUILD_PATH)/%.pb.o: $(PROTO_PATH)/%.pb.cc
	@$(CXX) -o $@ -c $< $(CXX_FLAGS)
	@printf "\033[1;93;49mCXX => $@\033[0m\n"
	@mv $@ $(BUILD_PATH)/proto

server: mkdir $(OBJ_FILE)
	@$(MAKE) -C $(CURDIR)/src/server -f server.mk all

client: mkdir $(OBJ_FILE)
	@$(MAKE) -C $(CURDIR)/src/client -f client.mk all

clean:
	@rm -r $(CURDIR)/build 2> /dev/null || true
	@printf "\033[1;93;49mBuild folders cleared.\033[0m\n"
	@rm $(CURDIR)/protos/*.cc 2> /dev/null || true
	@rm $(CURDIR)/include/messages.grpc.pb.h $(CURDIR)/include/messages.pb.h 2> /dev/null || true
	@printf "\033[1;93;49mProtobuf auto-generated files cleared.\033[0m\n"

create_proxy:
	@$(MAKE) -f $(CURDIR)/src/server/server.mk -C $(CURDIR)/src/server create_proxy

check_sgx:
	@$(MAKE) -f $(CURDIR)/check_sgx/check.mk -C $(CURDIR)/build sgx_enable