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
.PHONY: client server clean protobuf all

PROTO_PATH := $(CURDIR)/protos
PROTO_SRC := $(wildcard $(PROTO_PATH)/*.proto)
INCLUDE_PATH := $(CURDIR)/include
BUILD_PATH := $(CURDIR)/build

SRC_FILE := $(wildcard $(PROTO_PATH)/*.cc)
OBJ_FILE := $(patsubst $(PROTO_PATH)/%.cc, $(BUILD_PATH)/%.o, $(SRC_FILE))

CXX ?= g++
CXX_FLAGS ?= -std=c++17 -Wall -Wextra -fPIC -I$(INCLUDE_PATH)

ifeq ($(MODE), DEBUG)
	CXX_FLAGS += -O0 -g
else
	CXX_FLAGS += -O2 -g
endif

mkdir:
ifeq ("$(wildcard $(BUILD_PATH))", "")
	@mkdir $(BUILD_PATH)
	@printf "\033[1;93;49mMAKE DIRECTORY => $(BUILD_PATH)\033[0m\n"
endif

all: mkdir server client
	@printf "\033[1;93;49mCreated server and client.\033[0m\n"

protobuf: $(PROTO_SRC)
	@protoc --cpp_out=$(PROTO_PATH) -I $(PROTO_PATH) $(PROTO_SRC)
	@protoc --grpc_out=$(PROTO_PATH) --plugin=protoc-gen-grpc=$(shell which grpc_cpp_plugin) -I $(PROTO_PATH) $(PROTO_SRC)
	@mv $(CURDIR)/protos/*.h $(INCLUDE_PATH)
	@printf "\033[1;93;49mProtobuf files created.\033[0m\n"

$(BUILD_PATH)/%.o: $(PROTO_PATH)/%.cc
	@$(CXX) -o $@ -c $< $(CXX_FLAGS)
	@printf "\033[1;93;49mCXX => $@\033[0m\n"

server: mkdir protobuf $(OBJ_FILE)
	@$(MAKE) -C $(CURDIR)/src/server -f server.mk all

client: mkdir protobuf $(OBJ_FILE)
	@$(MAKE) -C $(CURDIR)/src/client -f client.mk all

clean:
ifneq ("$(wildcard $(CURDIR)/src/server/build)", "")
	@rm -r $(CURDIR)/src/server/build
endif
ifneq ("$(wildcard $(CURDIR)/src/client/build)", "")
	@rm -r $(CURDIR)/src/client/build
endif
	@printf "\033[1;93;49mBuild folders cleared.\033[0m\n"