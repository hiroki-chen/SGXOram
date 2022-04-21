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

SRC_PATH := $(CURDIR)
BUILD_PATH := ../../build/client
COMMON_INCLUDE_PATH := ../../include
CLIENT_INCLUDE_PATH := $(COMMON_INCLUDE_PATH)/client
KEY_PATH := ../../key
MODE ?= DEBUG
LIB_PATH := ../../lib
GRPC_PATH := /usr/local

SRC_FILE := $(wildcard $(SRC_PATH)/*.cc)
OBJ_FILE := $(patsubst $(SRC_PATH)/%.cc, $(BUILD_PATH)/%.o, $(SRC_FILE))
PROTO_OBJ :=  $(wildcard ../../build/proto/*.o)
APP_NAME := $(BUILD_PATH)/../bin/client.bin

CXX ?= g++
CXX_FLAGS ?= -std=c++17 -Wall -Wextra -fPIC -I$(COMMON_INCLUDE_PATH) -I$(CLIENT_INCLUDE_PATH) -DSUPPLIED_KEY_DERIVATION
CXX_LINK_FLAGS ?= -L$(LIB_PATH) -lsample_libcrypto -lservice_provider\
								  -L$(GRPC_PATH)/lib `pkg-config --libs protobuf grpc++`\
									-pthread\
									-Wl,--no-as-needed -lgrpc++_reflection -Wl,--as-needed\
									-ldl -lgflags -lsodium
									
ifeq ($(MODE), DEBUG)
	CXX_FLAGS += -O0 -g
else
	CXX_FLAGS += -O2 -g
endif

.PHONY: all mkdir

mkdir:
ifeq ("$(wildcard $(BUILD_PATH))", "")
	@mkdir -p $(BUILD_PATH)
	@printf "\033[1;93;49mMAKE DIRECTORY => $(BUILD_PATH).\033[0m\n"
endif

all: mkdir $(APP_NAME)
	@printf "\033[1;93;49mClient created.\033[0m\n"

$(APP_NAME): $(OBJ_FILE) $(PROTO_OBJ)
	@$(CXX) $^ $(CXX_LINK_FLAGS) -o $@ 
	@printf "\033[1;93;49mLINK => $@\033[0m\n"

$(BUILD_PATH)/%.o: $(SRC_PATH)/%.cc
	@$(CXX) -o $@ -c $< $(CXX_FLAGS)
	@printf "\033[1;93;49mCXX => $@\033[0m\n"