SRC_DIR = ./src
OBJ_DIR = ./obj
INCLUDE_DIR = ./include
SRC_FILE = $(wildcard $(SRC_DIR)/*.cc)
OBJ_FILE = $(patsubst $(SRC_DIR)/%.cc, $(OBJ_DIR)/%.o, $(SRC_FILE))
TARGET = $(OBJ_DIR)/Simulator

CXX = g++-11
CXXFLAGS = -Wextra -Werror -Wno-sign-compare -O2 -fPIE -std=c++17 -I$(INCLUDE_DIR)

.phony: all mk clean test

mk:
ifeq ("$(wildcard $(OBJ_DIR))", "")
	mkdir -p $(OBJ_DIR)
endif

test: all
	$(TARGET) -w 3 -n 9 -r 10 -c 2

all: mk $(OBJ_FILE)
	$(CXX) -o $(TARGET) $(OBJ_FILE)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf ./obj