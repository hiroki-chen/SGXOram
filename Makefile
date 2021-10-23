SRC_DIR = ./src
OBJ_DIR = ./obj
INCLUDE_DIR = ./include
SRC_FILE = $(wildcard $(SRC_DIR)/*.cc)
OBJ_FILE = $(patsubst $(SRC_DIR)/%.cc, $(OBJ_DIR)/%.o, $(SRC_FILE))
TARGET = $(OBJ_DIR)/Simulator

CXX = g++-11
CXXFLAGS = -Wextra -Werror -O2 -fPIE -std=c++11 -I$(INCLUDE_DIR)

.phony: all mk

mk:
	mkdir -p $(OBJ_DIR)

all: mk $(OBJ_FILE)
	$(CXX) -o $(TARGET) $(OBJ_FILE)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<
