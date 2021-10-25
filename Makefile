SRC_DIR = ./src
OBJ_DIR = ./obj
INCLUDE_DIR = ./include
SRC_FILE = $(wildcard $(SRC_DIR)/*.cc)
OBJ_FILE = $(patsubst $(SRC_DIR)/%.cc, $(OBJ_DIR)/%.o, $(SRC_FILE))
TARGET = $(OBJ_DIR)/Simulator

CXX = g++-11
CXXFLAGS = -Wextra -Werror -O0 -fPIE -std=c++17 -I$(INCLUDE_DIR)

.phony: all mk clean

mk:
	mkdir -p $(OBJ_DIR)

all: mk $(OBJ_FILE)
	$(CXX) -o $(TARGET) $(OBJ_FILE)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf ./obj