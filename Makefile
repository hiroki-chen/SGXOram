SRC_DIR = ./src
BUILD_DIR = ./build
INCLUDE_DIR = ./include
SRC_FILE = $(wildcard $(SRC_DIR)/*.cc)
OBJ_FILE = $(patsubst $(SRC_DIR)/%.cc, $(BUILD_DIR)/%.o, $(SRC_FILE))
TEST_FILE = $(filter-out $(BUILD_DIR)/experiment.o, $(OBJ_FILE))
EOBJ_FILE = $(filter-out $(BUILD_DIR)/main.o, $(OBJ_FILE)) # For experiment
TARGET = $(BUILD_DIR)/Simulator
EXPERIMENT = $(BUILD_DIR)/Experimenter

CXX = g++-11
CXXFLAGS = -Wextra -Werror -Wno-sign-compare -O2 -fPIE -std=c++17 -I$(INCLUDE_DIR) -g

.phony: all mk clean test experiment

mk:
ifeq ("$(wildcard $(BUILD_DIR))", "")
	mkdir -p $(BUILD_DIR)
endif

test: mk $(TEST_FILE)
	$(CXX) -o $(TARGET) $(TEST_FILE)
	$(TARGET) -w 128 -n 10000 -r 100 -t 0 -c 2.1

experiment: mk $(EOBJ_FILE)
	$(CXX) -o $(EXPERIMENT) $(EOBJ_FILE)
	$(EXPERIMENT)


$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR)