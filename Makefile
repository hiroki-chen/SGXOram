SRC_DIR = ./src
BUILD_DIR = ./build
INCLUDE_DIR = ./include
BRANCH = $(shell git rev-parse --abbreb-ref HEAD)
SRC_FILE = $(wildcard $(SRC_DIR)/*.cc)
OBJ_FILE = $(patsubst $(SRC_DIR)/%.cc, $(BUILD_DIR)/%.o, $(SRC_FILE))
TEST_FILE = $(filter-out $(BUILD_DIR)/experiment.o, $(OBJ_FILE))
EOBJ_FILE = $(filter-out $(BUILD_DIR)/main.o, $(OBJ_FILE)) # For experiment
TARGET = $(BUILD_DIR)/Simulator
EXPERIMENT = $(BUILD_DIR)/Experimenter
MODE ?= RELEASE
# OR MODE ?= RELEASE

CXX = clang++
CXXFLAGS = -Wextra -std=c++17 -I$(INCLUDE_DIR) \
			-Wno-sign-compare \
			-Wno-unused-parameter

ifeq ($(MODE), DEBUG)
	CXXFLAGS += -O0 -g
else
	CXXFLAGS += -O2
endif 

.phony: all mk clean test experiment push

mk:
ifeq ("$(wildcard $(BUILD_DIR))", "")
	mkdir -p $(BUILD_DIR)
endif

test: mk $(TEST_FILE)
	$(CXX) -o $(TARGET) $(TEST_FILE)
# $(TARGET) -w 3 -n 27 -r 1 -t 0 -c 2.0 -b 4

experiment: mk $(EOBJ_FILE)
	$(CXX) -o $(EXPERIMENT) $(EOBJ_FILE)
	$(EXPERIMENT)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	@rm -rf $(BUILD_DIR)

push:
ifeq ($(BRANCH), "main")
	@printf "You cannot directly push to main branch.\n"
else
	@git add .
	@echo "Enter some commit information."
	@read line; git commit -m "$$line";
	@echo "Are you sure you want to push to the branch mark? [Y/n]"
	@read line; if [ $$line == "n" ]; then echo "Aborting..."; exit 1; fi;
	@git push origin alpha
endif