#include <iostream>
#include <cmath>
#include <limits.h>
#include <vector>
#include <algorithm>
#include <random>  // std::default_random_engine
#include <chrono>  // std::chrono::system_clock
#include <unordered_map>

#include <gtest/gtest.h>

using namespace std;

// For debugging and testing
// ##############################################################################
void printArr(int* arr, int L) {
  cout << "Array: ";
  for (int i = 0; i < L; i++) {
    cout << arr[i] << " ";
  }
  cout << endl;
}

void printMap(unordered_map<int, int>& m) {
  cout << "[ ";
  for (auto& item : m) {
    cout << item.first << ":" << item.second << " ";
  }
  cout << "]\n";
}
void printVector(vector<int> path) {
  for (auto i : path) std::cout << i << ' ';
  cout << endl;
}

// ###############################################################################

class btree {
 public:
  btree(int* data, int N);
  ~btree();
  void printTree();
  int getHeight();
  int getTotalNodes();
  int getTotalLeaves();
  int readLeaf(int branch);
  vector<int> getPath(int branch);
  unordered_map<int, int>& getPositionMap();  // for test purpose
  int access(int op, int block, int new_data);
  void printData();

 private:
  default_random_engine e;
  vector<int> tree;
  int inputSize;
  int height;
  vector<int> userData;
  unordered_map<int, int> pos_map;
  vector<int> stash;
  unordered_map<int, int> stash_data;

  int getParent(int node);
  int randomPath(int node);
  void initPositionMap();
  int readBucket(int block);
  void writeBucket(int block, int new_data);
};

// template <int listSize>
btree::btree(int* data, int N) {
  unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
  default_random_engine gen(seed);
  e = gen;
  inputSize = N;
  height = ceil(log(inputSize) / log(2)) - 1;

  for (int x = 0; x < inputSize; x++) {
    userData.push_back(data[x]);
  }

  // dummy data
  userData.push_back(INT_MIN);

  for (int i = 0; i < getTotalNodes(); i++) {
    tree.push_back(inputSize);
  }
  for (int i = 0; i < inputSize; i++) {
    tree[i] = i;
  }
  std::shuffle(tree.begin(), tree.end(), e);
  initPositionMap();
}

btree::~btree() { tree.clear(); }

void btree::printTree() {
  cout << "Binary Tree: ";
  for (int i : tree) {
    cout << i << " ";
  }
  cout << endl;
}

int btree::getHeight() { return height; }

int btree::getTotalNodes() { return pow(2, height + 1) - 1; }

int btree::getTotalLeaves() { return pow(2, height) - 1; }

// Changes the branch [0 - no. of leaves] to the actual leaf node [0 - treeSize]
int btree::readLeaf(int branch) { return pow(2, height) + branch - 1; }

// finds a node's parent
int btree::getParent(int node) { return floor((node - 1) / 2.0); }

vector<int> btree::getPath(int branch) {
  vector<int> path;
  for (int i = height; i >= 0; i--) {
    path.push_back(branch);
    branch = getParent(branch);
  }
  return path;
}

int btree::randomPath(int node) {
  std::uniform_int_distribution<int> distr(0, 1);
  int rand = distr(e);
  int child1 = 2 * node + 1;
  int child2 = 2 * node + 2;
  if (child2 > (tree.size() - 1)) {
    int leaves = (pow(2, height) - 1);
    return node - leaves;  // node - no. of leaves
  } else {
    if (rand == 0) {
      return randomPath(child1);
    } else {
      return randomPath(child2);
    }
  }
}

void btree::initPositionMap() {
  for (int i = 0; i < tree.size(); i++) {
    int block = tree[i];

    if (block != inputSize) {
      pos_map[block] = randomPath(i);
    }
  }
}

unordered_map<int, int>& btree::getPositionMap() { return pos_map; }

int btree::readBucket(int block) {
  // cout << "Reading: " << block << endl;
  return userData[block];
}

void btree::writeBucket(int block, int new_data) {
  // cout << "Writing: " << block << " new data: " << new_data << endl;
  userData[block] = new_data;
}

// returns: 0 for write operation and the value at a given block for a read
// operation
int btree::access(int op, int block, int new_data) {
  int noOfLeafs = getTotalLeaves();
  int returnData = 0;  // should be an encrypted data type
  std::uniform_int_distribution<int> distr(0, noOfLeafs - 1);

  // Steps: 1-2
  int x = pos_map[block];
  // cout << "Previous position: " << x << endl;
  pos_map[block] = distr(e);
  // cout << "New position: " << pos_map[block] << endl;

  // Steps 3-5
  int leafNode = readLeaf(x);
  vector<int> path = getPath(leafNode);
  // printVector(path);
  // printTree();

  vector<int> blks;
  for (int i = 0; i <= height; i++) {
    int node = path[i];
    int blk = tree[node];

    if (stash_data.find(blk) == stash_data.end()) {
      stash.push_back(blk);
      blks.push_back(blk);
      stash_data[blk] = readBucket(blk);
      tree[node] = inputSize;
    }
  }

  // Steps 6-9
  if (op == 0) {  // Read operation
    for (auto& x : stash_data) {
      returnData = (x.first == block) ? stash_data[x.first] : returnData;
    }
  } else if (op == 1) {  // Write operation
    for (auto& x : stash_data) {
      stash_data[x.first] = (x.first == block) ? new_data : stash_data[x.first];
    }
  }

  // Steps 10-15
  for (int i = height; i >= 0; i--) {
    int node = path[i];
    int blk = blks[i];
    writeBucket(blk, stash_data[blk]);

    for (int j = 0; j < stash.size(); j++) {
      if (stash[j] == inputSize) {
        stash.erase(stash.begin() + j);
      } else {
        int current_branch = pos_map[stash[j]];
        int x = readLeaf(current_branch);
        vector<int> a = getPath(x);
        if (find(a.begin(), a.end(), node) != a.end()) {
          if (tree[node] == inputSize) {
            tree[node] = stash[j];
            stash.erase(stash.begin() + j);
          }
        }
      }
    }
  }

  if (stash.size() == 0) {
    stash_data.clear();
  } else {
    unordered_map<int, int> temp;
    for (auto x : stash_data) {
      if (find(stash.begin(), stash.end(), x.first) != stash.end())
        temp[x.first] = stash_data[x.first];
    }
    stash_data = temp;
  }

  // cout << "The final stash data: ";
  // // printMap(stash_data);
  // cout << "The final stash: ";
  // // printVector(stash);
  // cout << "The final tree: ";
  // printTree();
  return returnData;
}

void btree::printData() {
  cout << "user data: ";
  for (int i = 0; i < inputSize; i++) cout << userData[i] << ' ';
  cout << endl;
}

int main() {
 
}