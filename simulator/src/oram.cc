/*
 Copyright (c) 2021 Haobin Chen

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// FIXED: When the size of each slot is sufficient, the data stored in the slot
// will disappear?...
// FIXME: When the size of each slot is insufiicient, S2 will be full...

#include <plog/Appenders/ColorConsoleAppender.h>
#include <plog/Formatters/TxtFormatter.h>
#include <plog/Initializers/RollingFileInitializer.h>
#include <plog/Log.h>
#include <plog/Logger.h>

static plog::RollingFileAppender<plog::TxtFormatter> file_appender(
    "./log/oram.log");  // Create the 1st appender.
static plog::ColorConsoleAppender<plog::TxtFormatter>
    consoler_appender;  // Create the 2nd appender.

#include <chrono>
#include <climits>
#include <cmath>  // WARNING: FOR CLANG ON MACOS CATALINA OR HIGHER, CMATH IS CORRUPTED...
#include <models.hh>
#include <random>
#include <utils.hh>

// https://stackoverflow.com/a/45300654/14875612 <- C++ console color.

sgx_oram::Position::Position(const uint32_t& level_cur, const uint32_t& offset,
                             const uint32_t& bid_cur, const uint32_t& bid_dst)
    : level_cur(level_cur),
      offset(offset),
      bid_cur(bid_cur),
      bid_dst(bid_dst) {}

sgx_oram::Block::Block(const bool& is_dummy, const std::string& data,
                       const uint32_t& bid, const uint32_t& address)
    : is_dummy(is_dummy), data(data), bid(bid), address(address) {}

sgx_oram::Oram::Oram(const Config& config)
    : constant(config.constant),
      p(config.p),
      level(1 + std::ceil(std::log(config.real_block_num) / std::log(p))),
      block_number((uint32_t)(std::pow(p, level - 1))),
      real_block_num(config.real_block_num),
      verbose(config.verbose),
      round(config.round),
      type(config.type) {
  init_oram();
}

sgx_oram::Oram::Oram(const cxxopts::ParseResult& result)
    : constant(result["constant"].as<double>()),
      p(result["way"].as<uint32_t>())
      // , level(1 + std::ceil(std::log(result["number"].as<uint32_t>()) /
      // std::log(p))) // \log_{p}{N} = \log_{N} / \log_{p}
      ,
      block_number(result["number"].as<uint32_t>()),
      verbose(result["verbose"].as<bool>()),
      round(result["round"].as<uint32_t>()),
      type(result["type"].as<uint32_t>()),
      data_file(
          new std::ifstream(result["file"].as<std::string>(), std::ios::in)),
      bucket_size(result["bucket-size"].as<uint32_t>()) {
  const uint32_t all_blocks = 2 * block_number;
  const uint32_t bucket_number = std::ceil(all_blocks * 1.0 / bucket_size);
  level = 1 + std::ceil(std::log(bucket_number) / std::log(p));

  if (verbose) {
    plog::init(plog::debug, &file_appender).addAppender(&consoler_appender);
  }

  init_oram();
}

void sgx_oram::Oram::init_slot(void) {
  LOG(plog::info) << "The ORAM controller is initializing the SGX storage tree "
                     "level by level...";

  uint32_t sgx_size = 0;
  uint32_t cur_size = 1;

  // We traverse from the root to the leaf.
  for (uint32_t i = 0; i <= level; i++) {
    // How many slots are there at the current level.
    const uint32_t cur_slot_num = (uint32_t)(std::pow(p, i));
    // Cumulative size of the slot size.
    if (type == 0) {
      cur_size *= (uint32_t)(std::ceil(std::min(p, i + 1) * constant));
    } else if (type == 1) {
      cur_size = p;
    } else if (type == 2) {
      cur_size = (uint32_t)(std::ceil(std::pow(p, level - i) * constant));
    }

    // Calculate the total size at current level.
    sgx_size += cur_size * cur_slot_num;
    level_size_information.push_back(cur_size);
  }

  // std::cout << "The size of the SGX tree is " << sgx_size;

  // Although we mark the leaf level as 1, for computational convernience, we
  // still traverse from 0 to L - 1, i.e., from root to leaf.
  for (uint32_t i = 0; i < level; i++) {
    const uint32_t slot_num_cur = (uint32_t)std::pow(p, i);
    std::vector<Slot> slot_vec;
    for (uint32_t j = 0; j < slot_num_cur; j++) {
      // Set basic information for the slot.
      // Note that the range is bigger when the node is closer to the root!
      const uint32_t level_size = (uint32_t)(std::pow(p, level - 1 - i));
      const uint32_t begin = j * level_size;
      const uint32_t end = begin + level_size - 1;  // Starts at 0.
      const uint32_t slot_size =
          (i == level - 1 ? bucket_size : level_size_information[i]);
      Slot slot(slot_size + 1);
      slot.set_level(i);
      slot.set_range(begin, end);
      slot_vec.emplace_back(std::move(slot));
    }
    slots.emplace_back(std::move(slot_vec));
    // LOG(plog::debug) << i << ": " << slots[i][0].size();
  }

  LOG(plog::info) << "The ORAM has initialized the SGX storage tree.";
}

void sgx_oram::Oram::init_sgx(std::vector<Block>& blocks) {
  LOG(plog::info) << "The ORAM controller is loading the SGX data...";

  const uint32_t leaf_num = (uint32_t)(std::pow(p, level - 1));
  uint32_t i = 0, j = 0;

  while (i != blocks.size()) {
    Block block = blocks[i];
    const uint32_t offset = (uint32_t)(std::floor(j * 1.0 / leaf_num));
    const auto range = slots[level - 1][j % leaf_num].range;

    // Initialize the position map.
    bucket_fullness[range.first]++;
    position_map[block.address].level_cur = level - 1;
    position_map[block.address].offset = offset;
    block.bid = position_map[block.address].bid_cur =
        uniform_random(range.first, range.second);

    slots[level - 1][j % leaf_num].add_block(block, offset);
    i++;
    j++;
  }

  LOG(plog::info) << "The ORAM controller has initialized the SGX data.";
  if (verbose) {
    print_sgx();
  }
}

void sgx_oram::Oram::print_sgx(void) {
  for (uint32_t i = 0; i < slots.size(); i++) {
    LOG(plog::debug) << "LEVEL " << i << ": ";
    for (uint32_t j = 0; j < slots[i].size(); j++) {
      LOG(plog::debug) << slots[i][j];
    }
  }
}

void sgx_oram::Oram::oram_access(const bool& op, const uint32_t& address,
                                 std::string& data) {
  // Read the position from the position map.
  const Position position = position_map[address];
  const uint32_t bid_cur = position.bid_cur;
  const uint32_t level_cur = position.level_cur;

  for (int i = level - 2; i >= 0; i--) {
    // ObliAccessS1.
    Slot& s1 = get_slot(bid_cur, i + 1);
    const Block data1 =
        obli_access_s1(op, (level_cur == i + 1), s1, data, i + 1, position);
    // ObliAccessS2.
    Slot& s2 = get_slot(bid_cur, i);
    const Block data2 =
        obli_access_s2(op, (level_cur == i), s2, data1, data, i, position);

    // ObliAccessS3.
    uint32_t rbid;
    if (data2.is_dummy == true) {
      rbid = uniform_random(s2.range.first, s2.range.second);
    } else {
      rbid = data2.bid;
    }
    // LOG(plog::info) << "rbid:" << rbid;
    Slot& s3 = get_slot(rbid, i + 1);
    // LOG(plog::debug) << "before: dummy_num: " << s3.dummy_number << " for
    // range " << s3.range.first << ", " << s3.range.second;
    obli_access_s3(rbid, data2, s3, i + 1, position);
  }
}

sgx_oram::Slot& sgx_oram::Oram::get_slot(const uint32_t& bid,
                                         const uint32_t& level_cur) {
  const uint32_t offset_level =
      std::floor((bid * 1.0 / std::pow(p, level - level_cur - 1)));
  return slots[level_cur][offset_level];
}

void sgx_oram::Oram::set_slot(const uint32_t& bid, const uint32_t& level_cur,
                              const Slot& slot) {
  const uint32_t offset_level =
      std::floor((bid * 1.0 / std::pow(p, level - level_cur - 1)));
  slots[level_cur][offset_level] = slot;
}

sgx_oram::Block sgx_oram::Oram::obli_access_s1(const bool& op, const bool& flag,
                                               Slot& slot, std::string& data,
                                               const uint32_t& level,
                                               const Position& position) {
  if (verbose) {
    LOG(plog::debug) << "\033[1;97;40mInvoking ObliAccessS1...\033[0m";
  }

  const uint32_t offset = position.offset;

  Block data1(true), data2(true);
  bool find = false;
  // Case 1: Find a block that is required.
  for (uint32_t i = 0; i < slot.storage.size(); i++) {
    if (flag == true && i == offset &&
        slot.storage[i].is_dummy == false /* Necessary condition */) {
      const uint32_t nbid = uniform_random(0, block_number - 1);
      // LOG(plog::info) << "nbid: " << nbid;
      data1 = slot.storage[i];
      data1.bid = nbid;
      data = data1.data;
      slot.dummy_number++;
      slot.storage[i].is_dummy = true;

      return data1;
    }
  }

  // Case 2: Find a block that should be evicted.
  for (uint32_t i = 0; i < slot.storage.size(); i++) {
    if (slot.storage[i].is_dummy == false && !slot.in(slot.storage[i].bid)) {
      find = true;
      data2 = slot.storage[i];
      slot.storage[i].is_dummy = true;
      slot.dummy_number++;

      return data2;
    }
  }

  return data2;
}

// I believe that we should do extra care about the operation for the slot S2;
// S2 is easily full.
sgx_oram::Block sgx_oram::Oram::obli_access_s2(const bool& op, const bool& flag,
                                               Slot& slot, const Block& data1,
                                               std::string& data,
                                               const uint32_t& level_cur,
                                               const Position& position) {
  if (verbose) {
    LOG(plog::debug) << "\033[1;97;40mInvoking ObliAccessS2...\033[0m";
  }

  // Prepare data2.
  Block data2(true);

  // Read position
  const uint32_t offset = position.offset;

  bool find = false;

  for (uint32_t i = 0; i < slot.storage.size(); i++) {
    // Step 1: read a data and give it to the client.
    if (flag == true && i == offset && slot.storage[i].is_dummy == false) {
      data = slot.storage[i].data;
      const uint32_t bid_cur =
          uniform_random(slot.range.first, slot.range.second);
      position_map[slot.storage[i].address].bid_cur = bid_cur;
    }
  }

  // Step 2 (modified): Randomly choose a block.
  uint32_t pos_data2 = uniform_random(0, slot.storage.size() - 1);
  for (uint32_t i = 0; i < slot.storage.size(); i++) {
    if (i == pos_data2 && slot.storage[i].is_dummy == false) {
      data2 = slot.storage[i];
      slot.storage[i].is_dummy = true;
      slot.dummy_number++;
    }
  }

  if (slot.dummy_number == 0) {
    throw std::runtime_error("The slot is full in S2!");
  }

  // Generate a random position for data1 (either dummy or real).
  uint32_t pos_for_data1 = uniform_random(1, slot.dummy_number);
  // Iterate over the slot.
  for (uint32_t i = 0; i < slot.storage.size(); i++) {
    // Step 3: write data1 to the slot according to the given position.
    if ((pos_for_data1 -= slot.storage[i].is_dummy) == 0) {
      // Prevent wrongly write to the block.
      pos_for_data1 = UINT_MAX;
      slot.storage[i] = data1;
      if (data1.is_dummy == false) {
        // Generate a random bid_cur.
        const uint32_t bid_cur =
            uniform_random(slot.range.first, slot.range.second);
        position_map[data1.address].offset = i;
        position_map[data1.address].bid_cur = bid_cur;
        position_map[data1.address].level_cur = level_cur;

        slot.dummy_number--;
      }
    }
  }

  if (verbose) {
    LOG(plog::debug) << "\033[1;97;40mObliAccessS2 finished.\033[0m";
  }

  return data2;
}

void sgx_oram::Oram::obli_access_s3(const uint32_t& rbid, const Block& data2,
                                    Slot& slot, const uint32_t& level_cur,
                                    const Position& position) {
  if (verbose) {
    LOG(plog::debug) << "\033[1;97;40mInvoking ObliAccessS3...\033[0m";
  }

  // LOG(plog::debug) << "after: dummy_num: " << slot.dummy_number << " for
  // range " << slot.range.first << ", " << slot.range.second;
  if (slot.dummy_number == 0 && data2.is_dummy == false) {
    throw std::runtime_error("The slot is full in S3!");
  }

  // Genereate a bid for ORAM dummy read.
  const uint32_t rbid1 = uniform_random(slot.range.first, slot.range.second);

  uint32_t pos_for_data2 = uniform_random(1, slot.dummy_number);
  for (uint32_t i = 0; i < slot.storage.size(); i++) {
    // Find an empty place
    if ((pos_for_data2 -= slot.storage[i].is_dummy) == 0) {
      pos_for_data2 = UINT_MAX;
      slot.storage[i] = data2;

      if (data2.is_dummy == false) {
        // Generate a random bid_cur.
        const uint32_t bid_cur =
            uniform_random(slot.range.first, slot.range.second);
        position_map[data2.address].offset = i;
        position_map[data2.address].bid_cur = bid_cur;
        position_map[data2.address].level_cur = level_cur;

        slot.dummy_number--;
      }
    }
  }

  for (uint32_t i = level_cur; i < level - 1; i++) {
    std::string dummy;
    // ObliAccessS1.
    Slot& s1 = get_slot(rbid1, i + 1);
    const Block ndata1 = obli_access_s1(0, 0, s1, dummy, i + 1, position);
    // ObliAccessS2.
    Slot& s2 = get_slot(rbid1, i);
    const Block ndata2 = obli_access_s2(0, 0, s2, ndata1, dummy, i, position);

    // ObliAccessS3.
    uint32_t rbid2;
    if (ndata2.is_dummy == true) {
      rbid2 = uniform_random(s2.range.first, s2.range.second);
    } else {
      rbid2 = ndata2.bid;
    }

    Slot& s3 = get_slot(rbid2, i + 1);
    obli_access_s3(rbid2, ndata2, s3, i + 1, position);
  }

  if (verbose) {
    LOG(plog::debug) << "\033[1;97;40mObliAccessS3 finished.\033[0m";
  }
}

void sgx_oram::Oram::run_test(void) {
  std::ofstream out("./output.txt", std::ios::app);
  out << "[Experiment setting] "
      << "way: " << p << ", number: " << block_number
      << ", bucket_size: " << bucket_size << ", level: " << level
      << "round: " << round << std::endl;

  auto begin = std::chrono::high_resolution_clock::now();
  LOG(plog::warning) << "Experiment started!";

  for (uint32_t r = 0; r < round; r++) {
    for (uint32_t i = 0; i < block_number; i++) {
      try {
        Block b(true);
        // Generate lexicongraphic order for the root slot.
        Slot& root = get_slot(0, 0);
        const uint32_t order = root.last_eviction_order;
        std::vector<uint32_t> lexicon_order = to_p_nary(order, p, level);
        root.last_eviction_order =
            (root.last_eviction_order + 1) % (uint32_t)(std::pow(p, level));
        auto res = std::move(
            oram_access(0, i, b, 0, position_map[i].bid_cur, lexicon_order));

        if (res.data != data[i]) {
          // std::cout << res.data << ", " << data[i] << std::endl;
          // std::cout << "data not correct.\n";
          exit(1);
        }
      } catch (const std::runtime_error& e) {
        LOG(plog::error) << e.what();
        LOG(plog::info) << "Error happened at round: "
                        << (uint32_t)(std::ceil(i * 1.0 / block_number));
        out << "Error happened at round: "
            << (uint32_t)(std::ceil(i * 1.0 / block_number));
        exit(1);
      }
      // print_sgx();
    }
  }

  auto end = std::chrono::high_resolution_clock::now();

  // Print time.
  LOG(plog::warning) << "Access finished, time elapsed: "
                     << std::chrono::duration<double>(end - begin).count()
                     << " s";
  out << "Access finished, time elapsed: "
      << std::chrono::duration<double>(end - begin).count() << " s"
      << std::endl;
}

void sgx_oram::Oram::init_oram(void) {
  LOG(plog::info) << "\033[1;36;97m ORAM information: "
                  << "p: " << p << " real_num: " << block_number
                  << " constant: " << constant << " level: " << level
                  << "\033[0m" << std::endl;

  if (data_file != nullptr && data_file->good()) {
    PLOG(plog::info) << "Detected input file.";
    data = get_data_from_file(data_file);
  } else {
    PLOG(plog::info) << "Generating random strings as input data";
    data = std::move(generate_random_strings(block_number, 32));
  }

  // Convert to the block vector and initialize the oram controller.
  std::vector<Block> blocks = std::move(convert_to_blocks(data));

  // Initilize the slot level by level.
  init_slot();

  init_sgx(blocks);

  // Print out the bucket_fullness.
  for (auto item : bucket_fullness) {
    LOG(plog::debug) << item.first << ", " << item.second;
  }

  // If there is no input file, we generate random data.
  PLOG(plog::info) << "The ORAM controller is initialized!";
}

// FIXME: Reverse lexicongrahic eviction makes write operation fail... Find out
// why.
sgx_oram::Block sgx_oram::Oram::oram_access(
    const bool& op, const uint32_t& u, Block& data, const uint32_t& level_cur,
    const uint32_t& bid, std::vector<uint32_t> lexicon_order) {
  // Mechanism behind the access:
  // 1. For read operation, we will generate a new eviction_order based on the
  //    variable in each slot, called "last_eviction_order". Fetch the slot
  //    given the bid and the level.
  // 2. For write operation, we should re-use the lexicon_order (which is
  //    generated by higher level), but we will only pop one number back from
  //    the vector (since we use this number reserve-lexicongraphically).
  // Note that if the current ORAM is on the write path of its predecessor, then
  // it should follow the eviction rule specified by the parent; otherwise it
  // will generate a new eviction order.

  Slot& slot = get_slot(bid, level_cur);
  // Generate a random position for the incoming block.
  uint32_t r = uniform_random(1, slot.dummy_number);
  // Generate a random new bid for the accessed block. Non-full.
  uint32_t nbid = uniform_random(0, (uint32_t)std::pow(p, level - 1) - 1);
  // Generate a new lexicongraphic order. (In p-nary number:))
  std::vector<uint32_t> lexicon_order_cur =
      std::move(to_p_nary(slot.last_eviction_order, p, level - level_cur));

  // LOG(plog::error) << slot.last_eviction_order;

  // Prevent bucket overflow.
  if (u != UINT_MAX) {
    while (bucket_fullness[nbid] == bucket_size) {
      nbid = uniform_random(0, (uint32_t)std::pow(p, level - 1) - 1);
    }
  }

  // Fetch all the blocks from the slot.
  std::vector<Block>& storage = slot.storage;

  // If the current level is a leaf node.
  if (level_cur == level - 1) {
    // Create a dummy block to be returned to the upper level.
    Block block_ret(true);
    // This is a real read; else we do nothing and return a dummy block.
    if (u != UINT_MAX) {
      // Check if the leaf node is full.
      if (slot.dummy_number == 0) {
        throw std::runtime_error("The leaf node is full!");
      }
      // First we only handle read.
      for (Block& block : storage) {
        if (block.address == u && block.is_dummy == false && op == 0) {
          // Handle read type.
          data = block;
          block_ret = block;
          block_ret.bid = nbid;
          block_ret.view_only = false;
          block.is_dummy = true;
          slot.dummy_number++;
          bucket_fullness[slot.range.first]--;
        }
      }

      // Second we only handle write.
      for (Block& block : storage) {
        // A block data can be written to the current position iff. current
        // position is dummy and the data is not a dummy block. Once the data is
        // in the leaf slot, then view_only should be false.
        if (block.is_dummy == true && data.is_dummy == false && op == 1) {
          block = data;
          block.view_only = false;
          bucket_fullness[slot.range.first]++;
          slot.dummy_number--;
          position_map[data.address].bid_cur = slot.range.first;
          break;
        }
      }
    }

    return block_ret;
  }

  // If the current node is not a leaf node.
  // We try to read from the slot or the next level.
  Block block(true);
  if (u != UINT_MAX) {
    // If we found a block in the slot, then in_slot = true, and then a dummy
    // read will be invoked.
    bool in_slot = false;
    for (Block& b : storage) {
      // Case 1: The target block is in the slot.
      if (b.address == u && b.is_dummy == false) {
        Block none(true);
        oram_access(0, UINT_MAX, none, level_cur + 1, bid,
                    /* lexicon_order_cur */ {});
        in_slot = true;
        block = b;
        b.is_dummy = true;
        slot.dummy_number++;
      }
    }

    // Case 2: The target block is not in the slot, we read it from the next
    // level.
    if (in_slot == false) {
      block = oram_access(0, u, data, level_cur + 1, bid,
                          /* lexicon_order_cur */ {});
    }
    block.bid = nbid;

    // Read a bock.
    if (op == 0) {
      data = block;

      // LOG(plog::error) << "nbid: " << block.bid;
      if (slot.in(block.bid) && block.view_only == false &&
          block.is_dummy == false) {
        // Find a position.
        for (uint32_t i = 0; i < storage.size(); i++) {
          if ((r -= storage[i].is_dummy) == 0) {
            storage[i] = block;
            const uint32_t bid_cur =
                uniform_random(slot.range.first, slot.range.second);
            position_map[data.address].bid_cur = bid_cur;
            slot.dummy_number--;

            // By setting view_only = true, we mark this block as
            // non-transferrable.
            block.view_only = true;
            break;
          }
        }
      }
    } else {
      // A read write. We read a possibly (dummy) block from the next level.
      if (data.is_dummy == false) {
        auto res = oram_access(0, data.address, block, level_cur + 1, bid,
                               /* lexicon_order_cur */ {});
        res = data;
        // res.bid = nbid;

        for (uint32_t i = 0; i < storage.size(); i++) {
          if ((r -= storage[i].is_dummy) == 0) {
            storage[i] = res;
            storage[i].view_only = false;

            const uint32_t bid_cur =
                uniform_random(slot.range.first, slot.range.second);
            position_map[data.address].bid_cur = bid_cur;
            slot.dummy_number--;

            break;
          }
        }
      }
    }
  }

  // Call eviction.
  // Eviction will be based on the lexicongraphic order given by the higher
  // level.
  uint32_t next_slot_id = 0;
  const bool free_order = lexicon_order.empty();
  if (!free_order) {
    next_slot_id = lexicon_order.back();
    lexicon_order.pop_back();
  } else {
    // Use its own.
    slot.last_eviction_order = (slot.last_eviction_order + 1) %
                               (uint32_t)std::pow(p, level - level_cur);
    next_slot_id = lexicon_order_cur.back();
    lexicon_order_cur.pop_back();
  }
  // Find the next slot.
  //      S
  // /  / | \ \
  // S S S S S S
  // Calculate the range of the next selected slot.
  const uint32_t next_slot_begin =
      slot.range.first + std::pow(p, level - level_cur - 2) * next_slot_id;
  const uint32_t next_slot_end =
      next_slot_begin + std::pow(p, level - level_cur - 2) - 1;

  // std::cout << next_slot_begin << ", " << next_slot_end << std::endl;
  const uint32_t random_evict = uniform_random(next_slot_begin, next_slot_end);

  // Pick a block whose bid is in the range of the next slot.
  bool found = false;
  for (uint32_t i = 0; i < storage.size(); i++) {
    if (next_slot_begin <= storage[i].bid && storage[i].bid <= next_slot_end &&
        storage[i].is_dummy == false) {
      Block block = storage[i];

      found = true;

      LOG(plog::debug) << "At level " << level_cur << ", evicting "
                       << block.address;

      storage[i].is_dummy = true;
      slot.dummy_number++;
      oram_access(1, block.address, block, level_cur + 1, block.bid,
                  free_order ? lexicon_order_cur : lexicon_order);
      break;
    }
  }

  // If there is no such block in current slot, we should evict a dummy block to
  // the next level.
  if (!found) {
    Block block(true);
    oram_access(1, UINT_MAX, block, level_cur + 1, random_evict,
                free_order ? lexicon_order_cur : lexicon_order);
  }

  /*uint32_t to_evict = uniform_random(1, storage.size());
  for (uint32_t i = 0; i < storage.size(); i++) {
    if ((--to_evict) == 0) {
      Block block = storage[i];

      // Evict a dummy block.
      if (block.is_dummy == true) {
        const uint32_t random_branch =
            uniform_random(slot.range.first, slot.range.second);
        oram_access(1, UINT_MAX, block, level_cur + 1, random_branch);
      } else {
        LOG(plog::debug) << "At level " << level_cur << ", evicting "
                         << block.address;
        storage[i].is_dummy = true;
        slot.dummy_number++;
        oram_access(1, block.address, block, level_cur + 1, block.bid);
      }
      break;
    }
  }*/

  return block;
}