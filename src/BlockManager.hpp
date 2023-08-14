// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINXBLOCKMANAGER_HPP
#define SPHINXBLOCKMANAGER_HPP

#pragma once

#include <stdexcept>
#include <fstream> 
#include <iostream>
#include <ctime>
#include <string>
#include <vector>
#include <array>
#include <map>

namespace SPHINXBlock {
    class Block; // Forward declaration of the Block class
}

namespace SPHINXDb {
    class DistributedDb; // Forward declaration of the DistributedDb class
}

namespace SPHINXBlockManager {

    // Function declarations
    bool createAndMineBlock(uint32_t version, const std::string& previousHash, uint32_t difficulty, const std::vector<std::string>& transactions);
    SPHINXBlock::Block createBlockWithVersion(const std::string& previousHash, uint32_t version, const std::vector<std::string>& transactions);
    void setBlockHeaders(SPHINXBlock::Block& block, uint32_t height, uint32_t nonce, uint32_t difficulty);
    bool mineBlock(SPHINXBlock::Block& blockToMine, uint32_t difficulty);
    bool verifyBlock(const SPHINXBlock::Block& block, const SPHINXPubKey& publicKey);
    bool saveBlockToFile(const SPHINXBlock::Block& block, const std::string& filename);
    SPHINXBlock::Block loadBlockFromFile(const std::string& filename);
    bool saveBlockToDatabase(const SPHINXBlock::Block& block, SPHINXDb::DistributedDb& distributedDb);
    SPHINXBlock::Block loadBlockFromDatabase(const std::string& blockId, SPHINXDb::DistributedDb& distributedDb);

    // Forward declaration of SPHINXPubKey
    class SPHINXPubKey;

    // Function to create a new block with specified version
    SPHINXBlock::Block createBlockWithVersion(const std::string& previousHash, uint32_t version, const std::vector<std::string>& transactions);

    // Function to set block headers like timestamp, height, nonce, etc.
    void setBlockHeaders(SPHINXBlock::Block& block, uint32_t height, uint32_t nonce, uint32_t difficulty);

    // Function to mine a block with the given difficulty and add it to the blockchain
    bool mineBlock(SPHINXBlock::Block& blockToMine, uint32_t difficulty);

    // Function to verify the entire block with the given public key
    bool verifyBlock(const SPHINXBlock::Block& block, const SPHINXPubKey& publicKey);

    // Function to save a block to a file
    bool saveBlockToFile(const SPHINXBlock::Block& block, const std::string& filename);

    // Function to load a block from a file
    SPHINXBlock::Block loadBlockFromFile(const std::string& filename);

    // Function to save a block to a distributed database
    bool saveBlockToDatabase(const SPHINXBlock::Block& block, SPHINXDb::DistributedDb& distributedDb);

    // Function to load a block from a distributed database
    SPHINXBlock::Block loadBlockFromDatabase(const std::string& blockId, SPHINXDb::DistributedDb& distributedDb);

} // namespace SPHINXBlockManager

#endif // SPHINXBLOCKMANAGER_HPP

