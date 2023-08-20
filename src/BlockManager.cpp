// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// This structure helps to separate concerns and provides a clear interface for interacting with blocks, mining, verification, saving, and
// loading.
// Here's a brief overview of each function in the SPHINXBlockManager namespace:

    // createAndMineBlock: Creates a new block with the specified version, adds transactions to it, sets block headers, mines the block,
    // and saves it to a database if mining is successful.

    // createBlockWithVersion: Creates a new block with the specified version, adds transactions to it, and returns the block object.

    // setBlockHeaders: Sets various block headers like height, nonce, and difficulty for a given block.

    // mineBlock: Calls the block's mineBlock method to attempt to mine the block with the given difficulty. Returns true if mining succeeds.

    // verifyBlock: Calls the block's verifyBlock method to verify the block's integrity using a given public key.

    // saveBlockToFile: Calls the block's save method to save the block's data to a file.

    // loadBlockFromFile: Calls the static load method of the Block class to load a block from a file.

    // saveBlockToDatabase: Calls the block's saveToDatabase method to save the block's data to a distributed database.

    // loadBlockFromDatabase: Calls the static loadFromDatabase method of the Block class to load a block from a distributed database.

// This organization provides a clear structure and separation of concerns, making code more modular and easier to understand and maintain.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


#include <stdexcept>
#include <fstream> 
#include <iostream>
#include <ctime>
#include <string>
#include <vector>
#include <array>
#include <map>

#include "blockmanager.hpp"
#include "block.hpp"
#include "db.hpp"


namespace SPHINXBlockManager {

    // Function to create and mine a new block
    bool createAndMineBlock(uint32_t version, const std::string& previousHash, uint32_t difficulty, const std::vector<std::string>& transactions) {
        SPHINXBlock::Block newBlock(previousHash, version);

        for (const auto& transaction : transactions) {
            newBlock.addTransaction(transaction);
        }

        // Set other block headers
        setBlockHeaders(newBlock, 0, 0, difficulty);

        // Mine the block
        if (mineBlock(newBlock, difficulty)) {
            // Save the mined block to file or database
            saveBlockToDatabase(newBlock, distributedDb);
            return true;
        }

        return false; // Block mining failed
    }

    // Function to create a new block with specified version
    SPHINXBlock::Block createBlockWithVersion(const std::string& previousHash, uint32_t version, const std::vector<std::string>& transactions) {
        SPHINXBlock::Block newBlock(previousHash, version);

        for (const auto& transaction : transactions) {
            newBlock.addTransaction(transaction);
        }

        return newBlock;
    }

    // Function to set block headers like timestamp, height, nonce, etc.
    void setBlockHeaders(SPHINXBlock::Block& block, uint32_t height, uint32_t nonce, uint32_t difficulty) {
        block.setBlockHeight(height);
        block.setNonce(nonce);
        block.setDifficulty(difficulty);
    }

    // Function to mine a block with the given difficulty and add it to the blockchain
    bool mineBlock(SPHINXBlock::Block& blockToMine, uint32_t difficulty) {
        if (blockToMine.mineBlock(difficulty)) {
            // Block mined successfully
            return true;
        }

        return false; // Block mining failed
    }

    // Function to verify the entire block with the given public key
    bool verifyBlock(const SPHINXBlock::Block& block, const SPHINXPubKey& publicKey) {
        return block.verifyBlock(publicKey);
    }

    // Function to save a block to a file
    bool saveBlockToFile(const SPHINXBlock::Block& block, const std::string& filename) {
        return block.save(filename);
    }

    // Function to load a block from a file
    SPHINXBlock::Block loadBlockFromFile(const std::string& filename) {
        return SPHINXBlock::Block::load(filename);
    }

    // Function to save a block to a distributed database
    bool saveBlockToDatabase(const SPHINXBlock::Block& block, SPHINXDb::DistributedDb& distributedDb) {
        return block.saveToDatabase(distributedDb);
    }

    // Function to validate a block before adding it to the blockchain
    bool validateBlock(const SPHINXBlock::Block& block) {
        // Check if the block's previous hash matches the hash of the last block in the blockchain
        if (blockchain_->getLastBlockHash() == block.getPreviousHash()) {
            // Verify the block's signature and Merkle root
            if (block.verifyBlock()) {
                return true; // Block is valid
            } else {
                // Invalid block
                return false;
            }
        } else {
            // Block's previous hash doesn't match
            return false;
        }
    }

    // Function to load a block from a distributed database
    SPHINXBlock::Block loadBlockFromDatabase(const std::string& blockId, SPHINXDb::DistributedDb& distributedDb) {
        return SPHINXBlock::Block::loadFromDatabase(blockId, distributedDb);
    }
} // namespace SPHINXBlockManager
