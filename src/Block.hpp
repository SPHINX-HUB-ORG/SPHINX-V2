// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINXBLOCK_HPP
#define SPHINXBLOCK_HPP

#pragma once

#include <cstdint>
#include <iostream>
#include <unordered_map>

#include <stdexcept>
#include <fstream> 
#include <iostream>
#include <ctime>
#include <string>
#include <vector>
#include <array>

#include "json.hh"
#include "Params.hpp"
#include "MerkleBlock.hpp"


using json = nlohmann::json;

// Add the appropriate namespace for the MerkleBlock
using namespace SPHINXMerkleBlock;

// Forward declarations
namespace SPHINXTrx {
    class Transaction; // Forward declaration of the Transaction class
}

// Forward declarations
namespace SPHINXChain {
    class Chain; // Forward declaration of the Chain class
}

// Forward declarations
namespace SPHINXDb {
    class DistributedDb; // Forward declaration of the DistributedDb class
}

namespace SPHINXBlock {
    class Block {
    private:
        // Private member variables
        std::string previousHash_;
        std::string merkleRoot_;
        std::string signature_;
        uint32_t blockHeight_;
        std::time_t timestamp_;
        uint32_t nonce_;
        uint32_t difficulty_;
        uint32_t version_; // Add this private member variable to store the version of the block
        std::vector<std::string> transactions_;
        SPHINXChain::Chain* blockchain_;
        const std::vector<std::string>& checkpointBlocks_;

    public:
        static const uint32_t MAX_BLOCK_SIZE;
        static const uint32_t MAX_TIMESTAMP_OFFSET;

        // Constructor without checkpointBlocks parameter
        Block(const std::string& previousHash, uint32_t version); // Add the version parameter to the constructor

        // Constructor with the addition of checkpointBlocks parameter
        Block(const std::string& previousHash, uint32_t version, const std::vector<std::string>& checkpointBlocks); // Add the version parameter to the constructor

        // Function to calculate the hash of the block
        std::string calculateBlockHash() const;

        // Add a transaction to the list of transactions in the block
        void addTransaction(const std::string& transaction);

        // Calculate and return the Merkle root of the transactions
        std::string calculateMerkleRoot() const;

        // Function to sign the Merkle root with SPHINCS+ private key
        std::string signMerkleRoot(const SPHINXPrivKey& privateKey, const std::string& merkleRoot);

        // Function to store the Merkle root and signature in the header of the block
        void storeMerkleRootAndSignature(const std::string& merkleRoot, const std::string& signature);

        // Get the hash of the block by calling the calculateBlockHash() function
        std::string getBlockHash() const;

        // Verify the block's signature and Merkle root
        bool verifyBlock(const SPHINXMerkleBlock::SPHINXPubKey& publicKey) const;

        // Setters and getters for the remaining member variables
        void setMerkleRoot(const std::string& merkleRoot);
        void setSignature(const std::string& signature);
        void setBlockHeight(uint32_t blockHeight);
        void setNonce(uint32_t nonce);
        void setDifficulty(uint32_t difficulty);
        void setTransactions(const std::vector<std::string>& transactions);
        std::string getPreviousHash() const;
        std::string getMerkleRoot() const;
        std::string getSignature() const;
        uint32_t getBlockHeight() const;
        std::time_t getTimestamp() const;
        uint32_t getNonce() const;
        uint32_t getDifficulty() const;
        std::vector<std::string> getTransactions() const;

        // Block headers
        nlohmann::json toJson() const;
        void fromJson(const nlohmann::json& blockJson);
        bool save(const std::string& filename) const;
        static Block load(const std::string& filename);
        bool saveToDatabase(SPHINXDb::DistributedDb& distributedDb) const;
        static Block loadFromDatabase(const std::string& blockId, SPHINXDb::DistributedDb& distributedDb);
    };
} // namespace SPHINXBlock

#endif // SPHINX_BLOCK_HPP
