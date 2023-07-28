// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <unordered_map>
#include <limits>
#include <chrono>
#include <thread>
#include <ctime>
#include <stdexcept>
#include <fstream>
#include <array>
#include <iostream>
#include <string>
#include <vector>


#include "chain.hpp" // Include the header file for the SPHINXChain class

// Implement the Chain constructor
SPHINXChain::Chain::Chain(const MainParams& mainParams) {
    std::string genesisMessage = "Welcome to Post-Quantum era, The Beginning of a Secured-Trustless Network will start from here - SPHINX Network";
    SPHINXBlock::Block genesisBlock(SPHINXHash::SPHINX_256(genesisMessage));
    addBlock(genesisBlock);
}

// Implement the addBlock function
void SPHINXChain::Chain::addBlock(const SPHINXBlock::Block& block) {
    if (blocks_.empty()) {  // If the chain is empty
        blocks_.push_back(block);  // Add the block to the chain
    } else {
        if (block.verifyBlock(SPHINXPubKey)) {  // Verify the block using the public key
            blocks_.push_back(block);  // Add the block to the chain
        } else {
            throw std::runtime_error("Invalid block! Block verification failed.");  // Throw an error if the block verification fails
        }
    }
}

// Implement the getBlockHash function
std::string SPHINXChain::Chain::getBlockHash(uint32_t blockHeight) const {
    if (blockHeight >= blocks_.size()) {  // If the block height is out of range
        throw std::out_of_range("Block height out of range.");  // Throw an out-of-range error
    }
    return blocks_[blockHeight].getBlockHash();  // Get the hash of the block at the given height
}

// Implement other member functions of the SPHINXChain::Chain class as needed

// Define and implement the member functions of the SPHINXChain class here

// Implement the SPHINXChain::Chain constructor here

// Implement other member functions of the SPHINXChain class as needed
