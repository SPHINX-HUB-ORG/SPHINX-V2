// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINXCHAIN_HPP
#define SPHINXCHAIN_HPP

#pragma once

#include <stdexcept>
#include <fstream>
#include <array>
#include <iostream>
#include <string>
#include <vector>

using json = nlohmann::json;

class MainParams {
public:
    SPHINXParams::MainParams params;

    MainParams() {
        // Set the parameters in the constructor
        params.setMaxBlockSize(2048);
        params.setConsensusAlgorithm("SPHINXConsensus");
    }

    int getMaxBlockSize() const {
        return params.getMaxBlockSize();
    }

    std::string getConsensusAlgorithm() const {
        return params.getConsensusAlgorithm();
    }
};

class SPHINXChain {
public:
    // Constructor to create a new chain instance with provided MainParams.
    explicit SPHINXChain(const MainParams& mainParams);

    // Add a new block to the chain.
    void addBlock(const SPHINXBlock::Block& block) {
        // Add block to the blockchain
        // Calculate the hash of the block's data
        std::string blockHash = block.calculateBlockHash();

        // Sign the block's hash using the private key (Note: you need to define privateKey and transactionData somewhere)
        std::string signature = SPHINXVerify::sign_data(std::vector<uint8_t>(transactionData.begin(), transactionData.end()), privateKey);

        // Add the block and its signature to the chain
        blocks_.emplace_back(block, signature);
    }

    // Get the hash of a block at a specific block height.
    std::string getBlockHash(uint32_t blockHeight) const;

    // Transfer tokens from the sidechain to the main chain using a block hash.
    void transferFromSidechain(const SPHINXChain::Chain& sidechain, const std::string& blockHash);

    // Handle a bridge transaction for cross-chain communication.
    void handleBridgeTransaction(const std::string& bridge, const std::string& targetChain, const std::string& transaction);

    // Convert the chain data to a JSON format.
    nlohmann::json toJson() const;

    // Load chain data from a JSON object.
    void fromJson(const nlohmann::json& chainJson);

    // Save chain data to a file with the given filename.
    bool save(const std::string& filename) const;

    // Load chain data from a file with the given filename.
    static Chain load(const std::string& filename);

    // Get the genesis block of the chain.
    SPHINXBlock::Block getGenesisBlock() const;

    // Get the block at the specified index.
    SPHINXBlock::Block getBlockAt(size_t index) const;

    // Get the length of the chain (number of blocks).
    size_t getChainLength() const;

    // Visualize the chain, printing its details to the console.
    void visualizeChain() const;

    // Connect to a sidechain by referencing another chain instance.
    void connectToSidechain(const Chain& sidechain);

    // Transfer tokens from a sidechain to the main chain using the sidechain address and amount.
    void transferFromSidechain(const std::string& sidechainAddress, double amount);

    // Create a blockchain bridge between this chain and the target chain.
    void createBlockchainBridge(const Chain& targetChain);

    // Handle a bridge transaction between this chain and the target chain.
    void handleBridgeTransaction(const std::string& bridgeAddress, const std::string& recipientAddress, double amount);

    // Perform an atomic swap between this chain and the target chain.
    void performAtomicSwap(const Chain& targetChain, const std::string& senderAddress, const std::string& receiverAddress, double amount);

    // Sign a transaction before broadcasting it.
    void signTransaction(SPHINXTrx::Transaction& transaction);

    // Broadcast a signed transaction to the network.
    void broadcastTransaction(const SPHINXTrx::Transaction& transaction);

    // Update the balance of an address with the specified amount.
    void updateBalance(const std::string& address, double amount);

    // Get the balance of an address.
    double getBalance(const std::string& address) const;

    // Verify an atomic swap transaction with the target chain.
    bool verifyAtomicSwap(const SPHINXTrx::Transaction& transaction, const Chain& targetChain) const;

    // Handle a transfer transaction.
    void handleTransfer(const SPHINXTrx::Transaction& transaction);

    // Get the address of the bridge.
    std::string getBridgeAddress() const;

    // Get the secret key of the bridge.
    std::string getBridgeSecret() const;

    // Create a new shard with the given name.
    void createShard(const std::string& shardName);

    // Join an existing shard by connecting to its chain.
    void joinShard(const std::string& shardName, const Chain& shardChain);

    // Transfer tokens to a shard with the specified sender and recipient addresses.
    void transferToShard(const std::string& shardName, const std::string& senderAddress, const std::string& recipientAddress, double amount);

    // Handle a transfer transaction within a shard.
    void handleShardTransfer(const std::string& shardName, const SPHINXTrx::Transaction& transaction);

    // Handle a bridge transaction within a shard.
    void handleShardBridgeTransaction(const std::string& shardName, const std::string& bridgeAddress, const std::string& recipientAddress, double amount);

    // Perform an atomic swap with a shard.
    void performShardAtomicSwap(const std::string& shardName, const Chain& targetShard, const std::string& senderAddress, const std::string& receiverAddress, double amount);

    // Update the balance of an address in a shard.
    void updateShardBalance(const std::string& shardName, const std::string& address, double amount);

    // Get the balance of an address in a shard.
    double getShardBalance(const std::string& shardName, const std::string& address) const;

    // Check if the chain is valid.
    bool isChainValid() const;

    private:
    // Structure to represent a shard with its chain, bridge address, bridge secret, and balances.
    struct Shard {
        SPHINXChain* chain;  // Use a pointer to SPHINXChain.
        std::string bridgeAddress;
        std::string bridgeSecret;
        std::unordered_map<std::string, double> balances;
    };

    std::vector<Shard> shards_;  // Shards in the chain
    std::vector<SPHINXBlock::Block> blocks_;  // Blocks in the chain
    SPHINXHybridKey::HybridKeypair SPHINXKeyPub; // Public key of the chain
    static constexpr uint32_t BLOCK_NOT_FOUND = std::numeric_limits<uint32_t>::max();  // Constant for block not found
    std::unordered_map<std::string, uint32_t> shardIndices_;  // Indices of shards in the chain

    std::unordered_map<std::string, double> balances_;  // Balances of addresses on the chain
    std::string bridgeAddress_;  // Address of the bridge
    std::string bridgeSecret_;  // Secret key for the bridge

    bool verifyWrappedTransaction(const std::string& wrappedTransactionData);
    bool verifyUnwrappedTransaction(const std::string& unwrappedTransactionData);
    std::string generateBridgeAddress();
    std::string constructWrappedTransactionData(const std::string& recipientAddress, double amount);
    std::string constructUnwrappedTransactionData(const std::string& recipientAddress, double amount);

    // Target chain for atomic swaps
    SPHINXChain* targetChain_;  // Use a pointer to SPHINXChain.
    Chain::Chain(const SPHINXParams::MainParams& mainParams) : mainParams_(mainParams) {
        // Create the genesis block with the provided message
        SPHINXBlock::Block genesisBlock(mainParams_.genesisMessage);

        // Add the genesis block to the chain
        blocks_.push_back(genesisBlock);
    }

    void Chain::addBlock(const SPHINXBlock::Block& block) {
        // Add block to the blockchain
        // Calculate the hash of the block's data
        std::string blockHash = block.calculateBlockHash();

        // Sign the block's hash using the private key (Note: you need to define privateKey and transactionData somewhere)
        std::string signature = SPHINXVerify::sign_data(std::vector<uint8_t>(transactionData.begin(), transactionData.end()), privateKey);

        // Add the block and its signature to the chain
        blocks_.emplace_back(block, signature);
    }

    bool Chain::isChainValid() const {
        // Validate the integrity of the blockchain
        for (size_t i = 1; i < blocks_.size(); ++i) {
            const SPHINXBlock::Block& currentBlock = blocks_[i];
            const SPHINXBlock::Block& previousBlock = blocks_[i - 1];

            // Verify the block's hash and previous block hash
            if (currentBlock.getBlockHash() != currentBlock.calculateBlockHash() ||
                currentBlock.getPreviousHash() != previousBlock.calculateBlockHash()) {
                return false;
            }

            // Verify the signature of the block
            if (!SPHINXVerify::verifySPHINXBlock(currentBlock, currentBlock.getSignature(), publicKey_)) {
                return false;
            }
        }

        return true;
    }

    SPHINXBlock::Block Chain::getGenesisBlock() const {
        // Get the first block in the blockchain
        return blocks_.front();
    }

    SPHINXBlock::Block Chain::getBlockAt(size_t index) const {
        // Get the block at the specified index
        if (index < blocks_.size()) {
            return blocks_[index];
        } else {
            throw std::out_of_range("Index out of range");
        }
    }

    size_t Chain::getChainLength() const {
        // Get the length or size of the chain
        return blocks_.size();
    }

    void Chain::visualizeChain() const {
        // Visualize the blockchain for analysis or presentation purposes
        for (size_t i = 0; i < blocks_.size(); ++i) {
            const SPHINXBlock::Block& block = blocks_[i];
            std::cout << "Block " << i << " - Hash: " << block.getBlockHash() << std::endl;
            // Print or display other block details as desired
        }
    }

    json Chain::toJson() const {
        json chainJson;
        chainJson["blocks"] = json::array();
        for (const SPHINXBlock::Block& block : blocks_) {
            chainJson["blocks"].push_back(block.toJson());
        }
        return chainJson;
    }

    void Chain::fromJson(const json& chainJson) {
        blocks_.clear();
        if (chainJson.contains("blocks") && chainJson["blocks"].is_array()) {
            const json& blocksJson = chainJson["blocks"];
            for (const json& blockJson : blocksJson) {
                SPHINXBlock::Block block;
                block.fromJson(blockJson);
                blocks_.push_back(block);
            }
        } else {
            throw std::invalid_argument("Invalid JSON structure or missing fields");
        }
    }

    // Sharding class for horizontal partitioning of the blockchain network
    class Sharding {
    public:
        static std::vector<SPHINXChain> shardBlockchain(const SPHINXChain& chain, size_t shardCount);
    };
}; // namespace SPHINXChain

#endif // SPHINXCHAIN_HPP
