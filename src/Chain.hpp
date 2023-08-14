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
#include "Server_http.hpp"

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

    // Example JSON-RPC method: Get the balance of an address.
    Json::Value getBalanceJsonRpc(const Json::Value& request);

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

    void startJsonRpcServer();

    void createBlockchainBridge(const Chain& targetChain);

    void wrapTokens(const std::string& recipientAddress, double amount);

    void handleWrappedTransaction(const std::string& wrappedTransactionData);

    void unwrapTokens(const std::string& bridgeAddress, const std::string& recipientAddress, double amount);

    void handleUnwrappedTransaction(const std::string& unwrappedTransactionData);

    void performAtomicSwap(const Chain& targetChain, const std::string& senderAddress,
                            const std::string& receiverAddress, double amount);

    void performShardAtomicSwap(const std::string& shardName, const Chain& targetShard,
                                const std::string& senderAddress, const std::string& receiverAddress, double amount);

    void createShard(const std::string& shardName);

    void joinShard(const std::string& shardName, const Chain& shardChain);

    void transferToShard(const std::string& shardName, const std::string& senderAddress,
                            const std::string& recipientAddress, double amount);

    void handleShardTransfer(const std::string& shardName, const SPHINXTrx::Transaction& transaction);

    void handleShardBridgeTransaction(const std::string& shardName, const std::string& bridgeAddress,
                                        const std::string& recipientAddress, double amount);

    void updateShardBalance(const std::string& shardName, const std::string& address, double amount);

    double getShardBalance(const std::string& shardName, const std::string& address) const;

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

    // Bridge constructor
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
