// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


/////////////////////////////////////////////////////////////////////////////////////////////////////////
// This code defines a class called Chain that represents a blockchain. The Chain class has various member functions and data members that provide functionality for managing the blockchain and performing operations such as adding blocks, transferring funds, creating bridges, and handling transactions.

// Libraries and Namespaces:
    // The code includes the nlohmann/json library for working with JSON data.
    // The code uses the namespaces SPHINXBlock, SPHINXHash, and SPHINXTrx to organize related functions.

// SPHINXContract Class:
    // The SPHINXContract class represents a smart contract that can execute operations on the SPHINX blockchain.
    // It has member functions such as executeChain, handleBridgeTransaction, handleTransfer, handleShardTransfer, handleShardBridgeTransaction, and handleAtomicSwap.
    // It also maintains information such as balances, bridge address and secret, and a target chain for atomic swaps.

// SPHINXChain Namespace:
    // The SPHINXChain namespace contains the implementation of the SPHINX blockchain.
    // It includes the Chain class, which represents a blockchain consisting of blocks.
    // The Chain class has member functions for adding blocks, retrieving block hashes, handling transactions, creating bridges, transferring funds, and managing shards.
    // It also includes a Shard struct that represents a shard in the chain.

// Chain Class:
    // The Chain class represents a blockchain consisting of blocks in the SPHINXChain namespace.
    // It has member functions for adding blocks, getting block hashes, transferring funds, handling bridge transactions, converting to/from JSON, saving/loading from a file, and various other blockchain operations.
    // It also includes functions for managing shards, such as creating shards, joining shards, transferring funds to shards, handling shard transactions, and performing atomic swaps with shards.
    // The class maintains information such as blocks, balances, bridge address and secret, and a target chain for atomic swaps.

// Genesis Block:
    // The Chain class constructor initializes the blockchain with a genesis block, which is the first block in the chain.

// Block Operations:
    // The addBlock function adds a block to the chain after verifying its validity using the public key.
    // The isChainValid function verifies the integrity and validity of the blockchain by checking the hashes, signatures, and blocks' order.
    // The getBlockHash function retrieves the hash of a block at a given height.

// Transaction and Bridge Operations:
    // The transferFromSidechain function transfers funds from a sidechain to the main chain by adding a block with the specified block hash from the sidechain.
    // The handleBridgeTransaction function handles a bridge transaction on the chain, validating and adding the transaction to the target chain.
    // The signTransaction function signs a transaction using the private key.
    // The broadcastTransaction function broadcasts a transaction via the bridge.
    // The handleTransfer function updates balances based on a transfer transaction.
    // The updateBalance function updates the balance of an address on the chain.

// JSON Serialization:
    // The toJson function converts the chain object to a JSON representation.
    // The fromJson function populates the chain object from a JSON object.
    // The save function saves the chain to a file in JSON format.
    // The load function loads a chain from a JSON file.

// Shard Operations:
    // The createShard function creates a new shard in the chain.
    // The joinShard function joins an existing shard to the chain.
    // The transferToShard function transfers funds to a shard on the chain.
    // The handleShardTransfer function handles a shard transfer transaction on the chain.
    // The handleShardBridgeTransaction function handles a shard bridge transaction on the chain.
    // The performShardAtomicSwap function performs an atomic swap with a shard on the chain.

// This code provides the basic functionality of a blockchain and supports operations such as adding blocks, transferring funds, handling transactions, creating bridges, and managing shards.
/////////////////////////////////////////////////////////////////////////////////////////////////////////



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

#include "Chain.hpp"
#include "json.hh"
#include "Block.hpp"
#include "Verify.hpp"
#include "Sign.hpp"
#include "Key.hpp"
#include "Verify.hpp"
#include "Transaction.hpp"
#include "Consensus/Contract.hpp"
#include "Params.hpp"
#include "server_http.hpp"


using json = nlohmann::json;

// Constant for block not found
constexpr uint32_t BLOCK_NOT_FOUND = std::numeric_limits<uint32_t>::max();

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
        class Chain {
        public:
        // Constructor to create a new chain instance with provided MainParams.
        explicit Chain(const MainParams& mainParams);

        // Function to add a block to the chain
        void addBlock(const SPHINXBlock::Block& block);

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
        bool save(const nlohmann::json& chainJson, const std::string& filename) const;

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
        Chain* chain;  // Use a pointer to SPHINXChain::Chain.
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
        // Target chain for atomic swaps
        SPHINXChain::Chain* targetChain_;  // Use a pointer to SPHINXChain::Chain.

    };

    // Implementation of the Chain constructor
    SPHINXChain::SPHINXChain(const MainParams& mainParams) {
        std::string genesisMessage = "Welcome to Post-Quantum era, The Beginning of a Secured-Trustless Network will start from here - SPHINX Network";
        SPHINXBlock::Block genesisBlock(SPHINXHash::SPHINX_256(genesisMessage));
        addBlock(genesisBlock);
    }

    // Implementation of the addBlock function
    void SPHINXChain::addBlock(const SPHINXBlock::Block& block) {
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

    // Get the hash of the block at the given height
    std::string Chain::getBlockHash(uint32_t blockHeight) const {
        if (blockHeight >= blocks_.size()) {  // If the block height is out of range
            throw std::out_of_range("Block height out of range.");  // Throw an out-of-range error
        }
        return blocks_[blockHeight].getBlockHash();  // Get the hash of the block at the given height
    }

    // Transfer a block from a sidechain to the main chain
    void Chain::transferFromSidechain(const Chain& sidechain, const std::string& blockHash) {
        uint32_t blockHeight = BLOCK_NOT_FOUND;  // Initialize the block height variable
        for (uint32_t i = 0; i < sidechain.getChainLength(); ++i) {  // Iterate over the blocks in the sidechain
            if (sidechain.getBlockHash(i) == blockHash) {  // Check if the block hash matches the given block hash
                blockHeight = i;  // Store the block height
                break;
            }
        }

        if (blockHeight == BLOCK_NOT_FOUND) {  // If the block is not found in the main chain
            throw std::runtime_error("Block not found in the main chain.");  // Throw an error
        }

        const SPHINXBlock::Block& block = sidechain.getBlockAt(blockHeight);  // Get the block at the specified height from the sidechain
        if (block.verifyBlock(SPHINXPubKey)) {  // Verify the block using the public key
            blocks_.push_back(block);  // Add the block to the chain
        } else {
            throw std::runtime_error("Invalid block! Block verification failed.");  // Throw an error if the block verification fails
        }
    }

    // Handle a bridge transaction
    void Chain::handleBridgeTransaction(const std::string& bridgeAddress, const std::string& targetChain, const std::string& transaction) {
        if (bridgeAddress == "SPHINX") {  // Check if the bridge is "SPHINX"
            bool isValid = SPHINXVerify::validateTransaction(transaction);  // Validate the transaction
            if (!isValid) {  // If the transaction is not valid
                throw std::runtime_error("Invalid transaction! Transaction validation failed.");  // Throw an error
            }
            targetChain_.addTransaction(transaction);  // Add the transaction to the target chain
        } else {
            throw std::runtime_error("Invalid bridge!");  // If the bridge is invalid, throw an error
        }
    }

    // Convert the chain data to JSON format
    nlohmann::json Chain::toJson() const {
        nlohmann::json chainJson;
        // Serialize the blocks
        nlohmann::json blocksJson = nlohmann::json::array();
        for (const SPHINXBlock::Block& block : blocks_) {
            blocksJson.push_back(block.toJson());
        }
        chainJson["blocks"] = blocksJson;

        // Serialize the public key
        chainJson["SPHINXPubKey"] = SPHINXHybridKey::sphinxKeyToString(SPHINXPubKey);

        return chainJson;
    }

    // Load chain data from JSON and populate the chain
    void Chain::fromJson(const nlohmann::json& chainJson) {
        blocks_.clear();

        // Deserialize the blocks
        const nlohmann::json& blocksJson = chainJson["blocks"];
        for (const auto& blockJson : blocksJson) {
            SPHINXBlock::Block block("");
            block.fromJson(blockJson);
            blocks_.push_back(block);
        }

        // Deserialize the public key
        SPHINXPubKey = SPHINXHybridKey::sphinxKeyFromString(chainJson["SPHINXPubKey"]);
    }

    // Save the chain data to a file in JSON format
    bool Chain::save(const nlohmann::json& chainJson, const std::string& filename) const {
        std::ofstream outputFile(filename);
        if (outputFile.is_open()) {
            outputFile << chainJson.dump(4);  // Write the formatted JSON data to the file
            outputFile.close();
            return true;
        }
        return false;
    }

    // Load chain data from a JSON file and return the loaded chain
    SPHINXChain Chain::load(const std::string& filename) {
        std::ifstream inputFile(filename);
        if (inputFile.is_open()) {
            nlohmann::json chainJson;
            inputFile >> chainJson;  // Read the JSON data from the file
            inputFile.close();
            Chain loadedChain;
            loadedChain.fromJson(chainJson);  // Deserialize the JSON data into a Chain object
            return loadedChain;
        }
        throw std::runtime_error("Failed to load chain from file: " + filename);
    }

    // Get the genesis block of the chain
    SPHINXBlock::Block Chain::getGenesisBlock() const {
        return blocks_.front();  // Return the first block in the chain
    }

    // Get the block at a specific index in the chain
    SPHINXBlock::Block Chain::getBlockAt(size_t index) const {
        if (index < blocks_.size()) {
            return blocks_[index];  // Return the block at the specified index
        } else {
            throw std::out_of_range("Index out of range");
        }
    }

    // Get the number of blocks in the chain
    size_t Chain::getChainLength() const {
        return blocks_.size();  // Return the number of blocks in the chain
    }

    // Visualize the chain by printing the index and hash of each block
    void Chain::visualizeChain() const {
        for (size_t i = 0; i < blocks_.size(); ++i) {
            const SPHINXBlock::Block& block = blocks_[i];
            std::cout << "Block " << i << " - Hash: " << block.getBlockHash() << std::endl;  // Print the index and hash of each block
        }
    }

    // Connect the chain to a sidechain by establishing a connection
    void SPHINXChain::Chain::connectToSidechain(const Chain& sidechain) {
        SidechainConnection connection(sidechain.getBridgeAddress(), sidechain.getBridgeSecret());
        connection.sync();
    }

    // Transfer funds from a sidechain to the main chain
    void Chain::transferFromSidechain(const std::string& sidechainAddress, const std::string& senderAddress, double amount) {
        double senderBalance = getBalance(senderAddress);  // Get the balance of the sender
        if (amount > senderBalance) {
            throw std::runtime_error("Sender does not have enough funds");  // Throw an error if the sender doesn't have enough funds
        }

        if (!TwoFactorAuthenticator::verifyCode(senderUsername, sender2FACode)) {
            throw std::runtime_error("Authentication failed");  // Throw an error if authentication fails
        }

        // Generate and perform a key exchange
        SPHINXHybridKey::HybridKeypair keyPair = SPHINXKey::generate_and_perform_key_exchange();

        // Calculate the public key
        SPHINXKey::SPHINXPubKey publicKey = SPHINXKey::mergePublicKeys(keyPair.merged_key.curve448_public_key, keyPair.merged_key.kyber_public_key);

        // Create a transaction
        SPHINXTrx::Transaction transferTransaction = createTransaction(sidechainAddress, senderAddress, amount);

        // Sign the transaction using the private key
        SPHINXKey::SPHINXPrivKey privateKey;  // Replace this with the actual private key
        std::string signature = SPHINXSign::signTransactionData(transactionToString(transferTransaction), privateKey);

        // Broadcast the transaction
        SPHINXMempool::broadcastTransaction(transferTransaction);

        // Handle the transfer
        handleTransfer(transferTransaction); 
    }

    // Create a blockchain bridge between the current chain and a target chain
    void Chain::createBlockchainBridge(const Chain& targetChain) {
        std::string bridgeAddress = generateBridgeAddress();
        std::string targetBridgeAddress = targetChain.generateBridgeAddress();

        // Construct an HTTP request to create a bridge
        std::string httpRequest = "POST /create_bridge HTTP/1.1\r\nHost: localhost\r\nContent-Length: ";
        httpRequest += std::to_string(bridgeAddress.size()) + "\r\n\r\n" + bridgeAddress;

        // Send the HTTP request to your HTTP server
        std::string httpResponse = sendHttpRequest(httpRequest);

        // Process the HTTP response from your server (if needed)
    }

    // Handle a bridge transaction by transferring funds to the recipient address
    void Chain::handleBridgeTransaction(const std::string& bridgeAddress, const std::string& recipientAddress, double amount) {
        if (!bridge.verifyTransaction(bridgeAddress, amount)) {
            // Throw an error if the bridge transaction is invalid
            throw std::runtime_error("Invalid bridge transaction");
        }
        // Throw an error if authentication fails
        if (!TwoFactorAuthenticator::verifyCode(senderUsername, sender2FACode)) {
            throw std::runtime_error("Authentication failed");
        }

        // Construct an HTTP request to handle a bridge transaction
        std::string httpRequest = "POST /handle_transaction HTTP/1.1\r\nHost: localhost\r\nContent-Length: ";
        // Construct the transaction data and add it to the httpRequest

        // Send the HTTP request to your HTTP server
        std::string httpResponse = sendHttpRequest(httpRequest);

        // Generate and perform a key exchange
        SPHINXHybridKey::HybridKeypair keyPair = SPHINXKey::generate_and_perform_key_exchange();

        // Calculate the public key
        SPHINXKey::SPHINXPubKey publicKey = SPHINXKey::calculatePublicKey(keyPair.merged_key.kyber_private_key);

        // Get the transaction data from the bridge
        std::string transactionData = bridge.getTransactionData(bridgeAddress);

        // Sent request to Sign the transaction data to "sign.hpp"
        SPHINXKey::SPHINXPrivKey privateKey;  // Replace this with the actual private key
        std::string signature = SPHINXSign::signTransactionData(transactionData, privateKey);

        // Throw an error if the signature verification fails
        if (!SPHINXVerify::verifySignature(transactionData, signature, PUBLIC_KEY)) {
            throw std::runtime_error("Authentication failed");
        }
        // Calculate the transaction hash
        std::string transactionHash = SPHINXHash::SPHINX_256(transactionData);

        // Transfer funds to the recipient address in the target chain
        targetChain.transfer(recipientAddress, amount);

        // Update the balance of the recipient address
        updateBalance(recipientAddress, amount);

        // Update the balance of the sender address
        updateBalance(senderAddress, -amount);
    }

    // Perform an atomic swap between the current chain and a target chain
    void Chain::performAtomicSwap(const Chain& targetChain, const std::string& senderAddress, const std::string& receiverAddress, double amount) {
        // Get the balance of the sender address
        double senderBalance = getBalance(senderAddress);
        // Get the balance of the receiver address in the target chain
        double receiverBalance = targetChain.getBalance(receiverAddress);
        if (senderBalance < amount) {
            // Throw an error if the sender doesn't have enough funds
            throw std::runtime_error("Sender does not have enough funds");
        }

        if (!TwoFactorAuthenticator::verifyCode(senderUsername, sender2FACode)) {
            // Throw an error if authentication fails
            throw std::runtime_error("Authentication failed");
        }
        // Create a transaction from the sender address to the target chain bridge address
        SPHINXTrx::Transaction senderTransaction = createTransaction(senderAddress, targetChain.getBridgeAddress(), amount);
        // Create a transaction from the receiver address in the target chain to the sender address
        SPHINXTrx::Transaction receiverTransaction = targetChain.createTransaction(receiverAddress, senderAddress, amount);

        signTransaction(senderTransaction);  // Sign the sender transaction
        signTransaction(receiverTransaction);  // Sign the receiver transaction
        broadcastTransaction(senderTransaction);  // Broadcast the sender transaction
        targetChain.broadcastTransaction(receiverTransaction);  // Broadcast the receiver transaction

        while (true) {
            if (senderTransaction.isConfirmed() && receiverTransaction.isConfirmed()) {
                break;  // Exit the loop if both transactions are confirmed
            }
            // Sleep for 10 seconds before checking the confirmation status again
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }

        if (!verifyAtomicSwap(senderTransaction, targetChain) || !targetChain.verifyAtomicSwap(receiverTransaction, *this)) {
            // Throw an error if the atomic swap verification fails
            throw std::runtime_error("Atomic swap verification failed");
        }
        // Update the balance of the sender address
        updateBalance(senderAddress, -amount);
        // Update the balance of the receiver address in the target chain
        targetChain.updateBalance(receiverAddress, amount);
    }

    // Sign a transaction using the bridge's private key
    void Chain::signTransaction(SPHINXTrx::Transaction& transaction) {
        // Get the transaction data from the bridge
        std::string transactionData = bridge.getTransactionData(bridgeAddress_);
        
        // Generate the hybrid key pair
        SPHINXHybridKey::HybridKeypair hybridKeyPair = SPHINXKey::generate_hybrid_keypair();

        // Get the private key from the hybrid key pair
        std::string privateKey = SPHINXKey::sphinxKeyToString(hybridKeyPair.merged_key.sphinxPrivKey);

        // Sign the transaction data using the private key
        std::string signature = SPHINXSign::signTransactionData(transactionData, privateKey);

        // Set the transaction signature
        transaction.setSignature(signature);
    }

    // Broadcast a transaction to the network via the bridge and add it to the mempool
    void Chain::broadcastTransaction(const SPHINXTrx::Transaction& transaction) {
        // Convert the transaction to JSON
        std::string transactionJson = transaction.toJson().dump();
        
        // Broadcast the transaction via the bridge
        bridge.broadcastTransaction(bridgeAddress_, transactionJson);
        
        // Add the transaction to the mempool
        mempool.addTransaction(transaction);
    }

    // Update the balance of a given address by adding the specified amount
    void Chain::updateBalance(const std::string& address, double amount) {
        balances_[address] += amount;  // Update the balance of the given address by adding the specified amount
    }

    // Get the balance of a given address
    double Chain::getBalance(const std::string& address) const {
        if (balances_.count(address) > 0) {
            return balances_.at(address);  // Return the balance of the given address if it exists
        }
        return 0.0;  // Return 0 if the balance of the given address is not found
    }

    // Verify an atomic swap transaction by checking the transaction signature and the bridge transaction in the target chain
    bool Chain::verifyAtomicSwap(const SPHINXTrx::Transaction& transaction, const Chain& targetChain) const {
        std::string transactionData = bridge.getTransactionData(bridgeAddress_);
        std::string signature = transaction.getSignature();
        std::string senderPublicKey = transaction.getSenderPublicKey();
        // Verify the transaction signature and the bridge transaction in the target chain
        return SPHINXVerify::verifySignature(transactionData, signature, senderPublicKey) && targetChain.verifyBridgeTransaction(transaction);
    }

    // Handle a transfer transaction by updating the balance of the recipient address
    void Chain::handleTransfer(const SPHINXTrx::Transaction& transaction) {
        std::string recipientAddress = transaction.getRecipientAddress();
        double amount = transaction.getAmount();
        updateBalance(recipientAddress, amount);  // Update the balance of the recipient address
    }

    // Get the bridge address of the chain
    std::string Chain::getBridgeAddress() const {
        return bridgeAddress_;
    }

    // Get the bridge secret of the chain
    std::string Chain::getBridgeSecret() const {
        return bridgeSecret_;
    }

    // Create a new shard with the given shard name
    void Chain::createShard(const std::string& shardName) {
        Shard shard;
        shard.bridgeAddress = shardName;
        shard.chain = Chain();
        shards_.push_back(shard);  // Add a new shard to the shard vector
        shardIndices_[shardName] = shards_.size() - 1;  // Store the shard index by shard name for quick access
    }

    // Join an existing shard with the given shard name and chain
    void Chain::joinShard(const std::string& shardName, const Chain& shardChain) {
        auto it = shardIndices_.find(shardName);
        if (it == shardIndices_.end()) {
            throw std::runtime_error("Shard does not exist: " + shardName);  // Throw an error if the shard does not exist
        }
        shards_[it->second].chain = shardChain;  // Join the shard by assigning the shard chain to the corresponding shard
    }

    // Transfer funds from the main chain to a shard
    void Chain::transferToShard(const std::string& shardName, const std::string& senderAddress, const std::string& recipientAddress, double amount) {
        auto it = shardIndices_.find(shardName);
        if (it == shardIndices_.end()) {
            throw std::runtime_error("Shard does not exist: " + shardName);  // Throw an error if the shard does not exist
        }
        Shard& shard = shards_[it->second];  // Get the reference to the shard
        double senderBalance = getBalance(senderAddress);
        if (amount > senderBalance) {
            throw std::runtime_error("Sender does not have enough funds");  // Throw an error if the sender doesn't have enough funds
        }

        if (!TwoFactorAuthenticator::verifyCode(senderUsername, sender2FACode)) {
            throw std::runtime_error("Authentication failed");  // Throw an error if authentication fails
        }

        SPHINXHybridKey::HybridKeypair keyPair = SPHINXKey::generate_and_perform_key_exchange();  // Generate and perform a key exchange
        SPHINXKey::SPHINXPubKey publicKey = SPHINXKey::calculatePublicKey(keyPair.merged_key.kyber_private_key.data());  // Calculate the public key
        SPHINXTrx::Transaction transferTransaction = createTransaction(shard.bridgeAddress, senderAddress, amount);  // Create a transaction to the shard bridge address
        signTransaction(transferTransaction);  // Sign the transaction
        broadcastTransaction(transferTransaction);  // Broadcast the transaction
        shard.chain.handleShardTransfer(shardName, transferTransaction);  // Handle the shard transfer in the shard chain
        updateBalance(senderAddress, -amount);  // Update the balance of the sender address
    }

    // Handle a shard transfer transaction in the shard chain by updating the balance of the recipient address
    void Chain::handleShardTransfer(const std::string& shardName, const SPHINXTrx::Transaction& transaction) {
        auto it = shardIndices_.find(shardName);
        if (it == shardIndices_.end()) {
            throw std::runtime_error("Shard does not exist: " + shardName);  // Throw an error if the shard does not exist
        }
        Shard& shard = shards_[it->second];  // Get the reference to the shard
        shard.chain.handleTransfer(transaction);  // Handle the transfer in the shard chain
    }

    // Handle a shard bridge transaction in the shard chain by updating the balances of the recipient and sender addresses
    void Chain::handleShardBridgeTransaction(const std::string& shardName, const std::string& bridgeAddress, const std::string& recipientAddress, double amount) {
        auto it = shardIndices_.find(shardName);
        if (it == shardIndices_.end()) {
            throw std::runtime_error("Shard does not exist: " + shardName);  // Throw an error if the shard does not exist
        }
        Shard& shard = shards_[it->second];  // Get the reference to the shard
        if (!shard.bridge.verifyTransaction(bridgeAddress, amount)) {
            // Throw an error if the bridge transaction is invalid
            throw std::runtime_error("Invalid bridge transaction");
        }

        if (!TwoFactorAuthenticator::verifyCode(senderUsername, sender2FACode)) {
            throw std::runtime_error("Authentication failed");  // Throw an error if authentication fails
        }

        SPHINXHybridKey::HybridKeypair keyPair = SPHINXKey::generate_and_perform_key_exchange();  // Generate and perform a key exchange
        SPHINXKey::SPHINXPubKey publicKey = SPHINXKey::calculatePublicKey(keyPair.merged_key.kyber_private_key.data());  // Calculate the public key
        std::string transactionData = shard.bridge.getTransactionData(bridgeAddress);  // Get the transaction data from the shard bridge
        std::string signature = SPHINXSign::sign(transactionData, keyPair.merged_key.kyber_private_key.data());  // Sign the transaction data

        if (!SPHINXVerify::verifySignature(transactionData, signature, publicKey)) {
            throw std::runtime_error("Authentication failed");  // Throw an error if authentication fails
        }

        std::string transactionHash = SPHINXHash::SPHINX_256(transactionData);
        shard.chain.updateBalance(recipientAddress, amount);  // Update the balance of the recipient address in the shard chain
        shard.chain.updateBalance(senderAddress, -amount);  // Update the balance of the sender address in the shard chain
    }

    // Perform an atomic swap between the current shard and the target shard
    void Chain::performShardAtomicSwap(const std::string& shardName, const Chain& targetShard, const std::string& senderAddress, const std::string& receiverAddress, double amount) {
        auto it = shardIndices_.find(shardName);
        if (it == shardIndices_.end()) {
            throw std::runtime_error("Shard does not exist: " + shardName);  // Throw an error if the shard does not exist
        }
        Shard& shard = shards_[it->second];  // Get the reference to the shard
        double senderBalance = getBalance(senderAddress);
        double receiverBalance = targetShard.getBalance(receiverAddress);
        if (senderBalance < amount) {
            throw std::runtime_error("Sender does not have enough funds");  // Throw an error if the sender does not have enough funds
        }

        if (!TwoFactorAuthenticator::verifyCode(senderUsername, sender2FACode)) {
            throw std::runtime_error("Authentication failed");  // Throw an error if authentication fails
        }

        SPHINXTrx::Transaction senderTransaction = createTransaction(senderAddress, shard.bridgeAddress, amount);  // Create a transaction from the sender to the shard bridge
        SPHINXTrx::Transaction receiverTransaction = targetShard.createTransaction(receiverAddress, senderAddress, amount);  // Create a transaction from the shard bridge to the receiver

        signTransaction(senderTransaction);  // Sign the sender transaction
        signTransaction(receiverTransaction);  // Sign the receiver transaction
        broadcastTransaction(senderTransaction);  // Broadcast the sender transaction
        targetShard.broadcastTransaction(receiverTransaction);  // Broadcast the receiver transaction

        while (true) {
            if (senderTransaction.isConfirmed() && receiverTransaction.isConfirmed()) {
                break;  // Wait until both transactions are confirmed
            }
            std::this_thread::sleep_for(std::chrono::seconds(10));  // Sleep for 10 seconds before checking confirmation status again
        }

        if (!verifyAtomicSwap(senderTransaction, shard.chain) || !targetShard.verifyAtomicSwap(receiverTransaction, shard.chain)) {
            throw std::runtime_error("Atomic swap verification failed");  // Throw an error if atomic swap verification fails
        }

        updateBalance(senderAddress, -amount);  // Update the balance of the sender address
        targetShard.updateBalance(receiverAddress, amount);  // Update the balance of the receiver address in the target shard
    }

    // Update the balance of a given address in the specified shard by adding the specified amount
    void Chain::updateShardBalance(const std::string& shardName, const std::string& address, double amount) {
        auto it = shardIndices_.find(shardName);
        if (it == shardIndices_.end()) {
            throw std::runtime_error("Shard does not exist: " + shardName);  // Throw an error if the shard does not exist
        }
        Shard& shard = shards_[it->second];  // Get the reference to the shard
        shard.balances[address] += amount;  // Update the balance of the given address in the shard
    }

    // Get the balance of a given address in the specified shard
    double Chain::getShardBalance(const std::string& shardName, const std::string& address) const {
        auto it = shardIndices_.find(shardName);
        if (it == shardIndices_.end()) {
            throw std::runtime_error("Shard does not exist: " + shardName);  // Throw an error if the shard does not exist
        }
        const Shard& shard = shards_[it->second];  // Get the reference to the shard
        if (shard.balances.count(address) > 0) {
            return shard.balances.at(address);  // Return the balance of the given address in the shard if it exists
        }
        return 0.0;  // Return 0.0 if the address balance is not found in the shard
    }
} // namespace SPHINXChain
