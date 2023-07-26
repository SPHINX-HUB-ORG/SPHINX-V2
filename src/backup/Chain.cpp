/*
 *  Copyright (c) (2023) SPHINX_ORG
 *  Authors:
 *    - (C kusuma) <thekoesoemo@gmail.com>
 *      GitHub: (https://github.com/chykusuma)
 *  Contributors:
 *    - (Contributor 1) <email1@example.com>
 *      Github: (https://github.com/yourgit)
 *    - (Contributor 2) <email2@example.com>
 *      Github: (https://github.com/yourgit)
 */


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
#include "json.hpp"
#include "Block.hpp"
#include "Verify.hpp"
#include "Sign.hpp"
#include "Key.hpp"
#include "Verify.hpp"
#include "Transaction.hpp"


using json = nlohmann::json;

// Forward declarations
namespace SPHINXBlock {
    std::string SPHINXBlock (const std::string& message);
}

namespace SPHINXHash {
    std::string SPHINX_256(const std::string& message);
}

namespace SPHINXTrx {
    std::string SPHINXTrx(const std::string& message);
}

namespace SPHINXChain {
    class Chain;  // Forward declaration of the Chain class
}

namespace SPHINXTrx {
    class Transaction;  // Forward declaration of the Transaction class
}

class SPHINXContract {
public:
    void executeChain(SPHINXChain::Chain& chain);  // Function declaration
    void handleBridgeTransaction(SPHINXChain::Chain& chain, const std::string& bridge, const std::string& targetChain, const std::string& transaction);  // Function declaration
    void handleTransfer(SPHINXChain::Chain& chain, const SPHINXTrx::Transaction& transaction);  // Function declaration
    void handleShardTransfer(SPHINXChain::Chain& chain, const std::string& shardName, const SPHINXTrx::Transaction& transaction);  // Function declaration
    void handleShardBridgeTransaction(SPHINXChain::Chain& chain, const std::string& shardName, const std::string& bridgeAddress, const std::string& recipientAddress, double amount);  // Function declaration
    void handleAtomicSwap(SPHINXChain::Chain& chain, const SPHINXChain::Chain& targetChain, const std::string& senderAddress, const std::string& receiverAddress, double amount);  // Function declaration

private:
    std::unordered_map<std::string, double> balances_;  // Balances of addresses on the chain
    std::string bridgeAddress_;  // Address of the bridge
    std::string bridgeSecret_;  // Secret key for the bridge
    SPHINXChain::Chain targetChain_;  // Target chain for atomic swaps
};

class SPHINXChain {
public:
    class Chain {
    public:
        Chain();

        // Adds a block to the chain
        void addBlock(const SPHINXBlock::Block& block);

        // Retrieves the hash of a block at the given height
        std::string getBlockHash(uint32_t blockHeight) const;

        // Transfers funds from a sidechain to the chain
        void transferFromSidechain(const SPHINXChain::Chain& sidechain, const std::string& blockHash);

        // Handles a bridge transaction on the chain
        void handleBridgeTransaction(const std::string& bridge, const std::string& targetChain, const std::string& transaction);

        // Converts the chain to JSON format
        nlohmann::json toJson() const;

        // Populates the chain from a JSON object
        void fromJson(const nlohmann::json& chainJson);

        // Saves the chain to a file
        bool save(const nlohmann::json& chainJson, const std::string& filename) const;

        // Loads a chain from a file
        static Chain load(const std::string& filename);

        // Retrieves the genesis block of the chain
        SPHINXBlock::Block getGenesisBlock() const;

        // Retrieves the block at the given index
        SPHINXBlock::Block getBlockAt(size_t index) const;

        // Retrieves the length of the chain
        size_t getChainLength() const;

        // Visualizes the chain
        void visualizeChain() const;

        // Connects the chain to a sidechain
        void connectToSidechain(const Chain& sidechain);

        // Transfers funds from a sidechain to the chain
        void transferFromSidechain(const std::string& sidechainAddress, const std::string& senderAddress, double amount);

        // Creates a bridge between the chain and the target chain
        void createBlockchainBridge(const Chain& targetChain);

        // Handles a bridge transaction on the chain
        void handleBridgeTransaction(const std::string& bridgeAddress, const std::string& recipientAddress, double amount);

        // Performs an atomic swap with the target chain
        void performAtomicSwap(const Chain& targetChain, const std::string& senderAddress, const std::string& receiverAddress, double amount);

        // Signs a transaction
        void signTransaction(SPHINXTrx::Transaction& transaction);

        // Broadcasts a transaction
        void broadcastTransaction(const SPHINXTrx::Transaction& transaction);

        // Updates the balance of an address on the chain
        void updateBalance(const std::string& address, double amount);

        // Retrieves the balance of an address on the chain
        double getBalance(const std::string& address) const;

        // Verifies the validity of an atomic swap transaction with the target chain
        bool verifyAtomicSwap(const SPHINXTrx::Transaction& transaction, const Chain& targetChain) const;

        // Handles a transfer transaction on the chain
        void handleTransfer(const SPHINXTrx::Transaction& transaction);

        // Retrieves the address of the bridge
        std::string getBridgeAddress() const;

        // Retrieves the secret key of the bridge
        std::string getBridgeSecret() const;

        // Creates a shard on the chain
        void createShard(const std::string& shardName);

        // Joins a shard to the chain
        void joinShard(const std::string& shardName, const Chain& shardChain);

        // Transfers funds to a shard on the chain
        void transferToShard(const std::string& shardName, const std::string& senderAddress, const std::string& recipientAddress, double amount);

        // Handles a shard transfer transaction on the chain
        void handleShardTransfer(const std::string& shardName, const SPHINXTrx::Transaction& transaction);

        // Handles a shard bridge transaction on the chain
        void handleShardBridgeTransaction(const std::string& shardName, const std::string& bridgeAddress, const std::string& recipientAddress, double amount);

        // Performs an atomic swap with a shard on the chain
        void performShardAtomicSwap(const std::string& shardName, const Chain& targetShard, const std::string& senderAddress, const std::string& receiverAddress, double amount);

        // Updates the balance of an address on a shard
        void updateShardBalance(const std::string& shardName, const std::string& address, double amount);

        // Retrieves the balance of an address on a shard
        double getShardBalance(const std::string& shardName, const std::string& address) const;

        friend class SPHINXContract;

        // Validates the integrity of the blockchain
        bool isChainValid() const {
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

    private:
        // Represents a shard in the chain
        struct Shard {
            Chain chain;
            std::string bridgeAddress;
            std::string bridgeSecret;
            std::unordered_map<std::string, double> balances;
        };

        std::vector<Shard> shards_;  // Shards in the chain
        std::vector<SPHINXBlock::Block> blocks_;  // Blocks in the chain
        std::string publicKey_;  // Public key of the chain
        static constexpr uint32_t BLOCK_NOT_FOUND = std::numeric_limits<uint32_t>::max();  // Constant for block not found
        std::unordered_map<std::string, uint32_t> shardIndices_;  // Indices of shards in the chain

        std::unordered_map<std::string, double> balances_;  // Balances of addresses on the chain
        std::string bridgeAddress_;  // Address of the bridge
        std::string bridgeSecret_;  // Secret key for the bridge
        SPHINXChain::Chain targetChain_;  // Target chain for atomic swaps
    };


    // Genesis block
    Chain::Chain() {
        std::string genesisMessage = "Welcome to Post-Quantum era, The Beginning of a Secured-Trustless Network will start from here - SPHINX Network";
        SPHINXBlock::Block genesisBlock(SPHINXHash::SPHINX_256(genesisMessage));
        addBlock(genesisBlock);  
    }

    void Chain::addBlock(const SPHINXBlock::Block& block) {
        if (blocks_.empty()) {  // If the chain is empty
            blocks_.push_back(block);  // Add the block to the chain
        } else {
            if (block.verifyBlock(publicKey_)) {  // Verify the block using the public key
                blocks_.push_back(block);  // Add the block to the chain
            } else {
                throw std::runtime_error("Invalid block! Block verification failed.");  // Throw an error if the block verification fails
            }
        }
    }

    std::string Chain::getBlockHash(uint32_t blockHeight) const {
        if (blockHeight >= blocks_.size()) {  // If the block height is out of range
            throw std::out_of_range("Block height out of range.");  // Throw an out-of-range error
        }
        return blocks_[blockHeight].getBlockHash();  // Get the hash of the block at the given height
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    // Sidechain: in blockchain systems is an independent blockchain that runs in parallel with the main 
    // blockchain, connected through a two-way peg. Sidechains are often created to provide additional 
    // functionalities or scalability solutions while maintaining interoperability with the main chain.
    // They allow for the transfer of assets between the main chain and the sidechain, enabling 
    // specialized applications or experiments without affecting the main chain's performance and security.
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    void Chain::transferFromSidechain(const SPHINXChain::Chain& sidechain, const std::string& blockHash) {
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
        if (block.verifyBlock(publicKey_)) {  // Verify the block using the public key
            blocks_.push_back(block);  // Add the block to the chain
        } else {
            throw std::runtime_error("Invalid block! Block verification failed.");  // Throw an error if the block verification fails
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    // Bridge: In blockchain systems, a bridge is a mechanism that allows the transfer of assets or data
    // between two separate blockchains or networks. It acts as a connection point between different 
    // chains, facilitating the transfer of information or value. Bridges can be established to enable 
    // interoperability and interaction between chains that operate on different protocols or have 
    // different functionalities. They typically have their own addresses and secret keys for secure 
    // communication.
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    void Chain::handleBridgeTransaction(const std::string& bridge, const std::string& targetChain, const std::string& transaction) {
        if (bridge == "SPHINX") {  // Check if the bridge is "SPHINX"
            bool isValid = SPHINXVerify::validateTransaction(transaction);  // Validate the transaction
            if (!isValid) {  // If the transaction is not valid
                throw std::runtime_error("Invalid transaction! Transaction validation failed.");  // Throw an error
            }
            targetChain_.addTransaction(transaction);  // Add the transaction to the target chain
        } else {
            throw std::runtime_error("Invalid bridge!");  // If the bridge is invalid, throw an error
        }
    }

    nlohmann::json Chain::toJson() const {
        nlohmann::json chainJson;
        // Serialize the blocks
        nlohmann::json blocksJson = nlohmann::json::array();
        for (const SPHINXBlock::Block& block : blocks_) {
            blocksJson.push_back(block.toJson());
        }
        chainJson["blocks"] = blocksJson;

        // Serialize the public key
        chainJson["publicKey"] = publicKey_;

        return chainJson;
    }

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
        publicKey_ = chainJson["publicKey"].get<std::string>();
    }

    bool Chain::save(const nlohmann::json& chainJson, const std::string& filename) const {
        std::ofstream outputFile(filename);
        if (outputFile.is_open()) {
            outputFile << chainJson.dump(4);  // Write the formatted JSON data to the file
            outputFile.close();
            return true;
        }
        return false;
    }

    Chain Chain::load(const std::string& filename) {
        std::ifstream inputFile(filename);
        if (inputFile.is_open()) {
            json chainJson;
            inputFile >> chainJson;  // Read the JSON data from the file
            inputFile.close();
            Chain loadedChain;
            loadedChain.fromJson(chainJson);  // Deserialize the JSON data into a Chain object
            return loadedChain;
        }
        throw std::runtime_error("Failed to load chain from file: " + filename);
    }

    SPHINXBlock::Block Chain::getGenesisBlock() const {
        return blocks_.front();  // Return the first block in the chain
    }

    SPHINXBlock::Block Chain::getBlockAt(size_t index) const {
        if (index < blocks_.size()) {
            return blocks_[index];  // Return the block at the specified index
        } else {
            throw std::out_of_range("Index out of range");
        }
    }

    size_t Chain::getChainLength() const {
        return blocks_.size();  // Return the number of blocks in the chain
    }

    void Chain::visualizeChain() const {
        for (size_t i = 0; i < blocks_.size(); ++i) {
            const SPHINXBlock::Block& block = blocks_[i];
            std::cout << "Block " << i << " - Hash: " << block.getBlockHash() << std::endl;  // Print the index and hash of each block
        }
    }

    void Chain::connectToSidechain(const Chain& sidechain) {
        SidechainConnection connection(sidechain.getBridgeAddress(), sidechain.getBridgeSecret());  // Create a connection to the sidechain using its bridge address and secret
        connection.sync();  // Synchronize the connection
    }

    void Chain::transferFromSidechain(const std::string& sidechainAddress, const std::string& senderAddress, double amount) {
        double senderBalance = getBalance(senderAddress);  // Get the balance of the sender
        if (amount > senderBalance) {
            throw std::runtime_error("Sender does not have enough funds");  // Throw an error if the sender doesn't have enough funds
        }

        if (!TwoFactorAuthenticator::verifyCode(senderUsername, sender2FACode)) {
            throw std::runtime_error("Authentication failed");  // Throw an error if authentication fails
        }

        SPHINXKey::HybridKeypair keyPair = SPHINXKey::generate_and_perform_key_exchange();  // Generate and perform a key exchange
        std::string publicKey = SPHINXKey::calculatePublicKey(keyPair.merged_key.kyber_private_key.data());  // Calculate the public key
        SPHINXTrx::Transaction transferTransaction = createTransaction(sidechainAddress, senderAddress, amount);  // Create a transaction
        signTransaction(transferTransaction);  // Sign the transaction
        broadcastTransaction(transferTransaction);  // Broadcast the transaction
        handleTransfer(transferTransaction);  // Handle the transfer
    }

    void Chain::createBlockchainBridge(const Chain& targetChain) {
        std::string bridgeAddress = generateBridgeAddress();  // Generate a bridge address for the current chain
        std::string targetBridgeAddress = targetChain.generateBridgeAddress();  // Generate a bridge address for the target chain
        std::shared_ptr<CloudflareSecureBridgeConnection> connection = std::make_shared<CloudflareSecureBridgeConnection>(bridgeAddress, targetBridgeAddress);  // Create a connection using the bridge addresses
        connection->createBridge();  // Create a bridge using the connection
    }

    void Chain::handleBridgeTransaction(const std::string& bridgeAddress, const std::string& recipientAddress, double amount) {
        if (!bridge.verifyTransaction(bridgeAddress, amount)) {
            throw std::runtime_error("Invalid bridge transaction");  // Throw an error if the bridge transaction is invalid
        }

        if (!TwoFactorAuthenticator::verifyCode(senderUsername, sender2FACode)) {
            throw std::runtime_error("Authentication failed");  // Throw an error if authentication fails
        }

        SPHINXKey::HybridKeypair keyPair = SPHINXKey::generate_and_perform_key_exchange();  // Generate and perform a key exchange
        std::string publicKey = SPHINXKey::calculatePublicKey(keyPair.merged_key.kyber_private_key.data());  // Calculate the public key
        std::string transactionData = bridge.getTransactionData(bridgeAddress);  // Get the transaction data from the bridge
        std::string signature = SPHINXSign::sign(transactionData, keyPair.merged_key.kyber_private_key.data());  // Sign the transaction data

        if (!SPHINXVerify::verifySignature(transactionData, signature, publicKey)) {
            throw std::runtime_error("Authentication failed");  // Throw an error if the signature verification fails
        }

        std::string transactionHash = SPHINXHash::SPHINX_256(transactionData);  // Calculate the transaction hash
        targetChain.transfer(recipientAddress, amount);  // Transfer funds to the recipient address in the target chain
        updateBalance(recipientAddress, amount);  // Update the balance of the recipient address
        updateBalance(senderAddress, -amount);  // Update the balance of the sender address
    }

    void Chain::performAtomicSwap(const Chain& targetChain, const std::string& senderAddress, const std::string& receiverAddress, double amount) {
        double senderBalance = getBalance(senderAddress);  // Get the balance of the sender address
        double receiverBalance = targetChain.getBalance(receiverAddress);  // Get the balance of the receiver address in the target chain
        if (senderBalance < amount) {
            throw std::runtime_error("Sender does not have enough funds");  // Throw an error if the sender doesn't have enough funds
        }

        if (!TwoFactorAuthenticator::verifyCode(senderUsername, sender2FACode)) {
            throw std::runtime_error("Authentication failed");  // Throw an error if authentication fails
        }

        SPHINXTrx::Transaction senderTransaction = createTransaction(senderAddress, targetChain.getBridgeAddress(), amount);  // Create a transaction from the sender address to the target chain bridge address
        SPHINXTrx::Transaction receiverTransaction = targetChain.createTransaction(receiverAddress, senderAddress, amount);  // Create a transaction from the receiver address in the target chain to the sender address

        signTransaction(senderTransaction);  // Sign the sender transaction
        signTransaction(receiverTransaction);  // Sign the receiver transaction
        broadcastTransaction(senderTransaction);  // Broadcast the sender transaction
        targetChain.broadcastTransaction(receiverTransaction);  // Broadcast the receiver transaction

        while (true) {
            if (senderTransaction.isConfirmed() && receiverTransaction.isConfirmed()) {
                break;  // Exit the loop if both transactions are confirmed
            }
            std::this_thread::sleep_for(std::chrono::seconds(10));  // Sleep for 10 seconds before checking the confirmation status again
        }

        if (!verifyAtomicSwap(senderTransaction, targetChain) || !targetChain.verifyAtomicSwap(receiverTransaction, *this)) {
            throw std::runtime_error("Atomic swap verification failed");  // Throw an error if the atomic swap verification fails
        }

        updateBalance(senderAddress, -amount);  // Update the balance of the sender address
        targetChain.updateBalance(receiverAddress, amount);  // Update the balance of the receiver address in the target chain
    }

    void Chain::signTransaction(SPHINXTrx::Transaction& transaction) {
        std::string transactionData = bridge.getTransactionData(bridgeAddress_);  // Get the transaction data from the bridge
        std::string privateKey = SPHINXSign::getPrivateKey();  // Get the private key
        std::string signature = SPHINXSign::sign(transactionData, privateKey);  // Sign the transaction data using the private key
        transaction.setSignature(signature);  // Set the transaction signature
    }

    void Chain::broadcastTransaction(const SPHINXTrx::Transaction& transaction) {
        std::string transactionJson = transaction.toJson().dump();  // Convert the transaction to JSON
        bridge.broadcastTransaction(bridgeAddress_, transactionJson);  // Broadcast the transaction via the bridge
    }

    void Chain::updateBalance(const std::string& address, double amount) {
        balances_[address] += amount;  // Update the balance of the given address by adding the specified amount
    }

    double Chain::getBalance(const std::string& address) const {
        if (balances_.count(address) > 0) {
            return balances_.at(address);  // Return the balance of the given address if it exists
        }
        return 0.0;  // Return 0 if the balance of the given address is not found
    }

    bool Chain::verifyAtomicSwap(const SPHINXTrx::Transaction& transaction, const Chain& targetChain) const {
        std::string transactionData = bridge.getTransactionData(bridgeAddress_);
        std::string signature = transaction.getSignature();
        std::string senderPublicKey = transaction.getSenderPublicKey();
        // Verify the transaction signature and the bridge transaction in the target chain
        return SPHINXVerify::verifySignature(transactionData, signature, senderPublicKey) && targetChain.verifyBridgeTransaction(transaction);
    }

    void Chain::handleTransfer(const SPHINXTrx::Transaction& transaction) {
        std::string recipientAddress = transaction.getRecipientAddress();
        double amount = transaction.getAmount();
        updateBalance(recipientAddress, amount);  // Update the balance of the recipient address
    }

    std::string Chain::getBridgeAddress() const {
        return bridgeAddress_;
    }

    std::string Chain::getBridgeSecret() const {
        return bridgeSecret_;
    }


    //////////////////////////////////////////////////////////////////////////////////////////////////////
    // Shards: In blockchain systems, shards are smaller, independent chains that operate in parallel to 
    // the main blockchain. Sharding is a technique used to improve scalability by dividing the workload
    // across multiple chains, allowing for higher transaction throughput. Each shard typically contains
    // a subset of accounts or transactions, reducing the computational load and increasing overall 
    // network capacity.
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    void Chain::createShard(const std::string& shardName) {
        Shard shard;
        shard.bridgeAddress = shardName;
        shard.chain = Chain();
        shards_.push_back(shard);  // Add a new shard to the shard vector
        shardIndices_[shardName] = shards_.size() - 1;  // Store the shard index by shard name for quick access
    }

    void Chain::joinShard(const std::string& shardName, const Chain& shardChain) {
        auto it = shardIndices_.find(shardName);
        if (it == shardIndices_.end()) {
            throw std::runtime_error("Shard does not exist: " + shardName);  // Throw an error if the shard does not exist
        }
        shards_[it->second].chain = shardChain;  // Join the shard by assigning the shard chain to the corresponding shard
    }

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

        SPHINXKey::HybridKeypair keyPair = SPHINXKey::generate_and_perform_key_exchange();  // Generate and perform a key exchange
        std::string publicKey = SPHINXKey::calculatePublicKey(keyPair.merged_key.kyber_private_key.data());  // Calculate the public key
        SPHINXTrx::Transaction transferTransaction = createTransaction(shard.bridgeAddress, senderAddress, amount);  // Create a transaction to the shard bridge address
        signTransaction(transferTransaction);  // Sign the transaction
        broadcastTransaction(transferTransaction);  // Broadcast the transaction
        shard.chain.handleShardTransfer(shardName, transferTransaction);  // Handle the shard transfer in the shard chain
        updateBalance(senderAddress, -amount);  // Update the balance of the sender address
    }

    void Chain::handleShardTransfer(const std::string& shardName, const SPHINXTrx::Transaction& transaction) {
        auto it = shardIndices_.find(shardName);
        if (it == shardIndices_.end()) {
            throw std::runtime_error("Shard does not exist: " + shardName);  // Throw an error if the shard does not exist
        }
        Shard& shard = shards_[it->second];  // Get the reference to the shard
        shard.chain.handleTransfer(transaction);  // Handle the transfer in the shard chain
    }

    void Chain::handleShardBridgeTransaction(const std::string& shardName, const std::string& bridgeAddress, const std::string& recipientAddress, double amount) {
        auto it = shardIndices_.find(shardName);
        if (it == shardIndices_.end()) {
            throw std::runtime_error("Shard does not exist: " + shardName);  // Throw an error if the shard does not exist
        }
        Shard& shard = shards_[it->second];  // Get the reference to the shard
        if (!shard.bridge.verifyTransaction(bridgeAddress, amount)) {
            throw std::runtime_error("Invalid bridge transaction");  // Throw an error if the bridge transaction is invalid
        }

        if (!TwoFactorAuthenticator::verifyCode(senderUsername, sender2FACode)) {
            throw std::runtime_error("Authentication failed");  // Throw an error if authentication fails
        }

        SPHINXKey::HybridKeypair keyPair = SPHINXKey::generate_and_perform_key_exchange();  // Generate and perform a key exchange
        std::string publicKey = SPHINXKey::calculatePublicKey(keyPair.merged_key.kyber_private_key.data());  // Calculate the public key
        std::string transactionData = shard.bridge.getTransactionData(bridgeAddress);  // Get the transaction data from the shard bridge
        std::string signature = SPHINXSign::sign(transactionData, keyPair.merged_key.kyber_private_key.data());  // Sign the transaction data

        if (!SPHINXVerify::verifySignature(transactionData, signature, publicKey)) {
            throw std::runtime_error("Authentication failed");  // Throw an error if authentication fails
        }

        std::string transactionHash = SPHINXHash::SPHINX_256(transactionData);
        shard.chain.updateBalance(recipientAddress, amount);  // Update the balance of the recipient address in the shard chain
        shard.chain.updateBalance(senderAddress, -amount);  // Update the balance of the sender address in the shard chain
    }

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

    void Chain::updateShardBalance(const std::string& shardName, const std::string& address, double amount) {
        auto it = shardIndices_.find(shardName);
        if (it == shardIndices_.end()) {
            throw std::runtime_error("Shard does not exist: " + shardName);  // Throw an error if the shard does not exist
        }
        Shard& shard = shards_[it->second];  // Get the reference to the shard
        shard.balances[address] += amount;  // Update the balance of the given address in the shard
    }

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