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
// This code appears to be a C++ program that implements various classes and namespaces related to blockchain functionality. Let's go through the code and explain each part in detail:

// SPHINXVerify namespace:

  // Contains the SPHINX_PublicKey class, which is a placeholder definition for the SPHINX public key.
  // Defines the verifySignature function, which is used to verify the signature of a block. The function takes the block hash, signature, and a public key as parameters.

// SPHINXHash namespace:

  // Contains the SPHINX_256 function, which calculates the SPHINX-256 hash of the provided data. The function takes a string of data as input and returns the hash as a string.

// SPHINX_Chain namespace:

  // Contains the Chain class, which represents a blockchain. It provides a function called addBlock to add a block to the chain. The addBlock function takes a SPHINXMerkleBlock::MerkleBlock object as a parameter.

// SPHINXDb namespace:

  // Contains the DistributedDb class, which represents a distributed database. It provides functions to save and load data with a specific block hash. The saveData function takes data and a block hash as parameters, while the loadData function takes a block ID as a parameter.

// SPHINXMerkleBlock namespace:

  // Contains the MerkleBlock class, which is responsible for constructing and verifying the Merkle tree.
  // The constructMerkleTree function constructs the Merkle tree for a vector of SPHINXTrx::Transaction objects and returns the root hash of the tree as a string.
  // The verifyMerkleRoot function verifies the Merkle root by comparing the constructed root with the provided root for a given set of transactions.

// SPHINXBlock namespace:

  // Contains the Block class, representing a block in the blockchain.
  // The constructor Block initializes a block object with the previous block's hash and sets other member variables such as the timestamp, block height, nonce, and difficulty.
  // The calculateBlockHash function calculates the block's hash by concatenating the previous hash, Merkle root, timestamp, nonce, and transactions. It also utilizes the Proof-of-Work algorithm from SPHINXPoW to solve the nonce and obtain the block hash.
  // The addTransaction function adds a transaction to the block's list of transactions.
  // The calculateMerkleRoot function uses the MerkleBlock class to calculate the Merkle root of the block's transactions.
  // The getBlockHash function returns the block's hash by calling calculateBlockHash.
  // The verifyBlock function verifies the block's signature and Merkle root using the provided public key.
  // The verifySignature function calculates the block's hash and verifies its signature using the provided public key.
  // The setBlockHeight and getBlockHeight functions are used to set and get the block's height.
  // The getTransactionCount function returns the number of transactions in the block.
  // The isValid function checks if the block is valid based on the transaction count and timestamp.
  // The setBlockchain function sets the blockchain pointer to the provided blockchain object.
  // The addToBlockchain function adds the block to the blockchain if the blockchain pointer is valid.
  // The toJson function converts the block object to JSON format.
  // The fromJson function parses a JSON object and assigns the values to the corresponding member variables.
  // The save function saves the block to a file in JSON format.
  // The load function loads a block from a file in JSON format.
  // The saveToDatabase function converts the block object to JSON format, gets the block hash as the database key, converts the JSON data to a string, and saves the block data to the distributed database.
  // The loadFromDatabase function loads a block from the distributed database based on the provided block ID.

// The code snippet represents a partial implementation of a blockchain, including block creation, Merkle tree construction, block verification, serialization to JSON, and saving/loading to/from a file or distributed database.

// The code implements classes and functions for block management, Merkle tree construction and verification, signature verification, hash generation, and saving/loading block data to a distributed database. It provides the necessary functionality to work with blocks in a blockchain system.
/////////////////////////////////////////////////////////////////////////////////////////////////////////



#include <stdexcept>
#include <fstream>
#include <iostream>
#include <ctime>
#include <string>
#include <vector>

#include "Block.hpp"
#include "Hash.hpp"
#include "Sign.hpp"
#include "json.hpp"
#include "MerkleBlock.hpp"
#include "Chain.hpp"
#include "PoW.hpp"
#include "db.hpp"


using json = nlohmann::json;

namespace SPHINXVerify {
    class SPHINX_PublicKey {
    public:
        // Placeholder definition for SPHINX_PublicKey
    };

    // Function to verify the signature of a block
    bool verifySignature(const std::string& blockHash, const std::string& signature, const SPHINX_PublicKey& publicKey);
}

namespace SPHINXHash {
    // Function to calculate the SPHINX-256 hash of data
    std::string SPHINX_256(const std::string& data);
}

namespace SPHINX_Chain {
    class Chain {
    public:
        // Function to add a block to the chain
        void addBlock(const SPHINXMerkleBlock::MerkleBlock& block);
    };
}

namespace SPHINXDb {
    class DistributedDb {
    public:
        // Function to save data with a specific block hash
        void saveData(const std::string& data, const std::string& blockHash);

        // Function to load data for a given block ID
        std::string loadData(const std::string& blockId);
    };
}

namespace SPHINXMerkleBlock {
    class MerkleBlock {
    public:
        // Function to construct the Merkle tree
        std::string constructMerkleTree(const std::vector<SPHINXTrx::Transaction>& signedTransactions) const {
            // If there are no signed transactions, return an empty string
            if (signedTransactions.empty()) {
                return "";
            }

            // If there is only one signed transaction, return its SPHINX-256 hash
            if (signedTransactions.size() == 1) {
                return SPHINXHash::SPHINX_256(signedTransactions[0].transaction);
            }

            // Split the signed transactions into two halves
            size_t mid = signedTransactions.size() / 2;
            std::vector<SPHINXTrx::Transaction> leftTransactions(signedTransactions.begin(), signedTransactions.begin() + mid);
            std::vector<SPHINXTrx::Transaction> rightTransactions(signedTransactions.begin() + mid, signedTransactions.end());

            // Recursively construct the Merkle tree for the left and right transactions
            std::string leftRoot = constructMerkleTree(leftTransactions);
            std::string rightRoot = constructMerkleTree(rightTransactions);

            // Concatenate the left and right roots and calculate the SPHINX-256 hash
            return SPHINXHash::SPHINX_256(leftRoot + rightRoot);
        }

        // Function to verify the Merkle root
        bool verifyMerkleRoot(const std::string& merkleRoot, const std::vector<SPHINXTrx::Transaction>& transactions) const {
            // If there are no transactions, the Merkle root should be empty
            if (transactions.empty()) {
                return merkleRoot.empty();
            }

            // Construct the Merkle root for the given transactions
            std::string constructedRoot = constructMerkleTree(transactions);

            // Compare the constructed root with the provided Merkle root
            return (constructedRoot == merkleRoot);
        }

        // Function to verify the Merkle root for signed transactions
        bool verifyMerkleRoot(const std::string& merkleRoot, const std::vector<SPHINXTrx::Transaction>& signedTransactions) const {
            // Implementation of verifyMerkleRoot...
        }
    };
}

namespace SPHINXBlock {
    Block::Block(const std::string& previousHash)
        : previousHash_(previousHash), blockHeight_(0), nonce_(0), difficulty_(0) {
        timestamp_ = std::time(nullptr);
    }

    std::string Block::calculateBlockHash() const {
        std::string dataToHash = previousHash_ + merkleRoot_ + std::to_string(timestamp_) + std::to_string(nonce_);
        for (const std::string& transaction : transactions_) {
            dataToHash += transaction;
        }

        // Solve the nonce using the Proof-of-Work algorithm from PoW.hpp
        int difficulty = 4; // Specify the desired difficulty level
        std::string blockHash = SPHINXPoW::solveNonce(dataToHash, difficulty);

        return blockHash;
    }

    void Block::addTransaction(const std::string& transaction) {
        transactions_.push_back(transaction);
    }

    std::string Block::calculateMerkleRoot() const {
        return merkleBlock_.constructMerkleTree(transactions_);
    }

    std::string Block::getBlockHash() const {
        return calculateBlockHash();
    }

    bool Block::verifyBlock(const SPHINXVerify::SPHINX_PublicKey& publicKey) const {
        // Verify the block's signature and Merkle root
        return verifySignature(publicKey) && merkleBlock_.verifyMerkleRoot(merkleRoot_, transactions_);
    }

    bool Block::verifySignature(const SPHINXVerify::SPHINX_PublicKey& publicKey) const {
        // Calculate the block's hash and verify its signature using the provided public key
        std::string blockHash = calculateBlockHash();
        return SPHINXVerify::verifySignature(blockHash, signature_, publicKey);
    }

    void Block::setBlockHeight(uint32_t height) {
        // Set the block's height
        blockHeight_ = height;
    }

    uint32_t Block::getBlockHeight() const {
        // Get the block's height
        return blockHeight_;
    }

    uint32_t Block::getTransactionCount() const {
        // Get the number of transactions in the block
        return transactions_.size();
    }

    bool Block::isValid() const {
        // Check if the block is valid based on transaction count and timestamp
        return (transactions_.size() <= MAX_BLOCK_SIZE) && (timestamp_ <= std::time(nullptr) + MAX_TIMESTAMP_OFFSET);
    }

    void Block::setBlockchain(SPHINX_Chain::Chain* blockchain) {
        // Set the blockchain pointer to the provided blockchain object
        blockchain_ = blockchain;
    }

    void Block::addToBlockchain() {
        if (blockchain_) {
            // Add the block to the blockchain (if the blockchain pointer is valid)
            blockchain_->addBlock(merkleBlock_);
        }
    }

    // Block headers
    json Block::toJson() const {
        // Convert the block object to JSON format
        json blockJson;

        blockJson["previousHash"] = previousHash_;     // Store the previous hash in the JSON object
        blockJson["merkleRoot"] = merkleRoot_;         // Store the Merkle root in the JSON object
        blockJson["signature"] = signature_;           // Store the signature in the JSON object
        blockJson["blockHeight"] = blockHeight_;       // Store the block height in the JSON object
        blockJson["timestamp"] = timestamp_;           // Store the timestamp in the JSON object
        blockJson["nonce"] = nonce_;                   // Store the nonce in the JSON object
        blockJson["difficulty"] = difficulty_;         // Store the difficulty in the JSON object

        json transactionsJson = json::array();
        for (const std::string& transaction : transactions_) {
            transactionsJson.push_back(transaction);   // Store each transaction in the JSON array
        }
        blockJson["transactions"] = transactionsJson;  // Store the transactions array in the JSON object

        return blockJson;                              // Return the JSON object
    }

    void Block::fromJson(const json& blockJson) {
        // Parse the JSON object and assign values to the corresponding member variables
        previousHash_ = blockJson["previousHash"].get<std::string>();     // Retrieve the previous hash from the JSON object
        merkleRoot_ = blockJson["merkleRoot"].get<std::string>();         // Retrieve the Merkle root from the JSON object
        signature_ = blockJson["signature"].get<std::string>();           // Retrieve the signature from the JSON object
        blockHeight_ = blockJson["blockHeight"].get<uint32_t>();          // Retrieve the block height from the JSON object
        timestamp_ = blockJson["timestamp"].get<std::time_t>();           // Retrieve the timestamp from the JSON object
        nonce_ = blockJson["nonce"].get<uint32_t>();                      // Retrieve the nonce from the JSON object
        difficulty_ = blockJson["difficulty"].get<uint32_t>();            // Retrieve the difficulty from the JSON object

        transactions_.clear();
        const json& transactionsJson = blockJson["transactions"];
        for (const auto& transactionJson : transactionsJson) {
            transactions_.push_back(transactionJson.get<std::string>());  // Retrieve each transaction from the JSON array
        }
    }


    bool Block::save(const std::string& filename) const {
        // Convert the block object to JSON format
        json blockJson = toJson();
        
        // Open the output file stream
        std::ofstream outputFile(filename);
        if (outputFile.is_open()) {
            // Write the JSON data to the file with indentation
            outputFile << blockJson.dump(4);
            outputFile.close();
            return true; // Return true to indicate successful save
        }
        return false; // Return false to indicate failed save
    }

    Block Block::load(const std::string& filename) {
        // Open the input file stream
        std::ifstream inputFile(filename);
        if (inputFile.is_open()) {
            // Parse the JSON data from the file
            json blockJson;
            inputFile >> blockJson;
            inputFile.close();

            // Create a new block object and initialize it from the parsed JSON
            Block loadedBlock;
            loadedBlock.fromJson(blockJson);
            return loadedBlock; // Return the loaded block
        }
        throw std::runtime_error("Failed to load block from file: " + filename); // Throw an exception if the file could not be opened
    }

    bool Block::saveToDatabase(SPHINXDb::DistributedDb& distributedDb) const {
        // Convert the block object to JSON format
        json blockJson = toJson();

        // Get the block hash as the database key
        std::string blockId = getBlockHash();
        
        // Convert the JSON data to a string
        std::string blockData = blockJson.dump();

        // Save the block data to the distributed database
        distributedDb.saveData(blockData, blockId);

        return true;
    }

    Block Block::loadFromDatabase(const std::string& blockId, SPHINXDb::DistributedDb& distributedDb) {
        std::string blockData = distributedDb.loadData(blockId); // Load the block data from the distributed database
        json blockJson = json::parse(blockData); // Parse the JSON string

        Block loadedBlock;
        loadedBlock.fromJson(blockJson); // Initialize the block from the JSON
        return loadedBlock;
    }
} // namespace SPHINXBlock