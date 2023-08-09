// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// This code defines the Block class, which represents a block in a blockchain. The Block class contains various member variables 
// and member functions to handle block data, mining, signature verification, and serialization to JSON format.

// Namespace Definitions:
    // The code introduces three namespaces: SPHINXHash, SPHINXMerkleBlock, and SPHINXBlock.
    // Namespaces are used to group related functionality, and they help prevent naming conflicts.
    // The SPHINXHash namespace contains the SPHINX_256 function, which is used to calculate the hash of data using the SPHINX_256 
    // algorithm.
    // The SPHINXMerkleBlock namespace provides the constructMerkleTree function, which is used to construct the Merkle tree for the block.

// Private Member Variables:
    // The Block class has several private member variables that store information about a block in the blockchain.
    // previousHash_: The hash of the previous block in the blockchain.
    // merkleRoot_: The Merkle root hash of the transactions in the block.
    // signature_: The signature of the block.
    // blockHeight_: The position of the block within the blockchain.
    // timestamp_: The time when the block was created.
    // nonce_: A random value used in the mining process to find a valid block hash.
    // difficulty_: A measure of how hard it is to find a valid block hash (mining difficulty).
    // transactions_: The list of transactions included in the block.
    // blockchain_: A pointer to the blockchain (assuming SPHINXChain::Chain is a class).
    // checkpointBlocks_: A reference to the list of checkpoint blocks.
    // storedMerkleRoot_: A private member variable to store the Merkle root for signature verification purposes.
    // storedSignature_: A private member variable to store the signature for signature verification purposes.

// Constructors:
    // The class has two constructors to create Block objects.
    // The first constructor takes the hash of the previous block and initializes other member variables with default values. 
    // It sets the timestamp to the current time.
    // The second constructor additionally takes a vector of checkpoint blocks as input.

// Member Functions:
    // addTransaction: Adds a transaction to the block by appending it to the transactions_ vector.
    // calculateBlockHash: Calculates the block hash by concatenating relevant data and computing the SPHINX_256 hash of the block data.
    // calculateMerkleRoot: Calculates the Merkle root of the transactions in the block using the constructMerkleTree function from the 
    // SPHINXMerkleBlock namespace.
    // signMerkleRoot: Signs the Merkle root with SPHINCS+ private key and stores the signature and Merkle root for later verification.
    // verifySignature: Verifies the block's signature using the SPHINCS+ verification function available in the library.
    // verifyMerkleRoot: Verifies the block's Merkle root using the verifyMerkleRoot function from the SPHINXMerkleBlock namespace.
    // verifyBlock: Verifies the entire block (signature and Merkle root) with the given public key.
    // mineBlock: Attempts to mine the block by finding a valid hash that meets the mining difficulty level.
    // toJson: Converts the block object to a JSON format.
    // fromJson: Parses a JSON object and assigns values to the corresponding member variables.
    // save: Saves the block data to a file in JSON format.
    // load: Loads a block from a file and initializes a new Block object from the JSON data.
    // saveToDatabase: Saves the block data to a distributed database as a JSON string.
    // loadFromDatabase: Loads a block from the distributed database and initializes a new Block object from the JSON data.
    // getStoredMerkleRoot and getStoredSignature: Getter functions to retrieve the stored Merkle root and signature.

// The Block class provides functionalities to handle block data, calculate block hashes, construct Merkle trees, mine blocks, sign and 
// verify block signatures, serialize block data to JSON format, and store and retrieve blocks from a distributed database.
    
// The code represents a simplified implementation of a blockchain system with functionality related to block creation, verification, 
// mining, Merkle tree construction, and database interaction.
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



#include <stdexcept>
#include <fstream> 
#include <iostream>
#include <ctime>
#include <string>
#include <vector>
#include <array>
#include <map>

#include "Block.hpp"
#include "Hash.hpp"
#include "Sign.hpp"
#include "json.hh"
#include "MerkleBlock.hpp"
#include "Transaction.hpp"
#include "Chain.hpp"
#include "PoW.hpp"
#include "db.hpp"
#include "Verify.hpp"
#include "PoW.hpp"
#include "Key.hpp"
#include "Params.hpp"
#include "Utxo.hpp"


using json = nlohmann::json;

namespace SPHINXHash {
    std::string SPHINX_256(const std::string& data); // Function declaration for SPHINX_256
}

namespace SPHINXMerkleBlock {
    class MerkleBlock; // Forward declaration of the MerkleBlock class

    // Correct the constructMerkleTree function declaration
    std::string constructMerkleTree(const std::vector<SPHINXTrx::Transaction>& signedTransactions);
}

namespace SPHINXBlock {
    class Block {
    private:
        // Private member variables
        std::string previousHash_;               // The hash of the previous block in the blockchain
        std::string merkleRoot_;                 // The Merkle root hash of the transactions in the block
        std::string signature_;                  // The signature of the block
        uint32_t blockHeight_;                   // The position of the block within the blockchain
        std::time_t timestamp_;                  // The time when the block was created
        uint32_t nonce_;                         // A random value used in the mining process to find a valid block hash
        uint32_t difficulty_;                    // A measure of how hard it is to find a valid block hash (mining difficulty)
        uint32_t version_;                       // Add this private member variable to store the version of the block
        std::vector<std::string> transactions_;  // The list of transactions included in the block
        SPHINXChain::Chain* blockchain_;         // A pointer to the blockchain (assuming SPHINXChain::Chain is a class)
        const std::vector<std::string>& checkpointBlocks_; // Reference to the list of checkpoint blocks

        // Private member variables to store Merkle root and signature
        std::string storedMerkleRoot_;
        std::string storedSignature_;

    public:
        static const uint32_t MAX_BLOCK_SIZE = 1000;       // Maximum allowed block size in number of transactions
        static const uint32_t MAX_TIMESTAMP_OFFSET = 600;  // Maximum allowed timestamp difference from current time

        // Constructors
        Block(const std::string& previousHash)
            : previousHash_(previousHash), blockHeight_(0), nonce_(0), difficulty_(0) {
            timestamp_ = std::time(nullptr); // Set the timestamp to the current time
        }

        Block(const std::string& previousHash, uint32_t version)
            : previousHash_(previousHash), blockHeight_(0), nonce_(0), difficulty_(0), version_(version) {
            timestamp_ = std::time(nullptr); // Set the timestamp to the current time
        }

        // Getter function to retrieve the block version
        uint32_t getVersion() const {
            return version_;
        }

        // Function to add a transaction to the block
        void addTransaction(const std::string& transaction) {
            transactions_.push_back(transaction);
        }

        // Function to calculate the block hash
        std::string calculateBlockHash() const {
            // Concatenate all the data elements that uniquely identify the block
            std::string blockData = previousHash_ + std::to_string(timestamp_);

            for (const auto& transaction : transactions_) {
                blockData += transaction;
            }

            // Calculate the SPHINX_256 hash of the block data
            std::string blockHash = SPHINXHash::SPHINX_256(blockData);

            return blockHash;
        }

        // Function to calculate the Merkle root
        std::string calculateMerkleRoot() const {
            return SPHINXMerkleBlock::constructMerkleTree(transactions_);
        }

        // Function to sign the Merkle root with SPHINCS+ private key and store the signature
        void signMerkleRoot(const SPHINXPrivKey& privateKey, const std::string& merkleRoot) {
            // SPHINCS+ signing function is available in the "Sign.hpp"
            signature_ = SPHINXSign::sign_data(merkleRoot, privateKey);
            storedMerkleRoot_ = merkleRoot;
        }

        // Function to verify the block's signature with the given public key
        bool verifySignature(const SPHINXPubKey& publicKey) const {
            // Calculate the block hash
            std::string blockHash = calculateBlockHash();

            // Assuming the SPHINCS+ verification function is available in the library
            return SPHINXSign::verify_data(blockHash, signature_, publicKey);
        }

        // Function to verify the block's Merkle root with the given public key
        bool verifyMerkleRoot(const SPHINXPubKey& publicKey) const {
            return merkleBlock.verifyMerkleRoot(storedMerkleRoot_, transactions_);
        }

        // Function to verify the entire block with the given public key
        bool verifyBlock(const SPHINXPubKey& publicKey) const {
            // Call the verifySignature and verifyMerkleRoot functions
            return verifySignature(publicKey) && verifyMerkleRoot(publicKey);
        }

        // Function to mine the block with the given difficulty
        bool mineBlock(uint32_t difficulty) {
            std::string target(difficulty, '0');  // Create a target string with the specified difficulty level

            while (true) {
                nonce_++;  // Increment the nonce

                // Calculate the block hash
                std::string blockHash = calculateBlockHash();

                // Check if the block hash meets the target difficulty
                if (blockHash.substr(0, difficulty) == target) {
                    // Block successfully mined

                    //*
                    // UTXO function used in the mineBlock function in this version of block.cpp. 
                    // The mineBlock function is responsible for mining a block by finding a valid hash 
                    // that meets the required difficulty level. When a block is successfully mined, 
                    // the mineBlock function updates the UTXO set based on the transactions included 
                    // in the block. The UTXO set represents the unspent transaction outputs, and 
                    // updating it is an essential part of the blockchain's functioning to ensure the 
                    // correctness of transactions.
                    //*

                    // Update the UTXO set based on the transactions in the block
                    std::map<std::string, SPHINXUtxo::UTXO> utxoSet; // Assuming you have access to the UTXO set
                    SPHINXUtxo::updateUTXOSet(*this, utxoSet);

                    return true;
                }
            }

            // Block mining failed
            return false;
        }

        // Setters and getters for the remaining member variables
        void setMerkleRoot(const std::string& merkleRoot) {
            merkleRoot_ = merkleRoot;
        }

        // Sets the signature of the block
        void setSignature(const std::string& signature) {
            signature_ = signature;
        }

        // Sets the block height (the position of the block within the blockchain)
        void setBlockHeight(uint32_t blockHeight) {
            blockHeight_ = blockHeight;
        }

        // Sets the nonce (a random value used in the mining process to find a valid block hash)
        void setNonce(uint32_t nonce) {
            nonce_ = nonce;
        }

        // Sets the difficulty level of mining (a measure of how hard it is to find a valid block hash)
        void setDifficulty(uint32_t difficulty) {
            difficulty_ = difficulty;
        }

        // Sets the transactions included in the block
        void setTransactions(const std::vector<std::string>& transactions) {
            transactions_ = transactions;
        }

        // Returns the previous hash (the hash of the previous block in the blockchain)
        std::string getPreviousHash() const {
            return previousHash_;
        }

        // Returns the Merkle root (the root hash of the Merkle tree constructed from the transactions)
        std::string getMerkleRoot() const {
            return merkleRoot_;
        }

        // Returns the signature of the block
        std::string getSignature() const {
            return signature_;
        }

        // Returns the block height (the position of the block within the blockchain)
        uint32_t getBlockHeight() const {
            return blockHeight_;
        }

        // Returns the timestamp (the time when the block was created)
        std::time_t getTimestamp() const {
            return timestamp_;
        }

        // Returns the nonce (a random value used in the mining process to find a valid block hash)
        uint32_t getNonce() const {
            return nonce_;
        }

        // Returns the difficulty level of mining (a measure of how hard it is to find a valid block hash)
        uint32_t getDifficulty() const {
            return difficulty_;
        }

        // Returns the transactions included in the block
        std::vector<std::string> getTransactions() const {
            return transactions_;
        }

        Block::Block(const std::string& prevBlockHash, const std::string& timestamp, const std::string& nonce, const std::vector<Transaction>& transactions) {
            this->previousHash_ = prevBlockHash;
            this->timestamp_ = timestamp;
            this->nonce_ = nonce;
            this->transactions_ = transactions;

            // Merkle tree construction function is already implemented in "MerkleBlock.cpp"
            std::string merkleRoot = SPHINXMerkleBlock::constructMerkleTree(transactions);
            this->setMerkleRoot(merkleRoot); // Set the Merkle root for this block
        }

        // Block headers
        nlohmann::json toJson() const {
            // Convert the block object to JSON format
            nlohmann::json blockJson;

            blockJson["version"] = version_;               // Store the version in the JSON object
            blockJson["previousHash"] = previousHash_;     // Store the previous hash in the JSON object
            blockJson["merkleRoot"] = merkleRoot_;         // Store the Merkle root in the JSON object
            blockJson["signature"] = signature_;           // Store the signature in the JSON object
            blockJson["blockHeight"] = blockHeight_;       // Store the block height in the JSON object
            blockJson["timestamp"] = timestamp_;           // Store the timestamp in the JSON object
            blockJson["nonce"] = nonce_;                   // Store the nonce in the JSON object
            blockJson["difficulty"] = difficulty_;         // Store the difficulty in the JSON object

            nlohmann::json transactionsJson = nlohmann::json::array();
            for (const std::string& transaction : transactions_) {
                transactionsJson.push_back(transaction);   // Store each transaction in the JSON array
            }
            blockJson["transactions"] = transactionsJson;  // Store the transactions array in the JSON object

            return blockJson;                              // Return the JSON object
        }

        void fromJson(const nlohmann::json& blockJson) {
            // Parse the JSON object and assign values to the corresponding member variables
            version_ = blockJson["version"].get<uint32_t>();                  // Retrieve the version from the JSON object
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

        bool save(const std::string& filename) const {
            // Convert the block object to JSON format
            nlohmann::json blockJson = toJson();

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

        static Block load(const std::string& filename) {
            // Open the input file stream
            std::ifstream inputFile(filename);
            if (inputFile.is_open()) {
                // Parse the JSON data from the file
                nlohmann::json blockJson;
                inputFile >> blockJson;
                inputFile.close();

                // Create a new block object and initialize it from the parsed JSON
                Block loadedBlock("");
                loadedBlock.fromJson(blockJson);
                return loadedBlock; // Return the loaded block
            }
            throw std::runtime_error("Failed to load block from file: " + filename); // Throw an exception if the file could not be opened
        }

        bool saveToDatabase(SPHINXDb::DistributedDb& distributedDb) const {
            // Convert the block object to JSON format
            nlohmann::json blockJson = toJson();

            // Get the block hash as the database key
            std::string blockId = getBlockHash();

            // Convert the JSON data to a string
            std::string blockData = blockJson.dump();

            // Save the block data to the distributed database
            distributedDb.saveData(blockData, blockId);

            return true;
        }

        static Block loadFromDatabase(const std::string& blockId, SPHINXDb::DistributedDb& distributedDb) {
            std::string blockData = distributedDb.loadData(blockId); // Load the block data from the distributed database
            nlohmann::json blockJson = nlohmann::json::parse(blockData); // Parse the JSON string

            Block loadedBlock("");
            loadedBlock.fromJson(blockJson); // Initialize the block from the JSON
            return loadedBlock;
        }

        // Getter functions to retrieve the stored Merkle root and signature
        std::string getStoredMerkleRoot() const {
            return storedMerkleRoot_;
        }

        std::string getStoredSignature() const {
            return storedSignature_;
        }
    };
} // namespace SPHINXBlock


//Usage
int main() {
    // Create a new block with a previous hash
    std::string previousHash = "00000000000000000000000000000000"; // A placeholder for the previous block's hash
    SPHINXBlock::Block block(previousHash);

    // Add transactions to the block
    block.addTransaction("Transaction 1");
    block.addTransaction("Transaction 2");
    block.addTransaction("Transaction 3");

    // Calculate the Merkle root
    std::string merkleRoot = block.calculateMerkleRoot();

    // Sign the Merkle root with the private key (assuming you have a private key)
    SPHINXPrivKey privateKey = "your_private_key_here"; // Replace this with your actual private key
    block.signMerkleRoot(privateKey, merkleRoot);

    // Mine the block with a specified difficulty (e.g., 3 leading zeros)
    uint32_t miningDifficulty = 3;
    bool mined = block.mineBlock(miningDifficulty);

    if (mined) {
        // Print the block's information
        std::cout << "Block successfully mined:" << std::endl;
        std::cout << "Block Height: " << block.getBlockHeight() << std::endl;
        std::cout << "Block Hash: " << block.calculateBlockHash() << std::endl;
        std::cout << "Merkle Root: " << block.getMerkleRoot() << std::endl;
        std::cout << "Signature: " << block.getSignature() << std::endl;

        // Verify the block's signature and Merkle root
        bool isSignatureValid = block.verifySignature("your_public_key_here"); // Replace this with your actual public key
        bool isMerkleRootValid = block.verifyMerkleRoot("your_public_key_here");

        if (isSignatureValid && isMerkleRootValid) {
            std::cout << "Block signature and Merkle root are valid." << std::endl;
        } else {
            std::cout << "Block signature or Merkle root verification failed." << std::endl;
        }
    } else {
        std::cout << "Block mining failed." << std::endl;
    }

    return 0;
} // namespace SPHINXBlock
