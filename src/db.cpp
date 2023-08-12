// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The code introduces a new DistributedDb class that represents a distributed database. It maintains a vector of Node objects, each 
// representing a network node with its own Db database.

// The DistributedDb class provides methods to add nodes to the network, store transactions in each node's database, and retrieve 
// transaction data from any node's database.

  // The transactionIndex is an unordered map that serves as a centralized index for fast transaction lookup across the network. It maps 
  // transaction IDs to their corresponding data.
  // When a transaction is stored, the code iterates over all network nodes and stores the transaction in each node's database using the 
  // storeTransaction method.
  // The isTransactionStored method checks if a transaction is stored in any node's database by performing a lookup in the 
  // transactionIndex.
  // The getTransactionData method retrieves the transaction data from any node's database by performing a lookup in the transactionIndex.

// Note: This code provides a basic implementation of a decentralized database, but it does not include networking functionality, consensus
// mechanisms, or data replication techniques. Implementing those aspects requires additional code and infrastructure setup specific to 
// decentralized network architecture.
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////




#include <fstream>
#include <fstream>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "Node.hpp"
#include "db.hpp"
#include "Wallet.hpp"
#include "Consensus/Consensus.hpp"
#include "Consensus/Contract.hpp"
#include "Verify.hpp"
#include "Block.hpp"
#include "checksum.hpp"


using json = nlohmann::json;

class Block {
public:
    Block(const std::string& data) {
        // Constructor implementation
        this->data = data;
    }

    std::string toJson() const {
        json blockJson;

        blockJson["data"] = data;
        blockJson["previousHash"] = previousHash_;
        blockJson["merkleRoot"] = merkleRoot_;
        blockJson["signature"] = signature_;
        blockJson["timestamp"] = timestamp_;
        blockJson["nonce"] = nonce_;
        blockJson["difficulty"] = difficulty_;
        blockJson["transactions"] = transactions_;

        return blockJson.dump();
    }

    std::vector<std::string> getTransactions() const {
        // Extract and return the transactions from the block data
        return transactions_;
    }

    bool verifyBlock(const SPHINXVerify::SPHINX_PublicKey& publicKey) const {
        // Verify the block by checking the signature and the Merkle root of the transactions
        std::string blockHash = calculateBlockHash();
        return SPHINXVerify::verifySignature(blockHash, signature_, publicKey);
    }

    std::string calculateBlockHash() const {
        // Calculate the hash of the block by concatenating the previous hash, Merkle root, timestamp, nonce, and transactions
        std::string dataToHash = previousHash_ + merkleRoot_ + std::to_string(timestamp_) + std::to_string(nonce_);
        for (const std::string& transaction : transactions_) {
            dataToHash += transaction;
        }
        return SPHINXHash::SPHINX_256(dataToHash);
    }

public: // Move the following member variables outside the private section
    std::string previousHash_;
    std::string merkleRoot_;
    std::string signature_;
    std::time_t timestamp_;
    uint32_t nonce_;
    uint32_t difficulty_;
    std::vector<std::string> transactions_;

private:
    std::string data;
};


namespace SPHINXConsensus {
    class Transaction {
    public:
        Transaction(const std::string& id, const std::string& data) {
            // Constructor implementation
            this->id = id;
            this->data = data;
        }

        std::string getId() const {
            return id;
        }

        std::string getData() const {
            return data;
        }

    private:
        std::string id;
        std::string data;
    };

    class Consensus {
    public:
        Consensus() {
            // Initialize the transactions map
            transactions = std::unordered_map<std::string, std::string>();
        }

        void validateAndAddTransaction(const Transaction& transaction) {
            // Method implementation
            std::cout << "Validating and adding transaction with ID: " << transaction.getId() << std::endl;
            std::cout << "Transaction data: " << transaction.getData() << std::endl;

            // For simplicity, we'll just check if the transaction data is valid
            if (transaction.getData() == "valid") {
                // The transaction is valid, so we add it to the blockchain
                // For simplicity, we'll just store the transaction data in a map
                transactions[transaction.getId()] = transaction.getData();
            } else {
                // The transaction is invalid, so we discard it
            }
        }

    private:
        std::unordered_map<std::string, std::string> transactions;
    };
}

class SPHINXContract {
public:
  SPHINXContract(int balance) : database() {
    // Constructor implementation
    this->balance = balance;
  }

  void storeTransaction(const std::string& transactionId, const std::string& transactionData) {
    // Method implementation
    std::cout << "Storing transaction with ID: " << transactionId << std::endl;
    std::cout << "Transaction data: " << transactionData << std::endl;

    // Split the transaction data into the agreement and checksum
    std::string agreement = transactionData.substr(0, transactionData.find("checksum"));
    std::string checksum = transactionData.substr(transactionData.find("checksum") + 8);

    // Store the agreement in the smart contract
    database.storeTransaction(agreement, checksum);
  }

private:
  int balance;
  SPHINXDb::Db database; // Add an instance of SPHINXDb::Db as a member variable
};


namespace SPHINXDb {

    class Db {
    public:
        void storeTransaction(const std::string& transactionId, const std::string& transactionData) {
            // Method implementation
            std::cout << "Storing transaction with ID: " << transactionId << std::endl;
            std::cout << "Transaction data: " << transactionData << std::endl;

            // For simplicity, we'll just store the transaction data in a map
            transactions[transactionId] = transactionData;
        }

        void storeBlock(const std::string& blockId, const std::string& blockData) {
            // Method implementation
            std::cout << "Storing block with ID: " << blockId << std::endl;
            std::cout << "Block data: " << blockData << std::endl;

            // For simplicity, we'll just store the block data in a map
            blocks[blockId] = blockData;
        }

    private:
        std::map<std::string, std::string> transactions;
        std::map<std::string, std::string> blocks;
    };


    // Define a structure to represent a network node
    struct Node {
        std::string nodeId;
        Db database;
    };

    class DistributedDb {
    private:
        std::vector<Node> networkNodes;
        std::unordered_map<std::string, std::string> transactionIndex;
        std::unordered_map<std::string, SPHINXBlock::Block> blockIndex; // Store blocks in a map
        std::unordered_map<std::string, std::unordered_set<std::string>> accountTransactions; // Track transactions by account
        SPHINXConsensus::Consensus consensusAlgorithm; // Consensus algorithm instance
        SPHINXContract smartContract; // Smart contract instance

    public:
        DistributedDb() : consensusAlgorithm(), smartContract(100) {
            // Initialize the distributed database
            // Create a new consensus algorithm instance
            consensusAlgorithm = SPHINXConsensus::Consensus();

            // Create a new smart contract instance
            smartContract = SPHINXContract(100);
        }

        void addNode(const std::string& nodeId) {
            // Add a new node to the network
            Node newNode;
            newNode.nodeId = nodeId;
            networkNodes.push_back(newNode);
        }

        void storeTransaction(const std::string& transactionId, const std::string& transactionData) {
            // Store the transaction in the database of each node in the network
            for (Node& node : networkNodes) {
                node.database.storeTransaction(transactionId, transactionData);
            }

            // Update the transaction index for fast lookup
            transactionIndex[transactionId] = transactionData;

            // Update accountTransactions to track transactions by account
            std::string sender = extractSender(transactionData);
            std::string receiver = extractReceiver(transactionData);
            accountTransactions[sender].insert(transactionId);
            accountTransactions[receiver].insert(transactionId);

            // Create a Transaction object from the transaction data
            SPHINXConsensus::Transaction transaction(transactionId, transactionData);

            // Validate and add the transaction using the consensus algorithm
            consensusAlgorithm.validateAndAddTransaction(transaction);

            // Store the agreement in the smart contract
            smartContract.storeTransaction("Agreement reached", "checksum");
        }

        void storeBlock(const std::string& blockId, const SPHINXBlock::Block& block) {
            // Store the block in the database of each node in the network
            for (Node& node : networkNodes) {
                node.database.storeBlock(blockId, block.toJson());
            }

            // Update the block index for fast lookup
            blockIndex[blockId] = block;

            // Update accountTransactions to track transactions in the block
            for (const std::string& transaction : block.getTransactions()) {
                std::string sender = extractSender(transaction);
                std::string receiver = extractReceiver(transaction);
                accountTransactions[sender].insert(transaction);
                accountTransactions[receiver].insert(transaction);
            }
        }

        bool isTransactionStored(const std::string& transactionId) const {
            // Check if the transaction is stored in any node's database
            return transactionIndex.count(transactionId) > 0;
        }

        bool isBlockStored(const std::string& blockId) const {
            // Check if the block is stored in any node's database
            return blockIndex.count(blockId) > 0;
        }

        std::string getTransactionData(const std::string& transactionId) const {
            // Retrieve the transaction data from the database of any node
            if (isTransactionStored(transactionId)) {
                return transactionIndex.at(transactionId);
            }
            return "";
        }

        SPHINXBlock::Block getBlock(const std::string& blockId) const {
            // Retrieve the block from the database of any node
            if (isBlockStored(blockId)) {
                return blockIndex.at(blockId);
            }
            return SPHINXBlock::Block(""); // Return an empty block if not found
        }

        std::unordered_set<std::string> getTransactionsByAccount(const std::string& account) const {
            // Retrieve the set of transaction IDs associated with an account
            if (accountTransactions.count(account) > 0) {
                return accountTransactions.at(account);
            }
            return std::unordered_set<std::string>();
        }

        bool saveData(const std::string& filename) {
            std::ofstream outputFile(filename);

            if (!outputFile.is_open()) {
                std::cout << "Failed to open the file for saving data." << std::endl;
                return false; // Failed to open the file
            }

            // Save the state of the distributed database to the file

            // Save network nodes
            for (const Node& node : networkNodes) {
                outputFile << node.nodeId << "\n";
                // Save other relevant data for each node
            }

            // Save transaction index
            for (const auto& entry : transactionIndex) {
                outputFile << entry.first << ":" << entry.second << "\n";
            }

            // Save block index
            for (const auto& entry : blockIndex) {
                outputFile << entry.first << ":" << entry.second.toJson() << "\n";
            }

            // Save account transactions
            for (const auto& entry : accountTransactions) {
                outputFile << entry.first << ":";
                for (const std::string& transaction : entry.second) {
                    outputFile << transaction << ",";
                }
                outputFile << "\n";
            }

            outputFile.close();
            std::cout << "Data saved successfully." << std::endl;
            return true; // Successfully saved the data
        }

        bool loadData(const std::string& filename) {
            std::ifstream inputFile(filename);

            if (!inputFile.is_open()) {
                std::cout << "Failed to open the file for loading data." << std::endl;
                return false; // Failed to open the file
            }

            // Clear existing data structures before loading new data
            networkNodes.clear();
            transactionIndex.clear();
            blockIndex.clear();
            accountTransactions.clear();

            // Load the state of the distributed database from the file

            std::string line;

            // Load network nodes
            while (std::getline(inputFile, line) && !line.empty()) {
                Node newNode;
                newNode.nodeId = line;
                // Load other relevant data for each node
                networkNodes.push_back(newNode);
            }

            // Load transaction index
            while (std::getline(inputFile, line) && !line.empty()) {
                size_t separatorPos = line.find(':');
                if (separatorPos != std::string::npos) {
                    std::string transactionId = line.substr(0, separatorPos);
                    std::string transactionData = line.substr(separatorPos + 1);
                    transactionIndex[transactionId] = transactionData;
                }
            }

            // Load block index
            while (std::getline(inputFile, line) && !line.empty()) {
                size_t separatorPos = line.find(':');
                if (separatorPos != std::string::npos) {
                    std::string blockId = line.substr(0, separatorPos);
                    std::string blockData = line.substr(separatorPos + 1);
                    // Create a Block object from the block data
                    SPHINXBlock::Block block(blockData);
                    blockIndex[blockId] = block;
                }
            }

            // Load account transactions
            while (std::getline(inputFile, line) && !line.empty()) {
                size_t separatorPos = line.find(':');
                if (separatorPos != std::string::npos) {
                    std::string account = line.substr(0, separatorPos);
                    std::string transactions = line.substr(separatorPos + 1);
                    std::istringstream ss(transactions);
                    std::string transactionId;
                    while (std::getline(ss, transactionId, ',')) {
                        accountTransactions[account].insert(transactionId);
                    }
                }
            }

            inputFile.close();
            std::cout << "Data loaded successfully." << std::endl;
            return true; // Successfully loaded the data
        }

    private:
        std::string extractSender(const std::string& transactionData) {
            // Extract the sender from the transaction data
            // Split the transaction data into the sender and receiver
            std::string sender = transactionData.substr(0, transactionData.find("receiver"));
            return sender;
        }

        std::string extractReceiver(const std::string& transactionData) {
            // Extract the receiver from the transaction data
            // Split the transaction data into the sender and receiver
            std::string receiver = transactionData.substr(transactionData.find("receiver") + 8);
            return receiver;
        }
    };
} // namespace SPHINXDb





