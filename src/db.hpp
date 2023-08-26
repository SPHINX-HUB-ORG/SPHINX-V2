// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef DISTRIBUTED_DB_HPP
#define DISTRIBUTED_DB_HPP

#include <fstream>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>

#include "Node.hpp"
#include "db.hpp"
#include "Wallet.hpp"
#include "Consensus/Consensus.hpp"
#include "Consensus/Contract.hpp"
#include "Verify.hpp"
#include "Block.hpp"
#include "Transaction.hpp"


namespace SPHINXDb {

    struct Node {
        std::string nodeId;
        DistributedDb database;
    };

    class DistributedDb {
    private:
        std::vector<Node> networkNodes;
        std::unordered_map<std::string, std::string> transactionIndex;
        std::unordered_map<std::string, SPHINXBlock::Block> blockIndex;
        std::unordered_map<std::string, std::unordered_set<std::string>> accountTransactions;
        SPHINXConsensus::Consensus consensusAlgorithm;
        SPHINXContract::SmartContract smartContract;

    public:
        DistributedDb();

        void addNode(const std::string& nodeId);

        void storeTransaction(const std::string& transactionId, const std::string& transactionData);

        void storeBlock(const std::string& blockId, const SPHINXBlock::Block& block);

        bool isTransactionStored(const std::string& transactionId) const;

        bool isBlockStored(const std::string& blockId) const;

        std::string getTransactionData(const std::string& transactionId) const;

        SPHINXBlock::Block getBlock(const std::string& blockId) const;

        std::unordered_set<std::string> getTransactionsByAccount(const std::string& account) const;

        bool storeBlock(const std::string& blockId, const std::string& blockData);

        std::string getBlockData(const std::string& blockId) const;

        bool saveData(const std::string& filename);

        bool loadData(const std::string& filename);

    private:
        std::string extractSender(const std::string& transactionData) const;

        std::string extractReceiver(const std::string& transactionData) const;
    };

} // namespace SPHINXDb

#endif /* DB_HPP */






