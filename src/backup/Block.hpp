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



#ifndef BLOCK_HPP
#define BLOCK_HPP

#pragma once

#include <stdexcept>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <ctime>

#include "Hash.hpp"
#include "Sign.hpp"
#include "json.hpp"
#include "MerkleBlock.hpp"
#include "Chain.hpp"
#include "PoW.hpp"
#include "db.hpp"
#include "verify.hpp"

using json = nlohmann::json;

namespace SPHINXVerify {
    class SPHINX_PublicKey {
    public:
        // Placeholder definition for SPHINX_PublicKey
    };

    bool verifySignature(const std::string& blockHash, const std::string& signature, const SPHINX_PublicKey& publicKey);
}

namespace SPHINXHash {
    std::string SPHINX_256(const std::string& data);
}

namespace SPHINX_Chain {
    class Chain {
    public:
        void addBlock(const SPHINXMerkleBlock::MerkleBlock& block);
    };
}

namespace SPHINXMerkleBlock {
    class MerkleBlock {
    public:
        std::string constructMerkleTree(const std::vector<SignedTransaction>& signedTransactions) const;

        bool verifyMerkleRoot(const std::string& merkleRoot, const std::vector<SignedTransaction>& transactions) const;

        bool verifyMerkleRoot(const std::string& merkleRoot, const std::vector<SignedTransaction>& signedTransactions) const;
    };
}

namespace SPHINXDb {
    class DistributedDb {
    public:
        void saveData(const std::string& data, const std::string& blockHash);

        std::string loadData(const std::string& blockId);
    };
}

namespace SPHINXBlock {
    class Block {
    public:
        Block(const std::string& previousHash);

        void addTransaction(const std::string& transaction);

        std::string calculateMerkleRoot() const;

        std::string getBlockHash() const;

        bool verifyBlock(const SPHINXVerify::SPHINX_PublicKey& publicKey) const;

        bool verifySignature(const SPHINXVerify::SPHINX_PublicKey& publicKey) const;

        std::string calculateBlockHash() const;

        void setBlockHeight(uint32_t height);

        uint32_t getBlockHeight() const;

        uint32_t getTransactionCount() const;

        bool isValid() const;

        void setBlockchain(SPHINX_Chain::Chain* blockchain);

        void addToBlockchain();

        json toJson() const;

        void fromJson(const json& blockJson);

        bool save(const std::string& filename) const;

        static Block load(const std::string& filename);

        bool saveToDatabase(SPHINXDb::DistributedDb& distributedDb) const;

    private:
        std::string previousHash_;
        std::string merkleRoot_;
        std::string signature_;
        uint32_t blockHeight_;
        std::time_t timestamp_;
        uint32_t nonce_;
        uint32_t difficulty_;
        std::vector<std::string> transactions_;
        SPHINX_Chain::Chain* blockchain_;
    };

    const uint32_t MAX_BLOCK_SIZE = 1000;
    const std::time_t MAX_TIMESTAMP_OFFSET = 600;
}

#endif  // BLOCK_HPP