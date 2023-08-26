// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <iostream>
#include <vector>
#include <string>

#include "Merkle.hpp"
#include <hash.hpp>  // Include the header for SPHINXHash

namespace SPHINXMerkle {

    class Merkle {
    public:
        Merkle() {}

        void buildMerkleTree(const std::vector<Transaction>& transactions, const std::vector<Witness>& witnesses) {
            if (transactions.empty() || transactions.size() != witnesses.size()) {
                return;
            }

            std::vector<std::string> transactionHashes;
            for (size_t i = 0; i < transactions.size(); ++i) {
                const Transaction& transaction = transactions[i];
                const Witness& witness = witnesses[i];
                std::string combinedData = transaction.transactionData + witness.witnessData; // Adjust as needed
                std::string hash = SPHINXHash::SPHINX_256(combinedData); // Use the actual function name
                transactionHashes.push_back(hash);
            }

            merkleRoot = ComputeMerkleRoot(transactionHashes).ToString();
        }

        bool verifyMerkleProof(const std::string& merkleRoot, const std::string& transactionData, const std::string& witnessData) {
            std::string combinedData = transactionData + witnessData; // Adjust as needed
            std::string transactionHash = SPHINXHash::SPHINX_256(combinedData); // Use the actual function name

            // Find the path from the transactionHash to the merkleRoot
            std::vector<std::string> hashes;
            for (size_t i = 0; i < transactionHash.size(); i++) {
                hashes.push_back(std::string(1, transactionHash[i]));
            }
            bool mutated = false;
            std::string computedRoot = ComputeMerkleRoot(hashes, &mutated);

            return (computedRoot == merkleRoot) && !mutated;
        }

    private:
        std::string merkleRoot;
    };

} // namespace SPHINXMerkle




