// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef MERKLE_HPP
#define MERKLE_HPP

#include <vector>
#include <string>
#include <Hash.hpp>  // Include the header for SPHINXHash
#include <Block.hpp>

namespace SPHINXMerkle {

    // Define the Transaction and Witness classes
    struct Transaction {
        std::string transactionData;
        // Add any other relevant fields
    };

    struct Witness {
        std::string witnessData;
        // Add any other relevant fields
    };

    // Class to represent a Merkle tree
    class Merkle {
    public:
        Merkle() {}

        void buildMerkleTree(const std::vector<Transaction>& transactions, const std::vector<Witness>& witnesses);

        bool verifyMerkleProof(const std::string& merkleRoot, const std::string& transactionData, const std::string& witnessData);

    private:
        std::string merkleRoot;
    };

} // namespace SPHINXMerkle

#endif // MERKLE_HPP