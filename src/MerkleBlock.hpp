// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef MERKLEBLOCK_HPP
#define MERKLEBLOCK_HPP

#include <vector>
#include <string>
#include <set>  // For std::set
#include <cstdint>  // For uint256
#include "BloomFilter.hpp"  // Include the header for CBloomFilter
#include "CBlock.hpp"  // Include the header for CBlock
#include "PartialMerkleTree.hpp"  // Include the header for CPartialMerkleTree

namespace SPHINXMerkleblock {

    // Define a structure for transactions
    struct Transaction {
        std::string transactionData;
        // Add any other relevant fields
    };

    // Define a structure for header
    struct BlockHeader {
        // Define header fields
        std::string prevBlockHash;
        std::string timestamp;
        std::string nonce;
        std::vector<Transaction> transactions;
        std::string version;
    };

    // Function to convert bits to bytes
    std::vector<unsigned char> BitsToBytes(const std::vector<bool>& bits);

    // Function to convert bytes to bits
    std::vector<bool> BytesToBits(const std::vector<unsigned char>& bytes);

    // Class to represent a Merkle block
    class CMerkleBlock {
    public:
        // Constructor using a CBlock object
        CMerkleBlock(const CBlock& block, CBloomFilter* filter, const std::set<uint256>* txids);

    private:
        // Member variables
        BlockHeader header;
        CPartialMerkleTree txn;  // Assuming CPartialMerkleTree is the correct class

        // Other private member functions if needed
    };

    // Function to verify a Merkle block
    bool verifyMerkleBlock(const std::string& merkleRoot, const BlockHeader& header, const std::vector<Transaction>& transactions);

    // Function to combine left and right hashes
    std::string combineHashes(const std::string& left, const std::string& right);

    // Function to construct a Merkle tree from a list of hashes
    std::string constructMerkleTree(const std::vector<std::string>& hashes);

} // namespace SPHINXMerkleblock

#endif // MERKLEBLOCK_HPP




