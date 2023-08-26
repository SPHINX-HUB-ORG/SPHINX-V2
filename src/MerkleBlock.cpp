// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <vector>
#include <string>

#include "MerkleBlock.hpp"
#include "Hash.hpp"
#include "Consensus/Consensus.hpp"

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

    // Function to get the block header
    BlockHeader getBlockHeader(const std::string& prevBlockHash, const std::string& timestamp, const std::string& nonce,
                                const std::vector<Transaction>& transactions, const std::string& version) {
        BlockHeader header;
        header.prevBlockHash = prevBlockHash;
        header.timestamp = timestamp;
        header.nonce = nonce;
        header.transactions = transactions;
        header.version = version;
        return header;
    }

    // Function to convert bits to bytes
    std::vector<unsigned char> BitsToBytes(const std::vector<bool>& bits) {
        std::vector<unsigned char> bytes((bits.size() + 7) / 8);
        for (size_t i = 0; i < bits.size(); i++) {
            if (bits[i]) {
                bytes[i / 8] |= 1 << (i % 8);
            }
        }
        return bytes;
    }

    // Function to convert bytes to bits
    std::vector<bool> BytesToBits(const std::vector<unsigned char>& bytes) {
        std::vector<bool> bits(bytes.size() * 8);
        for (size_t i = 0; i < bytes.size() * 8; i++) {
            bits[i] = (bytes[i / 8] >> (i % 8)) & 1;
        }
        return bits;
    }

    // CMerkleBlock constructor using a CBlock object
    CMerkleBlock::CMerkleBlock(const CBlock& block, CBloomFilter* filter, const std::set<uint256>* txids) {
        // Extract the block header
        header = getBlockHeader(block.GetPrevBlockHash().ToString(), std::to_string(block.GetTime()), std::to_string(block.GetNonce()),
                                /* Extract transactions from block and create Transaction objects */,
                                block.GetVersionHex());

        // Convert block transactions to Transaction objects and add them to the header
        for (const CTransactionRef& tx : block.vtx) {
            Transaction transaction;
            // Extract necessary transaction data and populate the transaction object
            transaction.transactionData = /* Extract and assign transaction data */;
            header.transactions.push_back(transaction);
        }

        // Construct a partial merkle tree if needed
        if (filter || txids) {
            std::vector<uint256> vHashes;
            vHashes.reserve(block.vtx.size());

            // Extract hashes of relevant transactions based on filter or txids
            for (unsigned int i = 0; i < block.vtx.size(); i++) {
                const uint256& hash = block.vtx[i]->GetHash();
                if (txids && txids->count(hash)) {
                    vHashes.push_back(hash);
                } else if (filter && filter->IsRelevantAndUpdate(*block.vtx[i])) {
                    vHashes.push_back(hash);
                }
            }

            // Construct a partial merkle tree using the extracted hashes
            txn = CPartialMerkleTree(vHashes, /* A vector of flags indicating which transactions are matched */);
        }
    }

    // Function to verify a Merkle block
    bool verifyMerkleBlock(const std::string& merkleRoot, const BlockHeader& header, const std::vector<Transaction>& transactions) {
        // Create a Merkle tree from the transactions.
        std::vector<std::string> hashes;
        for (const Transaction& transaction : transactions) {
            hashes.push_back(computeHash(transaction.transactionData));
        }

        // While there are more than one hash, recursively combine them into pairs.
        while (hashes.size() > 1) {
            std::vector<std::string> new_hashes;
            for (int i = 0; i < hashes.size(); i += 2) {
                std::string hash = combineHashes(hashes[i], hashes[i + 1]);
                new_hashes.push_back(hash);
            }
            hashes = new_hashes;
        }

        // Check if the given Merkle root matches the root of the tree.
        return computeHash(hashes[0]) == merkleRoot;
    }

    // Function to combine left and right hashes
    std::string combineHashes(const std::string& left, const std::string& right) {
        return computeHash(left + right);
    }

    // Function to construct a Merkle tree from a list of hashes
    std::string constructMerkleTree(const std::vector<std::string>& hashes) {
        std::vector<std::string> tree = hashes;

        // While there are more than one hash, recursively combine them into pairs.
        while (tree.size() > 1) {
            std::vector<std::string> new_tree;
            for (int i = 0; i < tree.size(); i += 2) {
                std::string hash = combineHashes(tree[i], tree[i + 1]);
                new_tree.push_back(hash);
            }
            tree = new_tree;
        }

        // The root of the tree is the final hash.
        return tree[0];
    }

} // namespace SPHINXMerkleblock
