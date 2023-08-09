// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINX_MERKLEBLOCK_HPP
#define SPHINX_MERKLEBLOCK_HPP

#pragma once

#include <array>
#include <string>
#include <vector>
#include <algorithm>
#include <string>
#include <vector>
#include <iostream>
#include <cstdint>

#include "json.hh"
#include "Params.hpp"


// Forward declarations for classes that are defined later
namespace SPHINXMerkleBlock {
    class Transaction;
    struct SignedTransaction;
}

// Define the SPHINXPubKey type here (if not already defined)
namespace SPHINXKey {
    using SPHINXPubKey = std::vector<unsigned char>;
}

namespace SPHINXMerkleBlock {

    // Constants
    constexpr int SPHINCS_N = 256;
    constexpr int SPHINCS_H = 128;
    constexpr int SPHINCS_D = 64;
    constexpr int SPHINCS_A = 32;
    constexpr int SPHINCS_K = 16;
    constexpr int SPHINCS_W = 8;
    constexpr int SPHINCS_V = 4;

    // MerkleBlock class
    class MerkleBlock {
    public:
        // Helper functions for Merkle Tree construction
        std::string hashTransactions(const std::string& transaction1, const std::string& transaction2) const;
        std::string buildMerkleRoot(const std::vector<std::string>& transactions) const;
        bool sign(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sk_seed, const std::vector<uint8_t>& pk_seed, uint64_t idx_tree, uint32_t idx_leaf, std::vector<uint8_t>& sig);
        bool verify(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sig, const std::vector<uint8_t>& pk_seed, uint64_t idx_tree, uint32_t idx_leaf, const std::vector<uint8_t>& pkey) const;

        // Construct the Merkle tree from a vector of signed transactions
        std::string constructMerkleTree(const std::vector<SignedTransaction>& signedTransactions);

        // Verify the Merkle root against a vector of transactions
        bool verifyMerkleRoot(const std::string& merkleRoot, const std::vector<SignedTransaction>& transactions);

        // Add the function to generate the hybrid key pair
        static std::pair<std::string, SPHINXKey::SPHINXPubKey> generateHybridKeyPair();

    private:
        // Nested construction classes
        class ForsConstruction {
        public:
            // Construct a FORS tree from a vector of transactions
            std::vector<std::string> constructForsTree(const std::vector<std::string>& transactions);
        };

        class WotsConstruction {
        public:
            // Construct a WOTS tree from a vector of roots
            std::vector<std::string> constructWotsTree(const std::vector<std::string>& roots, size_t n) const;
        };

        class HypertreeConstruction {
        public:
            // Construct a Hypertree from a vector of roots
            std::string constructHypertree(const std::vector<std::string>& roots) const;
        };

        class XmssConstruction {
        public:
            // Generate an XMSS public key using the provided secret key seed and public key seed
            std::string pkgen(const std::string& sk_seed, const std::string& pk_seed, std::string& pkey) const;

            // Construct an XMSS public key using the Hypertree root
            std::string constructXMSS(const std::string& hypertreeRoot) const;
        };

        // Private members for construction classes
        ForsConstruction forsConstruction;
        WotsConstruction wotsConstruction;
        HypertreeConstruction hypertreeConstruction;
        XmssConstruction xmssConstruction;
    };

    // Transaction class
    class Transaction {
    public:
        std::string data;
        std::string signature;
        SPHINXKey::SPHINXPubKey publicKey;

        // Function to convert SPHINXPubKey to string representation
        std::string sphinxKeyToString(const SPHINXKey::SPHINXPubKey& publicKey) const {
            std::ostringstream oss;
            for (const auto& byte : publicKey) {
                // Convert each byte of the public key to its two-digit hexadecimal representation
                oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(byte);
            }
            return oss.str(); // Return the concatenated hexadecimal string
        }

        // Other member functions

        std::string toJson() const {
            json transactionJson;
            transactionJson["data"] = data;
            transactionJson["signature"] = signature;
            transactionJson["publicKey"] = sphinxKeyToString(publicKey); // Convert publicKey to string using sphinxKeyToString function
            return transactionJson.dump();
        }
    };

    // SignedTransaction structure
    struct SignedTransaction {
        Transaction transaction;
        std::string transactionData;
        std::vector<uint8_t> data;
        std::string signature;
        SPHINXKey::SPHINXPubKey publicKey;
    };

    // Function to calculate the hash of the block's header, including the Merkle root
    std::string calculateBlockHeaderHash(const std::string& prevBlockHash, const std::string& merkleRoot, const std::string& timestamp, const std::string& nonce);

    // Function to call verifyBlock and verifyChain functions from Verify.hpp and print the results
    void verifyIntegrity(const MerkleBlock& block, const SPHINXChain& chain);

    // Function to convert SPHINXPubKey to string representation
    std::string sphinxKeyToString(const SPHINXKey::SPHINXPubKey& publicKey);

    // Function to generate the hybrid key pair using the necessary functions and algorithms
    std::pair<std::string, SPHINXKey::SPHINXPubKey> generateHybridKeyPair();

    bool verifySignature(const std::string& data, const std::string& signature, const SPHINXKey::SPHINXPubKey& publicKey);
} // namespace SPHINXMerkleBlock

#endif // MERKLEBLOCK_HPP


