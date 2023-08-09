// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The provided code defines a set of classes and functions related to a cryptographic protocol using the SPHINCS+ `merkle-trees` and 
// `signature` scheme. This protocol is used to verify the integrity and authenticity of a chain of transactions. Let's break down the 
// code and explain its components in detail:

// Constants:
    // The code defines several constants that affect the behavior and security of the SPHINCS+ signature scheme. These constants include:
        // SPHINCS_N: The length of the cryptographic hash output in bytes. It determines the security strength of the SPHINCS+ signature 
        // scheme. In this case, the hash output length is 256 bytes (32 bytes x 8 bits per byte).

        // SPHINCS_H: The height of the binary hash tree used in the Merkle tree construction. It defines the number of layers in the 
        // Merkle tree, which affects the signature size and verification cost. In this case, the height of the binary hash tree is 128.

        // SPHINCS_D: The number of layers in the hypertree. It affects the size of the signature and the security level of the SPHINCS+ 
        // signature scheme. In this case, the number of layers in the hypertree is 64.

        // SPHINCS_A: The number of n-byte addresses used in the hash function. It affects the number of layers in the Merkle tree and 
        // the security of the SPHINCS+ scheme. In this case, the number of n-byte addresses is 32.

        // SPHINCS_K: The number of Winternitz iterations used in the WOTS+ (Winternitz One-Time Signature) scheme. It determines the 
        // signature size and verification cost in the SPHINCS+ scheme. In this case, there are 16 Winternitz iterations.

        // SPHINCS_W: The Winternitz parameter for the WOTS+ scheme. It defines the number of bits that can be signed using a single 
        // WOTS+ key pair. In this case, each WOTS+ key pair can sign 8 bits.

        // SPHINCS_V: The height of the binary hash tree used in the XMSS signature scheme. It determines the size of the XMSS signature
        // and the security level. In this case, the height of the binary hash tree for XMSS is 4.

// Type Aliases:
    // The code defines two type aliases for the SPHINX public key and private key, respectively, as SPHINXPubKey and SPHINXPrivKey. 
    // These aliases are defined as std::vector<unsigned char>, representing a sequence of bytes.
    // extractTransactionData(const std::string& signedTransaction):
    // This function is used to extract the transaction data field from a signed transaction represented as a JSON string. It parses the 
    // JSON string, searches for the "transaction_data" field, and returns its value as a std::string.
    // extractPublicKey(const std::string& signedTransaction):
    // This function is used to extract the public key from a signed transaction represented as a JSON string. It parses the JSON string,
    // searches for the "public_key" field, and converts the hexadecimal public key string to a SPHINXPubKey (vector of bytes) before returning it.

// SPHINXSign::addSignedTransactionToMerkleTree(const std::string& signedTransaction, const uint8_t* SPHINXPrivKey):
    // This function is an interface function used to add a signed transaction to the Merkle tree. It takes the signed transaction JSON 
    // string and the SPHINCS+ private key as inputs.
    // It extracts the transaction data and public key from the signed transaction using the previously defined extraction functions.
    // It then calls the sphincs::sign function from a library (not shown in this code snippet) to sign the transaction data using the 
    // private key and generate a SPHINCS+ signature.
    // After verifying the validity of the signature, it constructs a SPHINXMerkleBlock::SignedTransaction object and adds it to the 
    // Merkle tree using the SPHINXMerkleBlock::MerkleBlock::getInstance().addTransaction() function (assumed to be defined elsewhere).

// SPHINXSign::verify_data(const std::vector<uint8_t>& data, const std::string& signature, const SPHINXPubKey& publicKey):
    // This function is used to verify the SPHINCS+ signature for a given data using the provided signature and publicKey. It calls the
    // sphincs::verify function (not shown in this code snippet) to perform the actual verification.

// SPHINXSign::verifySPHINXBlock(const Block& block, const std::string& signature, const SPHINXPubKey& publicKey):
    // This function is used to verify the integrity of a SPHINX block. It takes a Block object, the signature string, and the public 
    // key as inputs.
    // It first verifies the signature of the block using the provided signature and publicKey by calling SPHINXVerify::verifySPHINXBlock.
    // Next, it verifies the Merkle root of the block by calling SPHINXMerkleBlock::verifyMerkleRoot.

// SPHINXSign::verifySPHINXChain(const Chain& chain):
    // This function is used to verify the integrity and consistency of a SPHINX chain. It takes a Chain object as input and calls 
    // verifyChainIntegrity(chain) (assumed to be defined elsewhere) to perform the chain verification.

// The code provides an interface for adding signed transactions to a Merkle tree and verifies the authenticity of the data using the 
// SPHINCS+ digital signature scheme. It also includes functions to verify individual blocks and the entire chain in the SPHINX blockchain. The integration with the Merkle tree scheme allows for efficient verification and tamper detection of transactions in the blockchain.
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



#include <string>
#include <vector>
#include <iostream>
#include <map>
#include <memory>

#include "Lib/Sphincs/include/sphincs.hpp"
#include "Checksum.hpp"
#include "Hash.hpp"
#include "Verify.hpp"
#include "Chain.hpp"
#include "Key.hpp"
#include "Transaction.hpp"
#include "json.hpp"
#include "Sign.hpp"


using json = nlohmann::json;

//**
// Define the SPHINCS_N, SPHINCS_H, SPHINCS_D, SPHINCS_A, SPHINCS_K, SPHINCS_W, SPHINCS_V constants here
// (if not already defined)
// SPHINCS_N: The length of the cryptographic hash output in bytes.
// It determines the security strength of the SPHINCS signature scheme.
// In this case, the hash output length is 256 bytes (32 bytes x 8 bits per byte).
constexpr int SPHINCS_N = 256;

//*
// SPHINCS_H: The height of the binary hash tree used in the Merkle tree construction.
// It defines the number of layers in the Merkle tree, which affects the signature size and verification cost.
// In this case, the height of the binary hash tree is 128.
constexpr int SPHINCS_H = 128;

//*
// SPHINCS_D: The number of layers in the hypertree.
// It affects the size of the signature and the security level of the SPHINCS signature scheme.
// In this case, the number of layers in the hypertree is 64.
constexpr int SPHINCS_D = 64;

//*
// SPHINCS_A: The number of n-byte addresses used in the hash function.
// It affects the number of layers in the Merkle tree and the security of the SPHINCS scheme.
// In this case, the number of n-byte addresses is 32.
constexpr int SPHINCS_A = 32;

//*
// SPHINCS_K: The number of Winternitz iterations used in the WOTS+ (Winternitz One-Time Signature) scheme.
// It determines the signature size and verification cost in the SPHINCS scheme.
// In this case, there are 16 Winternitz iterations.
constexpr int SPHINCS_K = 16;

//*
// SPHINCS_W: The Winternitz parameter for the WOTS+ scheme.
// It defines the number of bits that can be signed using a single WOTS+ key pair.
// In this case, each WOTS+ key pair can sign 8 bits.
constexpr int SPHINCS_W = 8;

//*
// SPHINCS_V: The height of the binary hash tree used in the XMSS signature scheme.
// It determines the size of the XMSS signature and the security level.
// In this case, the height of the binary hash tree for XMSS is 4.
constexpr int SPHINCS_V = 4;
//**


// Define SPHINXPubKey as an alias for the SPHINX public key (std::vector<unsigned char>)
typedef std::vector<unsigned char> SPHINXPubKey;

// Define an alias for the merged public key as SPHINXPubKey
using SPHINXPubKey = std::vector<unsigned char>;

// Define an alias for the merged private key as SPHINXPrivKey
using SPHINXPrivKey = std::vector<unsigned char>;

// Function to extract transaction data from the signed transaction
std::string extractTransactionData(const std::string& signedTransaction) {
    // Assuming the signed transaction is in JSON format
    // Extract the transaction data field from the JSON
    json signedTransactionJson = json::parse(signedTransaction);
    if (signedTransactionJson.find("transaction_data") != signedTransactionJson.end()) {
        return signedTransactionJson["transaction_data"].get<std::string>();
    } else {
        // Handle error if "transaction_data" field is not found in the JSON
        std::cerr << "ERROR: Missing 'transaction_data' field in the signed transaction JSON." << std::endl;
        return "";
    }
}

// Function to extract the public key from the signed transaction
SPHINXPubKey extractPublicKey(const std::string& signedTransaction) {
    // Assuming the signed transaction is in JSON format
    // Extract the public key field from the JSON
    json signedTransactionJson = json::parse(signedTransaction);
    if (signedTransactionJson.find("publickey") != signedTransactionJson.end()) {
        std::string publicKeyHex = signedTransactionJson["publickey"].get<std::string>();
        // Convert the hexadecimal public key string to bytes
        std::vector<unsigned char> publicKey;
        for (size_t i = 0; i < publicKeyHex.length(); i += 2) {
            unsigned char byte = std::stoi(publicKeyHex.substr(i, 2), nullptr, 16);
            publicKey.push_back(byte);
        }
        return publicKey;
    } else {
        // Handle error if "public_key" field is not found in the JSON
        std::cerr << "ERROR: Missing 'public_key' field in the signed transaction JSON." << std::endl;
        return {};
    }
}

namespace SPHINXSign {

    // Function to extract transaction data from the signed transaction
    std::string extractTransactionData(const std::string& signedTransaction) {
        // Assuming the signed transaction is in JSON format
        // Extract the transaction data field from the JSON
        json signedTransactionJson = json::parse(signedTransaction);
        if (signedTransactionJson.find("transaction_data") != signedTransactionJson.end()) {
            return signedTransactionJson["transaction_data"].get<std::string>();
        } else {
            // Handle error if "transaction_data" field is not found in the JSON
            std::cerr << "ERROR: Missing 'transaction_data' field in the signed transaction JSON." << std::endl;
            return "";
        }
    }

    // Function to sign the transaction data using SPHINCS+ signature
    std::string signTransactionData(const std::string& transactionData, const SPHINXPrivKey& privateKey) {
        // Perform the signing using the sign function from "Sphincs.hpp"
        std::string signature;
        if (transactionData.size() > 0) {
            signature.resize(SPHINCS_N * 4); // Size of SPHINCS+ signature
            sphincs::sign<SPHINCS_N, SPHINCS_H, SPHINCS_D, SPHINCS_A, SPHINCS_K, SPHINCS_W, SPHINCS_V>(
                reinterpret_cast<const uint8_t*>(transactionData.data()), transactionData.size(),
                privateKey.data(), reinterpret_cast<uint8_t*>(signature.data())
            );
        } else {
            throw std::runtime_error("ERROR: Empty transaction data.");
        }
        return signature;
    }

    // Function to extract the public key from the signed transaction
    SPHINXKey::SPHINXPubKey extractPublicKey(const std::string& signedTransaction) {
        // Assuming the signed transaction is in JSON format
        // Extract the public key field from the JSON
        json signedTransactionJson = json::parse(signedTransaction);
        if (signedTransactionJson.find("publicKey") != signedTransactionJson.end()) {
            std::string publicKeyHex = signedTransactionJson["publicKey"].get<std::string>();
            // Convert the hexadecimal public key string to bytes
            SPHINXKey::SPHINXPubKey sphinxPubKey;
            for (size_t i = 0; i < publicKeyHex.length(); i += 2) {
                unsigned char byte = std::stoi(publicKeyHex.substr(i, 2), nullptr, 16);
                sphinxPubKey.push_back(byte);
            }
            return sphinxPubKey;
        } else {
            // Handle error if "publicKey" field is not found in the JSON
            std::cerr << "ERROR: Missing 'publicKey' field in the signed transaction JSON." << std::endl;
            return {};
        }
    }

    // Interface function to add a signed transaction to the Merkle tree in "merkleblock.cpp"
    void addSignedTransactionToMerkleTree(const std::string& signedTransaction, const uint8_t* SPHINXPrivKey) {
        // Get the signed transaction data, signature, and public key from the input
        std::string transactionData = extractTransactionData(signedTransaction);
        SPHINXPubKey publicKey = extractPublicKey(signedTransaction);

        // Sign the transaction data using the private key by calling the sign function from "Sphincs.hpp"
        std::string signature;
        if (transactionData.size() > 0) {
            signature.resize(n * 4); // Size of SPHINCS+ signature
            sphincs::sign<SPHINCS_N, SPHINCS_H, SPHINCS_D, SPHINCS_A, SPHINCS_K, SPHINCS_W, SPHINCS_V>(reinterpret_cast<const uint8_t*>(transactionData.data()), transactionData.size(), SPHINXPrivKey, reinterpret_cast<uint8_t*>(signature.data()));
        } else {
            std::cerr << "ERROR: Empty transaction data." << std::endl;
            return;
        }

        // Verify the signature before adding it to the Merkle tree
        if (!signature.empty() && sphincs::verify<SPHINCS_N, SPHINCS_H, SPHINCS_D, SPHINCS_A, SPHINCS_K, SPHINCS_W, SPHINCS_V>(reinterpret_cast<const uint8_t*>(transactionData.data()), transactionData.size(), reinterpret_cast<const uint8_t*>(signature.data()), publicKey)) {
            SPHINXMerkleBlock::SignedTransaction signedTransaction;
            signedTransaction.transaction = transactionData;
            signedTransaction.signature = signature;
            signedTransaction.publickey = publicKey;
            signedTransaction.data = std::vector<uint8_t>(transactionData.begin(), transactionData.end());

            // Add the signed transaction to the Merkle tree
            SPHINXMerkleBlock::MerkleBlock::getInstance().addTransaction(signedTransaction);
        } else {
            // Signature verification failed or signature is empty, handle the error accordingly
            std::cerr << "ERROR: Invalid signature for transaction: " << signedTransaction << std::endl;
        }
    }

    // Function to verify data (unchanged)
    bool verify_data(const std::vector<uint8_t>& data, const std::string& signature, const SPHINXPubKey& publicKey) {
        // Call the verification function from "Sphincs.hpp" to verify the SPHINCS+ signature
        return sphincs::verify<SPHINCS_N, SPHINCS_H, SPHINCS_D, SPHINCS_A, SPHINCS_K, SPHINCS_W, SPHINCS_V>(
            data.data(), data.size(), reinterpret_cast<const uint8_t*>(signature.data()), publicKey);
    }

    bool verifySPHINXBlock(const Block& block, const std::string& signature, const SPHINXPubKey& publicKey) {
        // Step 1: Verify the signature of the block using the provided signature and public key
        bool isSignatureValid = SPHINXVerify::verifySPHINXBlock(block, signature, publicKey);

        // Step 2: Verify the Merkle root of the block
        bool isMerkleRootValid = SPHINXMerkleBlock::verifyMerkleRoot(block.getMerkleRoot(), block.getTransactions());

        // Return the verification result
        return isSignatureValid && isMerkleRootValid;
    }

    bool verifySPHINXChain(const Chain& chain) {
        // Step 1: Verify the integrity and consistency of the chain
        bool isChainValid = verifyChainIntegrity(chain);

        // Return the verification result
        return isChainValid;
    }
} // namespace SPHINXSign
