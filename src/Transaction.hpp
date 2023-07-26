// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.



#ifndef SPHINX_TRX_HPP
#define SPHINX_TRX_HPP

#pragma once

#include <ctime>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>

#include "Utils.hpp"
#include "MerkleBlock.hpp"

// Forward declarations for functions defined later in "MerkleBlock.hpp"
std::string generateOrRetrieveSecretKeySeed();
std::string generateOrRetrievePublicKeySeed();
bool verifySignature(const std::string& data, const std::string& signature, const SPHINXMerkleBlock::SPHINXPubKey& publicKey);

namespace SPHINXTrx {
    class Transaction {
    public:
        std::string data;
        std::string signature;
        SPHINXMerkleBlock::SPHINXPubKey publicKey;

        // Other member functions

        std::string toJson() const {
            json transactionJson;
            transactionJson["data"] = data;
            transactionJson["signature"] = signature;
            transactionJson["publicKey"] = SPHINXMerkleBlock::pubKeyToString(publicKey); // Convert publicKey to string
            return transactionJson.dump();
        }

        void fromJson(const std::string& jsonStr) {
            json transactionJson = json::parse(jsonStr);
            data = transactionJson["data"].get<std::string>();
            signature = transactionJson["signature"].get<std::string>();
            publicKey = SPHINXMerkleBlock::stringToPubKey(transactionJson["publicKey"].get<std::string>()); // Convert string to publicKey
        }

        void sign(const std::string& senderPrivateKey) {
            // Create a private key object from the string
            std::string transactionJson = toJson();
            std::string transactionHash = hash(transactionJson);

            // Sign the transaction using the private key
            signature = SPHINXMerkleBlock::SPHINXSign(transactionHash, senderPrivateKey);
        }

        bool isConfirmed() const {
            // Check if the transaction is confirmed
            // Implement the confirmation logic
            return true; // Replace with actual confirmation logic
        }

        std::string serializeToJson() const {
            json dataJson;
            dataJson["data"] = data;
            dataJson["signature"] = signature;
            dataJson["publicKey"] = SPHINXMerkleBlock::pubKeyToString(publicKey);
            return dataJson.dump();
        }

        void deserializeFromJson(const std::string& jsonData) {
            json dataJson = json::parse(jsonData);
            data = dataJson["data"].get<std::string>();
            signature = dataJson["signature"].get<std::string>();
            publicKey = SPHINXMerkleBlock::stringToPubKey(dataJson["publicKey"].get<std::string>());
        }

        std::string signTransaction(const std::string& privateKey) const {
            std::string transactionHash = hash(serializeToJson());

            // Call other functions to perform signing-related tasks
            unsigned int nonce = generateRandomNonce();
            bool isSignatureValid = verifySignature(transactionHash, privateKey);
            bool areFundsAvailable = checkFundsAvailability(serializeToJson());

            // Print the signing information
            std::cout << "Transaction signed with private key: " << privateKey << std::endl;
            std::cout << "Transaction Hash: " << transactionHash << std::endl;
            std::cout << "Nonce: " << nonce << std::endl;
            std::cout << "Signature Validity: " << (isSignatureValid ? "Valid" : "Invalid") << std::endl;
            std::cout << "Funds Availability: " << (areFundsAvailable ? "Available" : "Not Available") << std::endl;

            broadcastTransaction(transactionHash); // Broadcast the transaction to the mempool

            return transactionHash;
        }
    }
};

#endif // TRANSACTION_HPP



