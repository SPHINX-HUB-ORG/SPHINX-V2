// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINX_UTILS_HPP
#define SPHINX_UTILS_HPP

#include <random>
#include <vector>
#include <string>
#include <utility>
#include "Hash.hpp"
#include "Key.hpp"
#include "Sign.hpp"
#include "Consensus/Consensus.hpp"
#include "Transaction.hpp"


namespace SPHINXUtils {
    // Function to generate a random value
    std::string generateRandomValue(size_t valueLength);

    // Function to generate a random nonce
    std::string generateRandomNonce();

    // Function to generate a random seed
    std::string generateRandomSeed();

    // Function to calculate the SWIFFTX-256 hash of the data
    std::string hash(const std::string& data);

    // Function to verify a signature
    bool verifySignature(const Transaction& transaction);

    // Function to check funds availability
    bool checkFundsAvailability(const Transaction& transaction);

    // Function to adhere to network rules
    bool adhereToNetworkRules(const Transaction& transaction);

    // Function to encode a transaction
    std::string encodeTransaction(const std::string& transaction);

    // Function to decode a transaction
    std::string decodeTransaction(const std::string& encodedTransaction);

    // Function to calculate the transaction fee
    unsigned int calculateTransactionFee(const std::string& transaction);

    // Function to generate a key pair
    std::pair<std::string, std::string> generateKeyPair();

    // Function to generate an address from a public key
    std::string generateAddress(const std::string& publicKey);

    // Function to calculate a public key from a private key
    std::string calculatePublicKey(const std::string& privateKey);
} // namespace SPHINXUtils


#endif // SPHINX_UTILS_HPP


