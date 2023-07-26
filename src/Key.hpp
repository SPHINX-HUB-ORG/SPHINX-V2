// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINX_KEY_HPP
#define SPHINX_KEY_HPP

#pragma once

#include <string>
#include <vector>
#include <cstring>
#include <utility>
#include <iostream>
#include <algorithm>
#include <cstdint>

namespace SPHINXHybridKey {
    // Assume the definition of SPHINXHybridKey
    struct HybridKeypair {};

    // Function to perform key exchange using hybrid method
    std::string encapsulateHybridSharedSecret(const HybridKeypair& hybridKeyPair, std::vector<uint8_t>& encapsulatedKey);
    std::string decapsulateHybridSharedSecret(const HybridKeypair& hybridKeyPair, const std::vector<uint8_t>& encapsulatedKey);

    // Function to encrypt and decrypt messages using Kyber1024 PKE
    std::string encryptMessage(const std::string& message, const std::vector<uint8_t>& publicKey);
    std::string decryptMessage(const std::string& ciphertext, const std::vector<uint8_t>& privateKey);
}

namespace SPHINXHash {
    // Assume the definition of SPHINX_256 function
    std::string SPHINX_256(const std::vector<unsigned char>& data);
    std::string RIPEMD_160(const std::vector<unsigned char>& data);
}

// Base58 characters (excluding confusing characters: 0, O, I, l) for address human readable
static const std::string base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Function to encode data using Base58
std::string EncodeBase58(const std::vector<unsigned char>& data);

namespace SPHINXKey {

    // Constants
    constexpr size_t CURVE448_PRIVATE_KEY_SIZE = 56;
    constexpr size_t CURVE448_PUBLIC_KEY_SIZE = 56;
    constexpr size_t KYBER1024_PUBLIC_KEY_LENGTH = 800;
    constexpr size_t KYBER1024_PRIVATE_KEY_LENGTH = 1632;
    constexpr size_t KYBER1024_PKE_PUBLIC_KEY_LENGTH = 800;
    constexpr size_t KYBER1024_PKE_PRIVATE_KEY_LENGTH = 1632;

    // Size of HYBRIDKEY
    constexpr size_t HYBRID_KEYPAIR_LENGTH = CURVE448_PUBLIC_KEY_SIZE + KYBER1024_PUBLIC_KEY_LENGTH + 2 * SPHINXHybridKey::HMAC_MAX_MD_SIZE;
    // HYBRID_KEYPAIR_LENGTH = 56 (Curve448 public key size) + 800 (Kyber1024 public key length) + 2 * 64 (HMAC_MAX_MD_SIZE) = 976;

    // Define an alias for the merged public key as SPHINXPubKey
    using SPHINXPubKey = std::vector<unsigned char>;

    // Define an alias for the merged private key as SPHINXPrivKey
    using SPHINXPrivKey = std::vector<unsigned char>;

    // Function to calculate the SPHINX public key from the private key
    SPHINXPubKey calculatePublicKey(const SPHINXPrivKey& privateKey);

    // Function to convert SPHINXKey to string
    std::string sphinxKeyToString(const std::vector<unsigned char>& key);

    // Function to generate the smart contract address based on the public key and contract name
    std::string generateAddress(const SPHINXPubKey& publicKey, const std::string& contractName);

    // Function to merge the private keys of Curve448 and Kyber1024
    SPHINXPrivKey mergePrivateKeys(const SPHINXPrivKey& curve448PrivateKey, const SPHINXPrivKey& kyberPrivateKey);

    // Function to merge the public keys of Curve448 and Kyber1024
    SPHINXPubKey mergePublicKeys(const SPHINXPubKey& curve448PublicKey, const SPHINXPubKey& kyberPublicKey);

    // Function to generate the hybrid key pair from "hybrid_key.cpp"
    HybridKeypair generate_hybrid_keypair();

    // Function to generate and perform key exchange hybrid method from "hybrid_key.cpp"
    HybridKeypair generate_and_perform_key_exchange();

    // Function to print the generated keys and return them as strings
    std::pair<std::string, std::string> printKeyPair(const std::string& name, const SPHINXPrivKey& privateKey, const SPHINXPubKey& publicKey);
} // namespace SPHINXKey

#endif // HYBRID_KEY_HPP

