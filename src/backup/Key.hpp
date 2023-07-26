/*
 *  Copyright (c) (2023) SPHINX_ORG
 *  Authors:
 *    - (C kusuma) <thekoesoemo@gmail.com>
 *      GitHub: (https://github.com/cahyaksm)
 *  Contributors:
 *    - (Contributor 1) <email1@example.com>
 *      Github: (https://github.com/yourgit)
 *    - (Contributor 2) <email2@example.com>
 *      Github: (https://github.com/yourgit)
 */


#ifndef SPHINX_KEY_HPP
#define SPHINX_KEY_HPP

#include <vector>
#include <string>

// Forward declaration of HybridKeypair struct (if required)
struct HybridKeypair;

namespace SPHINXKey {

    // Define an alias for the merged public key as SPHINXPubKey
    using SPHINXPubKey = std::vector<unsigned char>;

    // Define an alias for the merged private key as SPHINXPrivKey
    using SPHINXPrivKey = std::vector<unsigned char>;

    // Define value of SPHINXPubKey length
    constexpr size_t SPHINX_PUBLIC_KEY_LENGTH = KYBER768_PUBLIC_KEY_LENGTH + CURVE25519_PUBLIC_KEY_SIZE;

    // Function to calculate the SPHINX public key from the private key
    SPHINXPubKey calculatePublicKey(const SPHINXPrivKey& privateKey);

    // Function to extract the SPHINX public key from the hybrid keypair
    SPHINXPubKey extractSPHINXPublicKey(const HybridKeypair& hybridKeyPair);

    // Function to extract the SPHINX private key from the hybrid keypair
    SPHINXPrivKey extractSPHINXPrivateKey(const HybridKeypair& hybridKeyPair);

    // Function to generate the smart contract address based on the public key and contract name
    std::string generateAddress(const std::string& publicKey, const std::string& contractName);

    // Function to generate the hybrid keypair using functions from "hybrid_key.cpp"
    HybridKeypair generate_hybrid_keypair();
} // namespace SPHINXKey

#endif // SPHINXKEY_HPP
