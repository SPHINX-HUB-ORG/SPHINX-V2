/*
 *  Copyright (c) (2023) SPHINX_ORG
 *  Authors:
 *    - (C kusuma) <thekoesoemo@gmail.com>
 *      GitHub: (https://github.com/chykusuma)
 *  Contributors:
 *    - (Contributor 1) <email1@example.com>
 *      Github: (https://github.com/yourgit)
 *    - (Contributor 2) <email2@example.com>
 *      Github: (https://github.com/yourgit)
 */



/////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////
// This code is a part of the SPHINXKey namespace, which provides functions related to the SPHINX (Sphinx-Hybrid Key) cryptographic scheme. The main functionalities include generating SPHINX key pairs, extracting SPHINX public and private keys from a hybrid key pair, calculating the SPHINX public key from the private key, and generating a smart contract address based on the SPHINX public key and a contract name. Let's break down the code and explain each part in detail:

// Type Aliases and Constants:
    // The code defines two type aliases SPHINXPubKey and SPHINXPrivKey to represent SPHINX public and private keys, respectively. Additionally, it defines a constant SPHINX_PUBLIC_KEY_LENGTH which is the size of the SPHINX public key, calculated as the sum of the Kyber768 public key size and the X448 public key size.

// calculatePublicKey Function:
    // This function takes the SPHINX private key as input and calculates the corresponding SPHINX public key. It creates a vector of bytes to store the public key, then calls a hypothetical function calculate_sphinx_public_key, which is assumed to be available externally to calculate the public key. The function returns the computed public key as a vector.

// extractSPHINXPublicKey and extractSPHINXPrivateKey Functions:
    // These functions are used to extract the SPHINX public and private keys, respectively, from a hybrid key pair (HybridKeypair struct). They simply return the corresponding components from the merged_key member of the HybridKeypair structure.

// generateAddress Function:
    // This function generates a smart contract address based on the SPHINX public key and a contract name. It uses the SPHINXHash::SPHINX_256 function (assumed to be available) to hash the SPHINX public key. The function then concatenates the contract name and the hashed public key to create a contract identifier. Finally, the function returns the contract identifier as the smart contract address.

// printKeyPair Lambda Function:
    // This lambda function is defined inside the generateAddress function. It takes a hybrid key pair as input and prints the merged public key and the smart contract address generated from that public key using the generateAddress function.

// generate_hybrid_keypair Function:
    // This function calls the SPHINXHybridKey::generate_hybrid_keypair function from the SPHINXHybridKey namespace (assumed to be available externally). It generates a hybrid key pair using the Kyber768, X25519, and PKE schemes. Then, it returns the generated hybrid key pair.

// The SPHINXKey namespace provides a set of utility functions to work with the SPHINX cryptographic scheme and interacts with other functions available in the SPHINXHybridKey namespace to generate a hybrid key pair and perform key exchange and encryption operations using the Kyber1024, X448, and PKE schemes.
////////////////////////////////////////////////////////////////////////////////////////////////////////



#include <iostream>
#include <string>
#include "Hybrid_key.hpp"
#include "Hash.hpp"
#include "Key.hpp"


namespace SPHINXKey {

    // Define an alias for the merged public key as SPHINXPubKey
    using SPHINXPubKey = std::vector<unsigned char>;

    // Define an alias for the merged private key as SPHINXPrivKey
    using SPHINXPrivKey = std::vector<unsigned char>;

    // Define value of SPHINXPubKey length
    constexpr size_t SPHINX_PUBLIC_KEY_LENGTH = KYBER768_PUBLIC_KEY_LENGTH + CURVE25519_PUBLIC_KEY_SIZE;

    // Function to calculate the SPHINX public key from the private key
    SPHINXPubKey calculatePublicKey(const SPHINXPrivKey& privateKey) {
        SPHINXPubKey publicKey(SPHINX_PUBLIC_KEY_LENGTH);
        // Assuming the appropriate function for calculating SPHINX public key is available
        calculate_sphinx_public_key(publicKey.data(), privateKey.data());
        return publicKey;
    }

    // Function to extract the SPHINX public key from the hybrid keypair
    SPHINXPubKey extractSPHINXPublicKey(const HybridKeypair& hybridKeyPair) {
        return hybridKeyPair.merged_key.kyber_public_key;
    }

    // Function to extract the SPHINX private key from the hybrid keypair
    SPHINXPrivKey extractSPHINXPrivateKey(const HybridKeypair& hybridKeyPair) {
        return hybridKeyPair.merged_key.kyber_private_key;
    }

    // Function to generate the smart contract address based on the public key and contract name
    std::string generateAddress(const std::string& publicKey, const std::string& contractName) {
        // Assume the definition of SPHINXHash::SPHINX_256 function
        std::string hash = SPHINXHash::SPHINX_256(publicKey);

        std::string contractIdentifier = contractName + "_" + hash;
        std::string address = contractIdentifier;

        // Function to print the key pair information
        auto printKeyPair = [](const HybridKeypair& hybridKeyPair) {
            // Extract the public key from the merged key pair
            SPHINXPubKey pubKey = hybridKeyPair.merged_key.kyber_public_key;
            std::string mergedPublicKey(reinterpret_cast<const char*>(pubKey.data()), pubKey.size());

            // Print the merged public key and address
            std::cout << "Merged Public key: " << mergedPublicKey << std::endl;
            std::cout << "Address: " << generateAddress(mergedPublicKey, "MyContract") << std::endl;
        };

        // Call the original function from "hybrid_key.cpp"
        HybridKeypair hybrid_keypair = SPHINXHybridKey::generate_hybrid_keypair();

        // Call the printKeyPair function to print the merged public key and address
        printKeyPair(hybrid_keypair);

        return address;
    }

    // Function to generate the hybrid keypair using functions from "hybrid_key.cpp"
    HybridKeypair generate_hybrid_keypair() {
        // Forward declaration of HybridKeypair struct (if required)
        struct HybridKeypair;

        // Call the original function from "hybrid_key.cpp"
        HybridKeypair hybrid_keypair = SPHINXHybridKey::generate_hybrid_keypair();

        return hybrid_keypair;
    }
} // namespace SPHINXKey




