// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The provided code defines various functions related to generating and working with hybrid key pairs using cryptographic algorithms like
// Curve448, Kyber1024, and SPHINXhash hash functions.

// Namespaces SPHINXHybridKey and SPHINXHash:
    // The code starts with defining two namespaces: SPHINXHybridKey and SPHINXHash.
    // SPHINXHybridKey does not contain any actual functions or data; it only has a dummy struct HybridKeypair, which is currently empty.
    // SPHINXHash contains two functions: SPHINX_256 and RIPEMD_160. These functions are currently implemented as dummy functions for 
    // demonstration purposes.

// Base58 Encoding:
    // The code defines a static string base58_chars which contains the characters used in Base58 encoding.
    // The function EncodeBase58 takes a vector of unsigned characters as input and encodes it into a Base58 string.
    // The function calculates the number of leading zeros in the input data, converts the data to a big-endian number, and then performs
    // Base58 encoding.

// SPHINXKey Namespace:
    // This namespace contains several functions related to the generation and manipulation of cryptographic keys.
    // Constants CURVE448_PRIVATE_KEY_SIZE, CURVE448_PUBLIC_KEY_SIZE, and KYBER1024_PUBLIC_KEY_LENGTH define the sizes of keys for 
    // Curve448 and Kyber1024 algorithms.
    // HYBRID_KEYPAIR_LENGTH is the total length of the hybrid key pair, which combines the public keys of both algorithms with extra 
    // HMAC sizes.

// calculatePublicKey Function:
    // This function calculates the SPHINX public key from the private key by extracting the Kyber1024 public key from the merged private
    // key.

// sphinxKeyToString Function:
    // This function converts the binary representation of SPHINX key (private or public) to a string.

// generateAddress Function:
    // This function generates a smart contract address based on the public key and contract name.
    // It first converts the public key to a string, then performs SPHINX_256 and RIPEMD-160 hashes on the public key string.
    // It adds a version byte (0x00) to the RIPEMD-160 hash and calculates the checksum using double SPHINX_256 hash.
    // Finally, it performs Base58Check encoding to create the contract address.

// mergePrivateKeys and mergePublicKeys Functions:
    // These functions are used to merge the private keys and public keys of Curve448 and Kyber1024.

// generate_hybrid_keypair Function:
    // This function generates the hybrid key pair by combining the keys generated from Curve448 and Kyber1024 algorithms.
    // It uses the private and public key generation functions from an external source hybrid_key.cpp, which are not defined in the 
    // provided code snippet.
    // The merged private and public keys are obtained by concatenating the corresponding keys from the two algorithms and then hashing 
    // the merged private key using SPHINX_256.
    // The result is stored in a struct HybridKeypair from the SPHINXHybridKey namespace.

// generate_and_perform_key_exchange Function:
    // This function generates and performs a key exchange using the hybrid key pair.
    // It follows similar steps as the generate_hybrid_keypair function to generate the hybrid key pair.
    // It then performs a key exchange using the X448 and Kyber1024 key encapsulation mechanisms (KEM).
    // It also encrypts and decrypts a sample message using Kyber1024 public key encryption (PKE) to demonstrate the use of the keys.

// printKeyPair Function:
    // This function takes a name (identifier), private key, and public key as input.
    // It converts the private and public keys to strings and prints them.
    // It then generates a contract address based on the public key and a contract name and prints it.
    // Finally, it returns the private key and public key as strings.

// The SPHINXKey namespace provides a set of utility functions to work with the SPHINX cryptographic scheme and interacts with other 
// functions available in the SPHINXHybridKey namespace to generate a hybrid key pair and perform key exchange and encryption operations 
// using the Kyber1024, X448, and PKE schemes.
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


#include <string>
#include <vector>
#include <cstring>
#include <utility>
#include <iostream>
#include <algorithm>
#include <cstdint>

#include "Hybrid_key.hpp"
#include "Hash.hpp"
#include "Key.hpp"
#include "base58check.h"
#include "base58.h"
#include "hash/Ripmed160.hpp"


namespace SPHINXHybridKey {
    // Assume the definition of SPHINXHybridKey
    struct HybridKeypair {};
}

namespace SPHINXHash {
    // Assume the definition of SPHINX_256 function
    std::string SPHINX_256(const std::vector<unsigned char>& data) {
        // Dummy implementation for demonstration purposes
        return "hashed_" + std::string(data.begin(), data.end());
    }

    // Assume the definition of RIPEMD-160 function
    std::string RIPEMD_160(const std::vector<unsigned char>& data) {
        // Dummy implementation for demonstration purposes
        return "ripemd160_" + std::string(data.begin(), data.end());
    }
}

// Base58 characters (excluding confusing characters: 0, O, I, l) for human readability
static const std::string base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Function to encode data using Base58
std::string EncodeBase58(const std::vector<unsigned char>& data) {
    // Count leading zeros
    size_t zeros_count = 0;
    for (const unsigned char byte : data) {
        if (byte != 0) {
            break;
        }
        ++zeros_count;
    }

    // Convert the data to a big-endian number
    uint64_t num = 0;
    for (size_t i = zeros_count; i < data.size(); ++i) {
        num = num * 256 + data[i];
    }

    // Calculate the necessary length for the encoded string
    size_t encoded_length = (data.size() - zeros_count) * 138 / 100 + 1;
    std::string encoded(encoded_length, '1');

    // Encode the big-endian number in Base58
    for (size_t i = 0; num > 0; ++i) {
        const uint64_t remainder = num % 58;
        num /= 58;
        encoded[encoded_length - i - 1] = base58_chars[remainder];
    }

    return encoded;
}

namespace SPHINXKey {

    // Constants
    constexpr size_t CURVE448_PRIVATE_KEY_SIZE = 56;
    constexpr size_t CURVE448_PUBLIC_KEY_SIZE = 56;
    constexpr size_t KYBER1024_PUBLIC_KEY_LENGTH = 800;
    
    // Size of HYBRIDKEY
    constexpr size_t HYBRID_KEYPAIR_LENGTH = SPHINXHybridKey::CURVE448_PUBLIC_KEY_SIZE + SPHINXHybridKey::KYBER1024_PUBLIC_KEY_LENGTH + 2 * SPHINXHybridKey::HMAC_MAX_MD_SIZE;
    // HYBRID_KEYPAIR_LENGTH = 56 (Curve448 public key size) + 800 (Kyber1024 public key length) + 2 * 64 (HMAC_MAX_MD_SIZE) = 976;

    // Define an alias for the merged public key as SPHINXPubKey
    using SPHINXPubKey = std::vector<unsigned char>;

    // Define an alias for the merged private key as SPHINXPrivKey
    using SPHINXPrivKey = std::vector<unsigned char>;

    // Function to calculate the SPHINX public key from the private key
    SPHINXKey::SPHINXPubKey calculatePublicKey(const SPHINXKey::SPHINXPrivKey& privateKey) {
        // The length of the Kyber1024 public key
        constexpr size_t KYBER_PUBLIC_KEY_LENGTH = SPHINXKey::KYBER1024_PUBLIC_KEY_LENGTH;

        // Calculate the SPHINX public key by extracting the Kyber1024 public key from the merged private key
        SPHINXKey::SPHINXPubKey sphinxPubKey(privateKey.begin() + CURVE448_PRIVATE_KEY_SIZE, privateKey.end());

        return sphinxPubKey;
    }

    // Function to convert SPHINXKey to string
    std::string sphinxKeyToString(const SPHINXKey::SPHINXKey& key) {
        return std::string(key.begin(), key.end());
    }

    // Function to generate the smart contract address based on the public key and contract name
    std::string generateAddress(const SPHINXKey::SPHINXPubKey& publicKey, const std::string& contractName) {
        // Step 1: Convert the public key to a string
        std::string pubKeyString = sphinxKeyToString(publicKey);

        // Step 2: Perform the SPHINX_256 hash on the public key (assuming it returns a std::string)
        std::string sphinxHash = SPHINXHash::SPHINX_256(pubKeyString);

        // Step 3: Perform the RIPEMD-160 hash on the SPHINX_256 hash (assuming it returns a std::string)
        std::string ripemd160Hash = SPHINXHash::RIPEMD_160(sphinxHash);

        // Step 4: Add a version byte to the RIPEMD-160 hash (optional)
        // For Bitcoin addresses, the version byte is 0x00 (mainnet). We can change it if needed.
        unsigned char versionByte = 0x00;
        std::string dataWithVersion(1, versionByte);
        dataWithVersion += ripemd160Hash;

        // Step 5: Calculate the checksum (first 4 bytes of double SPHINX_256 hash)
        std::string checksum = SPHINXHash::SPHINX_256(SPHINXHash::SPHINX_256(dataWithVersion)).substr(0, 4);

        // Step 6: Concatenate the data with the checksum
        std::string dataWithChecksum = dataWithVersion + checksum;

        // Step 7: Perform Base58Check encoding
        std::string address = EncodeBase58(reinterpret_cast<const unsigned char*>(dataWithChecksum.data()),
                                           dataWithChecksum.size());

        return address;
    }

    // Function to merge the private keys of Curve448 and Kyber1024
    SPHINXKey::SPHINXPrivKey mergePrivateKeys(const SPHINXKey::SPHINXPrivKey& curve448PrivateKey, const SPHINXKey::SPHINXPrivKey& kyberPrivateKey) {
        SPHINXKey::SPHINXPrivKey mergedPrivateKey;
        mergedPrivateKey.reserve(curve448PrivateKey.size() + kyberPrivateKey.size());
        mergedPrivateKey.insert(mergedPrivateKey.end(), curve448PrivateKey.begin(), curve448PrivateKey.end());
        mergedPrivateKey.insert(mergedPrivateKey.end(), kyberPrivateKey.begin(), kyberPrivateKey.end());
        return SPHINXHash::SPHINX_256(mergedPrivateKey); // Hash the merged private key
    }

    // Function to merge the public keys of Curve448 and Kyber1024
    SPHINXKey::SPHINXPubKey mergePublicKeys(const SPHINXKey::SPHINXPubKey& curve448PublicKey, const SPHINXKey::SPHINXPubKey& kyberPublicKey) {
        SPHINXKey::SPHINXPubKey mergedPublicKey;
        mergedPublicKey.reserve(curve448PublicKey.size() + kyberPublicKey.size());
        mergedPublicKey.insert(mergedPublicKey.end(), curve448PublicKey.begin(), curve448PublicKey.end());
        mergedPublicKey.insert(mergedPublicKey.end(), kyberPublicKey.begin(), kyberPublicKey.end());
        return SPHINXHash::SPHINX_256(mergedPublicKey); // Hash the merged public key
    }

    // Function to generate the hybrid key pair from "hybrid_key.cpp"
    SPHINXHybridKey::HybridKeypair generate_hybrid_keypair() {
        // Function to merge the private keys of Curve448 and Kyber1024
        auto mergePrivateKeys = [](const SPHINXKey::SPHINXPrivKey& curve448PrivateKey, const SPHINXKey::SPHINXPrivKey& kyberPrivateKey) {
            SPHINXKey::SPHINXPrivKey mergedPrivateKey;
            mergedPrivateKey.insert(mergedPrivateKey.end(), curve448PrivateKey.begin(), curve448PrivateKey.end());
            mergedPrivateKey.insert(mergedPrivateKey.end(), kyberPrivateKey.begin(), kyberPrivateKey.end());
            return SPHINXHash::SPHINX_256(mergedPrivateKey); // Hash the merged private key
        };

        // Function to merge the public keys of Curve448 and Kyber1024
        auto mergePublicKeys = [](const SPHINXKey::SPHINXPubKey& curve448PublicKey, const SPHINXKey::SPHINXPubKey& kyberPublicKey) {
            SPHINXKey::SPHINXPubKey mergedPublicKey;
            mergedPublicKey.insert(mergedPublicKey.end(), curve448PublicKey.begin(), curve448PublicKey.end());
            mergedPublicKey.insert(mergedPublicKey.end(), kyberPublicKey.begin(), kyberPublicKey.end());
            return SPHINXHash::SPHINX_256(mergedPublicKey); // Hash the merged public key
        };

        // Generate Curve448 key pair from hybrid_key.cpp
        SPHINXKey::SPHINXPrivKey curve448PrivateKey = generateCurve448PrivateKey();
        SPHINXKey::SPHINXPubKey curve448PublicKey = generateCurve448PublicKey();

        // Generate Kyber1024 key pair from hybrid_key.cpp
        SPHINXKey::SPHINXPrivKey kyberPrivateKey = generateKyberPrivateKey();
        SPHINXKey::SPHINXPubKey kyberPublicKey = generateKyberPublicKey();

        // Merge the private keys
        SPHINXKey::SPHINXPrivKey sphinxPrivKey = mergePrivateKeys(curve448PrivateKey, kyberPrivateKey);

        // Merge the public keys
        SPHINXKey::SPHINXPubKey sphinxPubKey = mergePublicKeys(curve448PublicKey, kyberPublicKey);

        // Create the hybrid key pair structure
        SPHINXHybridKey::HybridKeypair hybridKeyPair;
        hybridKeyPair.merged_key.sphinxPrivKey = sphinxPrivKey;
        hybridKeyPair.merged_key.sphinxPubKey = sphinxPubKey;

        return hybridKeyPair;
    }

    // Function to generate and perform key exchange hybrid method from "hybrid_key.cpp"
    SPHINXHybridKey::HybridKeypair generate_and_perform_key_exchange() {
        // Function to merge the private keys of Curve448 and Kyber1024
        auto mergePrivateKeys = [](const SPHINXKey::SPHINXPrivKey& curve448PrivateKey, const SPHINXKey::SPHINXPrivKey& kyberPrivateKey) {
            SPHINXKey::SPHINXPrivKey mergedPrivateKey;
            mergedPrivateKey.insert(mergedPrivateKey.end(), curve448PrivateKey.begin(), curve448PrivateKey.end());
            mergedPrivateKey.insert(mergedPrivateKey.end(), kyberPrivateKey.begin(), kyberPrivateKey.end());
            return SPHINXHash::SPHINX_256(mergedPrivateKey); // Hash the merged private key
        };

        // Function to merge the public keys of Curve448 and Kyber1024
        auto mergePublicKeys = [](const SPHINXKey::SPHINXPubKey& curve448PublicKey, const SPHINXKey::SPHINXPubKey& kyberPublicKey) {
            SPHINXKey::SPHINXPubKey mergedPublicKey;
            mergedPublicKey.insert(mergedPublicKey.end(), curve448PublicKey.begin(), curve448PublicKey.end());
            mergedPublicKey.insert(mergedPublicKey.end(), kyberPublicKey.begin(), kyberPublicKey.end());
            return SPHINXHash::SPHINX_256(mergedPublicKey); // Hash the merged public key
        };

        // Generate Curve448 key pair
        SPHINXKey::SPHINXPrivKey curve448PrivateKey = SPHINXHybridKey::generateCurve448PrivateKey();
        SPHINXKey::SPHINXPubKey curve448PublicKey = SPHINXHybridKey::generateCurve448PublicKey();

        // Generate Kyber1024 key pair
        SPHINXKey::SPHINXPrivKey kyberPrivateKey = SPHINXHybridKey::generateKyberPrivateKey();
        SPHINXKey::SPHINXPubKey kyberPublicKey = SPHINXHybridKey::generateKyberPublicKey();

        // Merge the private keys
        SPHINXKey::SPHINXPrivKey sphinxPrivKey = mergePrivateKeys(curve448PrivateKey, kyberPrivateKey);

        // Merge the public keys
        SPHINXKey::SPHINXPubKey sphinxPubKey = mergePublicKeys(curve448PublicKey, kyberPublicKey);

        // Create the hybrid key pair structure
        SPHINXHybridKey::HybridKeypair hybridKeyPair;
        hybridKeyPair.merged_key.sphinxPrivKey = sphinxPrivKey;
        hybridKeyPair.merged_key.sphinxPubKey = sphinxPubKey;

        // Perform the key exchange using X448 and Kyber1024 KEM
        std::vector<uint8_t> encapsulated_key;
        std::string shared_secret = SPHINXHybridKey::encapsulateHybridSharedSecret(hybridKeyPair, encapsulated_key);

        // Decapsulate the shared secret using Kyber1024 KEM
        std::string decapsulated_shared_secret = SPHINXHybridKey::decapsulateHybridSharedSecret(hybridKeyPair, encapsulated_key);

        // Check if the decapsulated shared secret matches the original shared secret
        if (decapsulated_shared_secret == shared_secret) {
            std::cout << "Decapsulation successful. Shared secrets match." << std::endl;
        } else {
            std::cout << "Decapsulation failed. Shared secrets do not match." << std::endl;
        }

        // Example message to be encrypted
        std::string message = "Hello, this is a secret message.";

        // Encrypt the message using Kyber1024 PKE with the public key
        std::string encrypted_message = SPHINXHybridKey::encryptMessage(message, hybridKeyPair.public_key_pke);

        // Decrypt the message using Kyber1024 PKE with the secret key
        std::string decrypted_message = SPHINXHybridKey::decryptMessage(encrypted_message, hybridKeyPair.secret_key_pke);

        // Print the original message, encrypted message, and decrypted message
        std::cout << "Original Message: " << message << std::endl;
        std::cout << "Encrypted Message: " << encrypted_message << std::endl;
        std::cout << "Decrypted Message: " << decrypted_message << std::endl;

        // Return the shared secret as specified in the function signature
        return shared_secret;
    }

    // Function to print the generated keys and return them as strings
    std::pair<std::string, std::string> printKeyPair(const std::string& name, const SPHINXKey::SPHINXPrivKey& privateKey, const SPHINXKey::SPHINXPubKey& publicKey) {
        // Convert private key to string
        std::string privKeyString = sphinxKeyToString(privateKey);
        // Convert public key to string
        std::string pubKeyString = sphinxKeyToString(publicKey);

        // Print the private and public keys
        std::cout << name << " private key: " << privKeyString << std::endl;
        std::cout << name << " public key: " << pubKeyString << std::endl;

        // Generate and print the contract address
        std::string contractName = "MyContract";
        std::string contractAddress = generateAddress(publicKey, contractName);
        std::cout << "Contract Address: " << contractAddress << std::endl;

        // Return the keys and contract address as strings
        return std::make_pair(privKeyString, pubKeyString);
    }
} // namespace SPHINXKey


// Usage
int main() {
    // Generate the hybrid key pair
    SPHINXHybridKey::HybridKeypair hybridKeyPair = SPHINXKey::generate_hybrid_keypair();

    // Print the hybrid key pair
    std::cout << "Hybrid Key Pair:" << std::endl;
    std::cout << "Merged Private Key: ";
    for (const auto& byte : hybridKeyPair.merged_key.sphinxPrivKey) {
        std::cout << std::hex << static_cast<int>(byte);
    }
    std::cout << std::endl;

    std::cout << "Merged Public Key: ";
    for (const auto& byte : hybridKeyPair.merged_key.sphinxPubKey) {
        std::cout << std::hex << static_cast<int>(byte);
    }
    std::cout << std::endl;

    // Generate and perform key exchange
    SPHINXHybridKey::HybridKeypair exchangedKeys = SPHINXKey::generate_and_perform_key_exchange();

    // Print the shared secret (Example: For demonstration purposes)
    std::cout << "Shared Secret: ";
    for (const auto& byte : exchangedKeys.shared_secret) {
        std::cout << std::hex << static_cast<int>(byte);
    }
    std::cout << std::endl;

    // Call the printKeyPair function to print and get the keys and address as strings
    std::pair<std::string, std::string> keys = SPHINXKey::printKeyPair("ExampleKeyPair", exchangedKeys.merged_key.sphinxPrivKey, exchangedKeys.merged_key.sphinxPubKey);

    // Access the keys and contract address as strings
    std::string private_key_str = keys.first;
    std::string public_key_str = keys.second;

    // Example usage: print the keys and contract address
    std::cout << "Private Key as String: " << private_key_str << std::endl;
    std::cout << "Public Key as String: " << public_key_str << std::endl;

    return 0;
}
