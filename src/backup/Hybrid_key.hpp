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


#ifndef SPHINX_HYBRID_KEY_HPP
#define SPHINX_HYBRID_KEY_HPP

#pragma once

#include <utility>
#include <array>
#include <iostream>
#include <algorithm>
#include <random>
#include <string>
#include <vector>
#include <cstdint>

namespace SPHINXHybridKey {

    // Constants
    constexpr size_t CURVE25519_PRIVATE_KEY_SIZE = 32;
    constexpr size_t CURVE25519_PUBLIC_KEY_SIZE = 32;
    constexpr size_t CURVE25519_SHARED_SECRET_SIZE = 32;
    constexpr size_t KYBER768_PUBLIC_KEY_LENGTH = 1184;
    constexpr size_t KYBER768_PRIVATE_KEY_LENGTH = 2400;
    constexpr size_t KYBER768_CIPHERTEXT_LENGTH = 1088;
    constexpr size_t KYBER768_SHARED_SECRET_LENGTH = 32;
    constexpr size_t KYBER768_PKE_PUBLIC_KEY_LENGTH = 1184;
    constexpr size_t KYBER768_PKE_PRIVATE_KEY_LENGTH = 2400;
    constexpr size_t KYBER768_PKE_CIPHERTEXT_LENGTH = 1088;

    // Forward declaration
    namespace kyber768_kem {
        void keygen(std::vector<unsigned char>& public_key, std::vector<unsigned char>& private_key);
        void encapsulate(unsigned char* ciphertext, const unsigned char* public_key, const unsigned char* shared_secret, const unsigned char* private_key);
        void decapsulate(unsigned char* shared_secret, const unsigned char* ciphertext, const unsigned char* private_key);
    }

    // Forward declaration
    namespace kyber768_pke {
        void keygen(unsigned char* random_bytes, unsigned char* public_key, unsigned char* secret_key);
        void encrypt(const unsigned char* public_key, const unsigned char* message, size_t message_length,
                const unsigned char* nonce, size_t nonce_length, unsigned char* ciphertext, size_t ciphertext_length,
                size_t tag_length);
        void decrypt(const unsigned char* secret_key, const unsigned char* ciphertext, size_t ciphertext_length,
                size_t tag_length, unsigned char* message, size_t message_length);
    }

    // Forward declaration
    namespace SPHINXHash {
        std::string SPHINX_256(const std::string& input);
    }

    // Function to perform the X25519 key exchange
    void performX25519KeyExchange(unsigned char shared_key[CURVE25519_SHARED_SECRET_SIZE], const unsigned char private_key[CURVE25519_PRIVATE_KEY_SIZE], const unsigned char public_key[CURVE25519_PUBLIC_KEY_SIZE]);

    // Structure to hold the merged keypair
    struct HybridKeypair {
        struct {
            // Kyber768 keypair
            std::vector<unsigned char> kyber_public_key;
            std::vector<unsigned char> kyber_private_key;
        } merged_key;

        // X25519 keypair
        std::pair<std::vector<unsigned char>, std::vector<unsigned char>> X25519_key;

        // PKE keypair
        std::vector<uint8_t> public_key_pke;
        std::vector<uint8_t> secret_key_pke;

        // PRNG for key generation
        std::vector<unsigned char> prng;
    };

    // HybridKeyPair Function to generate the hybrid keypair and corresponding private and public keys
    HybridKeypair generate_hybrid_keypair();

    // Function to generate a random nonce
    std::string generateRandomNonce();

    // Function to derive a key using HKDF
    std::string deriveKeyHKDF(const std::string& inputKeyMaterial, const std::string& salt, const std::string& info, size_t keyLength);

    // Function to calculate the SWIFFTX-256 hash of a string
    std::string hash(const std::string& input);

    // Function to generate an address from a public key
    std::string generateAddress(const std::string& publicKey);

    // Function to encrypt a message using Kyber768 KEM
    std::string encryptMessage(const std::string& message, const std::vector<uint8_t>& public_key_pke);

    // Function to decrypt a message using Kyber768 KEM
    std::string decryptMessage(const std::string& encrypted_message, const std::vector<uint8_t>& secret_key_pke);

    // Function to encapsulate a shared secret using the hybrid KEM
    std::string encapsulateHybridSharedSecret(const HybridKeypair& hybrid_keypair, std::vector<uint8_t>& encapsulated_key);

    // Function to decapsulate a shared secret using the hybrid KEM
    std::string decapsulateHybridSharedSecret(const HybridKeypair& hybrid_keypair, const std::vector<uint8_t>& encapsulated_key);

} // namespace SPHINXHybridKey

#endif // SPHINX_HYBRID_KEY_HPP
