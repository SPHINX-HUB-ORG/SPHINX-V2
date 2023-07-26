// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINX_HYBRID_KEY_HPP
#define SPHINX_HYBRID_KEY_HPP

#include <utility>
#include <array>
#include <iostream>
#include <algorithm>
#include <random>
#include <string>
#include <vector>
#include <cstdint>

#include "lib/Openssl/evp.h"
#include "lib/Openssl/hkdf.h" 
#include "lib/Openssl/hmac.h"
#include "lib/Openssl/curve448/point_448.h"
#include "lib/Openssl/sha.h"
#include "lib/Swifftx/SHA3.h"
#include "lib/Kyber/include/kyber1024_kem.hpp"
#include "lib/Kyber/include/kyber1024_pke.hpp"
#include "lib/Kyber/include/encapsulation.hpp"
#include "lib/Kyber/include/decapsulation.hpp"
#include "lib/Kyber/include/encryption.hpp"
#include "lib/Kyber/include/compression.hpp"
#include "lib/Kyber/include/pke_keygen.hpp"


namespace SPHINXHybridKey {

    // Constants
    constexpr size_t CURVE448_PRIVATE_KEY_SIZE = 56;
    constexpr size_t CURVE448_PUBLIC_KEY_SIZE = 56;
    constexpr size_t CURVE448_SHARED_SECRET_SIZE = 56;
    constexpr size_t HMAC_MAX_MD_SIZE = 64;
    constexpr size_t SWIFFTX512_DIGEST_SIZE = 65;
    constexpr size_t SPHINXHash_DIGEST_SIZE = 65;
    constexpr size_t KYBER1024_PUBLIC_KEY_LENGTH = 800;
    constexpr size_t KYBER1024_PRIVATE_KEY_LENGTH = 1632;
    constexpr size_t KYBER1024_CIPHERTEXT_LENGTH = 1088;
    constexpr size_t KYBER1024_SHARED_SECRET_LENGTH = 32;
    constexpr size_t KYBER1024_PKE_PUBLIC_KEY_LENGTH = 800;
    constexpr size_t KYBER1024_PKE_PRIVATE_KEY_LENGTH = 1632;
    constexpr size_t KYBER1024_PKE_CIPHERTEXT_LENGTH = 1088;

    #define CURVE448_PRIVATE_KEY_SIZE 56
    #define CURVE448_PUBLIC_KEY_SIZE 56
    #define CURVE448_SHARED_SECRET_SIZE 56
    #define HMAC_MAX_MD_SIZE 64
    #define SWIFFTX512_DIGEST_SIZE 65
    #define SPHINXHash_DIGEST_SIZE 65
    #define KYBER1024_PUBLIC_KEY_LENGTH 800
    #define KYBER1024_PRIVATE_KEY_LENGTH 1632
    #define KYBER1024_CIPHERTEXT_LENGTH 1088
    #define KYBER1024_SHARED_SECRET_LENGTH 32
    #define KYBER1024_PKE_PUBLIC_KEY_LENGTH 800
    #define KYBER1024_PKE_PRIVATE_KEY_LENGTH 1632
    #define KYBER1024_PKE_CIPHERTEXT_LENGTH 1088

    // Forward declaration
    namespace kyber1024_kem {
        void keygen(std::vector<unsigned char>& public_key, std::vector<unsigned char>& private_key);
        void encapsulate(unsigned char* ciphertext, const unsigned char* public_key, const unsigned char* shared_secret, const unsigned char* private_key);
        void decapsulate(unsigned char* shared_secret, const unsigned char* ciphertext, const unsigned char* private_key);
    }

    // Forward declaration
    namespace kyber1024_pke {
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

    // Function to perform the X448 key exchange
    void performX448KeyExchange(unsigned char shared_key[CURVE448_SHARED_SECRET_SIZE], const unsigned char private_key[CURVE448_PRIVATE_KEY_SIZE], const unsigned char public_key[CURVE448_PUBLIC_KEY_SIZE]);

    // Structure to hold the merged keypair
    struct HybridKeypair {
        struct {
            // Kyber1024 keypair
            std::vector<unsigned char> kyber_public_key;
            std::vector<unsigned char> kyber_private_key;
        } merged_key;

        // X448 keypair
        std::pair<std::vector<unsigned char>, std::vector<unsigned char>> x448_key;

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

    // Function to encrypt a message using Kyber1024 KEM
    std::string encryptMessage(const std::string& message, const std::vector<uint8_t>& public_key_pke);

    // Function to decrypt a message using Kyber1024 KEM
    std::string decryptMessage(const std::string& encrypted_message, const std::vector<uint8_t>& secret_key_pke);

    // Function to encapsulate a shared secret using the hybrid KEM
    std::string encapsulateHybridSharedSecret(const HybridKeypair& hybrid_keypair, std::vector<uint8_t>& encapsulated_key);

    // Function to decapsulate a shared secret using the hybrid KEM
    std::string decapsulateHybridSharedSecret(const HybridKeypair& hybrid_keypair, const std::vector<uint8_t>& encapsulated_key);

} // namespace SPHINXHybridKey

#endif // SPHINX_HYBRID_KEY_HPP
