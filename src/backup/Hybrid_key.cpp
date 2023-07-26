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
// The code provided belongs to the SPHINXHybridKey namespace and contains various functions and a 
// structure related to hybrid key operations using different cryptographic algorithms. Let's go through 
// each part of the code to understand its functionality:

// performX25519KeyExchange:
    // This function performs the X25519 key exchange by utilizing the curve25519_keypair and curve25519_scalarmult functions. It takes private and public keys as input and computes the shared key.

// HybridKeypair structure:
    // This structure holds the merged keypair information.
    // It has the following members:
        // merged_key: A nested structure that stores the Kyber768 keypair (kyber_public_key and kyber_private_key).
        // X25519_key: A pair of vectors (first and second) to store the Curve25519 keypair.
        // public_key_pke: A vector to hold the public key for PKE (Public Key Encryption).
        // secret_key_pke: A vector to hold the secret key for PKE.
        // prng: An instance of the kyber768_pke::RandomNumberGenerator for key generation.

// generate_hybrid_keypair:
    // This function generates a hybrid keypair.
    // It generates the Kyber768 keypair using the keygen function and stores it in merged_key.kyber_public_key and merged_key.kyber_private_key.
    // It generates the Curve25519 keypair using the curve25519_keypair function and stores it in x25519_key.
    // It resizes the PKE keypair vectors (public_key_pke and secret_key_pke) and generates the PKE keypair using the keygen function.

// deriveMasterKeyAndChainCode:
    // This function derives the master private key and chain code from a given seed.
    // It uses the deriveKeyHMAC_SWIFFTX function to derive the master private key and chain code based on the seed.
    // It returns the derived master private key and chain code as a pair of strings.

// deriveKeyHMAC_SHA512:
    // This function derives a key using HMAC-SHA512.
    // It takes a key and data as input and performs HMAC-SHA512 hashing using the provided key and data.
    // It returns the derived key as a string.
    // hashSWIFFTX512:
        // This function calculates the SWIFFTX-512 hash of a string.
        // It initializes the hash state, updates it with the input data, and finalizes the hash.
        // It returns the hashed data as a string.

// generateRandomNonce:
    // This function generates a random nonce using the SPHINXUtils::generateRandomNonce function.
    // It returns the generated nonce as a string.

// deriveKeyHKDF:
    // This function derives a key using the HKDF (HMAC-based Key Derivation Function) algorithm.
    // It takes the input key material, salt, info, and key length as input.
    // It uses the EVP_PKEY functions to perform HKDF with SHA256.
    // It returns the derived key as a compressed key (SPHINX-256 hash) in a string.
    // hash:
        // This function calculates the SWIFFTX-256 hash of a string.
        // It uses the SPHINXHash::SPHINX_256 function to compute the hash.
        // It returns the hashed data as a string.

// generateKeyPair:
    // This function generates a key pair.
    // It generates a random private key and computes the public key by hashing the private key.
    // It returns the key pair as a pair of strings (private key and public key).

// generateAddress:
    // This function generates an address from a given public key.
    // It computes the hash of the public key and returns the first 20 characters of the hash as the address.

// requestDigitalSignature:
    // This function requests a digital signature for a given data using the hybrid keypair.
    // It uses the SPHINXSign::verify_data function to generate the signature.
    // It returns the signature as a string.

// encryptMessage:
    // This function encrypts a message using Kyber768 KEM (Key Encapsulation Mechanism).
    // It takes a message and a public key for PKE as input.
    // It generates a random nonce and uses the cpapke::encrypt function to encrypt the message.
    // It returns the encrypted message as a string.

// decryptMessage:
    // This function decrypts an encrypted message using Kyber768 KEM.
    // It takes the encrypted message and the secret key for PKE as input.
    // It uses the cpapke::decrypt function to decrypt the message.
    // It returns the decrypted message as a string.

// encapsulateHybridSharedSecret:
    // This function encapsulates a shared secret using the hybrid KEM (Key Encapsulation Mechanism).
    // It takes the hybrid keypair and a vector to store the encapsulated key as input.
    // It performs the X25519 key exchange and the Kyber768 encapsulation to derive the shared secret and encapsulated key.
    // It returns the shared secret as a string.

// decapsulateHybridSharedSecret:
    // This function decapsulates a shared secret using the hybrid KEM.
    // It takes the hybrid keypair and the encapsulated key as input.
    // It performs the X25519 key exchange and the Kyber768 decapsulation to derive the shared secret.
    // It checks if the derived shared secret matches the provided shared secret and throws an error if they don't match.
    // It returns the shared secret as a string.

// This code provides functions for generating and manipulating hybrid keypairs using Curve25519 and Kyber768 algorithms. It also includes functions for key derivation, hashing, encryption, decryption, and digital signatures.
////////////////////////////////////////////////////////////////////////////////////////////////////////



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
#include "lib/Openssl/curve25519.h"
#include "lib/Openssl/sha.h"
#include "lib/Swifftx/SHA3.h"
#include "lib/Kyber/include/kyber768_kem.hpp"
#include "lib/Kyber/include/kyber768_pke.hpp"
#include "lib/Kyber/include/encapsulation.hpp"
#include "lib/Kyber/include/decapsulation.hpp"
#include "lib/Kyber/include/encryption.hpp"
#include "lib/Kyber/include/compression.hpp"
#include "lib/Kyber/include/pke_keygen.hpp"

#include "lib/Swifftx/SHA3.h"
#include "Hash.hpp"
#include "Key.hpp"
#include "Transaction.hpp"
#include "Hybrid_key.hpp"


namespace SPHINXHybridKey {

    // Constants
    constexpr size_t CURVE2519_PRIVATE_KEY_SIZE = 32;
    constexpr size_t CURVE2519_PUBLIC_KEY_SIZE = 32;
    constexpr size_t CURVE2519_SHARED_SECRET_SIZE = 32;
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
    void performX25519KeyExchange(unsigned char shared_key[CURVE25519_SHARED_SECRET_SIZE], const unsigned char private_key[CURVE448_PRIVATE_KEY_SIZE], const unsigned char public_key[CURVE448_PUBLIC_KEY_SIZE]) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_derive_set_peer(ctx, EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, public_key, CURVE448_PUBLIC_KEY_SIZE));
        size_t shared_key_len;
        EVP_PKEY_derive(ctx, shared_key, &shared_key_len);
        EVP_PKEY_CTX_free(ctx);
    }

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

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    // HybridKeyPair Function to generate the hybrid keypair and corresponding private and public keys
    // The code first generates a Kyber768 keypair for KEM, then generates an X25519 keypair, and 
    // finally generates a PKE keypair. The private and public keys are then derived from the master 
    // private key and chain code using HMAC-SHA512.
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    HybridKeypair generate_hybrid_keypair() {
        HybridKeypair hybrid_keypair;
        hybrid_keypair.prng.resize(32);

        // Generate Kyber768 keypair for KEM
        hybrid_keypair.merged_key.kyber_public_key.resize(KYBER768_PUBLIC_KEY_LENGTH);
        hybrid_keypair.merged_key.kyber_private_key.resize(KYBER768_PRIVATE_KEY_LENGTH);
        kyber768_kem::keygen(hybrid_keypair.merged_key.kyber_public_key.data(), hybrid_keypair.merged_key.kyber_private_key.data());

        // Generate X25519 keypair
        hybrid_keypair.X25519_key.first.resize(CURVE25519_PUBLIC_KEY_SIZE);
        hybrid_keypair.X25519_key.second.resize(CURVE25519_PRIVATE_KEY_SIZE);
        RAND_bytes(hybrid_keypair.X25519_key.first.data(), CURVE25519_PUBLIC_KEY_SIZE);
        RAND_bytes(hybrid_keypair.X25519_key.second.data(), CURVE25519_PRIVATE_KEY_SIZE);

        // Resize PKE keypair vectors
        hybrid_keypair.public_key_pke.resize(KYBER768_PKE_PUBLIC_KEY_LENGTH);
        hybrid_keypair.secret_key_pke.resize(KYBER768_PKE_PRIVATE_KEY_LENGTH);

        // Generate PKE keypair
        kyber768_pke::keygen(hybrid_keypair.prng.data(), hybrid_keypair.public_key_pke.data(), hybrid_keypair.secret_key_pke.data());

        // Derive the master private key and chain code using HMAC-SHA512 from a seed value
        std::string seed = "ThisIsAVeryLongAndRandomStringThatIsAtLeast256BitsLong";
        std::pair<std::string, std::string> masterKeyAndChainCode = deriveMasterKeyAndChainCode(seed);

        // Derive the private and public keys using HMAC-SHA512 from the master private key and chain code
        std::string SPHINXPrivKey = deriveKeyHMAC_SHA512(masterKeyAndChainCode.first, "private_key_salt");
        std::string SPHINXPubKey = deriveKeyHMAC_SHA512(masterKeyAndChainCode.second, "public_key_salt");

        // Hash the master private key and chain code using SPHINXHash::SPHINX_256
        SPHINXPrivKey = SPHINXHash::SPHINX_256(SPHINXPrivKey);
        SPHINXPubKey = SPHINXHash::SPHINX_256(SPHINXPubKey);

        // Save the private and public keys in the hybrid keypair
        hybrid_keypair.SPHINXPrivKey.resize(PRIVATE_KEY_LENGTH);
        hybrid_keypair.SPHINXPubKey.resize(PUBLIC_KEY_LENGTH);
        std::copy(SPHINXPrivKey.begin(), SPHINXPrivKey.end(), hybrid_keypair.SPHINXPrivKey.begin());
        std::copy(SPHINXPubKey.begin(), SPHINXPubKey.end(), hybrid_keypair.SPHINXPubKey.begin());

        return hybrid_keypair;
    }

    // Function to generate a random nonce
    std::string generateRandomNonce() {
        std::string nonce(32, '\0');
        RAND_bytes(reinterpret_cast<unsigned char*>(&nonce[0]), nonce.size());
        return nonce;
    }

    // Function to derive a key using HKDF
    std::string deriveKeyHKDF(const std::string& inputKeyMaterial, const std::string& salt, const std::string& info, size_t keyLength) {
        std::string derivedKey(keyLength, 0);

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_key(ctx, reinterpret_cast<const unsigned char*>(inputKeyMaterial.c_str()), inputKeyMaterial.length());
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length());
        EVP_PKEY_CTX_add1_hkdf_info(ctx, reinterpret_cast<const unsigned char*>(info.c_str()), info.length());
        EVP_PKEY_CTX_set1_hkdf_keylen(ctx, keyLength);
        EVP_PKEY_derive(ctx, reinterpret_cast<unsigned char*>(derivedKey.data()), &keyLength);
        EVP_PKEY_CTX_free(ctx);

        return derivedKey;
    }

    // Function to calculate the SWIFFTX-256 hash of a string
    std::string hash(const std::string& input) {
        return SPHINXHash::SPHINX_256(input);
    }

    // Function to generate an address from a public key
    std::string generateAddress(const std::string& publicKey) {
        std::string hash = hash(publicKey);
        std::string address = hash.substr(0, 20);

        return address;
    }

    // Function to encrypt a message using Kyber768 KEM
    std::string encryptMessage(const std::string& message, const std::vector<uint8_t>& public_key_pke) {
        constexpr size_t tagLength = 16;

        std::string encrypted_message(KYBER768_PKE_CIPHERTEXT_LENGTH + tagLength, 0);

        std::string nonce = generateRandomNonce();

        kyber768_pke::encrypt(public_key_pke.data(),
            reinterpret_cast<const unsigned char*>(message.data()), message.length(),
            reinterpret_cast<const unsigned char*>(nonce.data()), nonce.length(),
            reinterpret_cast<uint8_t*>(encrypted_message.data()), encrypted_message.length(),
            tagLength
        );

        return encrypted_message;
    }

    // Function to decrypt a message using Kyber768 KEM
    std::string decryptMessage(const std::string& encrypted_message, const std::vector<uint8_t>& secret_key_pke) {
        constexpr size_t tagLength = 16;

        std::string decrypted_message(encrypted_message.length() - KYBER768_PKE_CIPHERTEXT_LENGTH, 0);

         kyber768_pke::decrypt(secret_key_pke.data(),
            reinterpret_cast<const unsigned char*>(encrypted_message.data()), encrypted_message.length(),
            tagLength,
            reinterpret_cast<uint8_t*>(decrypted_message.data()), decrypted_message.length()
        );

        return decrypted_message;
    }

    // Function to encapsulate a shared secret using the hybrid KEM
    std::string encapsulateHybridSharedSecret(const HybridKeypair& hybrid_keypair, std::vector<uint8_t>& encapsulated_key) {
        encapsulated_key.resize(KYBER768_CIPHERTEXT_LENGTH);
        unsigned char X25519_private_key[CURVE25519_PRIVATE_KEY_SIZE];
        curve25519_keypair(hybrid_keypair.X25519_key.first.data(), X25519_private_key);

        unsigned char shared_secret[CURVE25519_SHARED_SECRET_SIZE];
        performX25519KeyExchange(shared_secret, X25519_private_key, hybrid_keypair.merged_key.kyber_public_key.data());

        kyber768_kem::encapsulate(encapsulated_key.data(), hybrid_keypair.X25519_key.first.data(), hybrid_keypair.merged_key.kyber_public_key.data(), hybrid_keypair.merged_key.kyber_private_key.data());

        return std::string(reinterpret_cast<char*>(shared_secret), CURVE25519_SHARED_SECRET_SIZE);
    }

    // Function to decapsulate a shared secret using the hybrid KEM
    std::string decapsulateHybridSharedSecret(const HybridKeypair& hybrid_keypair, const std::vector<uint8_t>& encapsulated_key) {
        unsigned char X25519_public_key[CURVE25519_PUBLIC_KEY_SIZE];
        unsigned char shared_secret[CURVE25519_SHARED_SECRET_SIZE];
        kyber768_kem::decapsulate(shared_secret, encapsulated_key.data(), hybrid_keypair.merged_key.kyber_private_key->data());

        unsigned char derived_shared_secret[CURVE25519_SHARED_SECRET_SIZE];
        performX25519KeyExchange(derived_shared_secret, hybrid_keypair.X25519_key.second.data(), X25519_public_key);

        if (std::memcmp(shared_secret, derived_shared_secret, CURVE25519_SHARED_SECRET_SIZE) != 0) {
            throw std::runtime_error("Shared secret mismatch");
        }

        return std::string(reinterpret_cast<char*>(shared_secret), CURVE25519_SHARED_SECRET_SIZE);
    }
}  // namespace SPHINXHybridKey
