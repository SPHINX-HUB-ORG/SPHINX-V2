// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <string>
#include <vector>
#include "base58check.h"
#include "script.hpp"
#include "hash.hpp"

namespace SPHINXCheck {

    class Checksum {
    public:
        static bool validateAddress(const std::string& address);

    private:
        static bool isAddressValidLength(const std::string& address);
        static bool isAddressValidChecksum(const std::string& address);
        static void sha3Hash256(const std::vector<uint8_t>& data, unsigned char* hash); // Rename the function
        static bool isDigitalSignatureValid(const std::string& address);
    };

    bool Checksum::validateAddress(const std::string& address) {
        // Check if the address is the correct length
        if (!isAddressValidLength(address)) {
            return false;
        }

        // Check if the address has a valid checksum
        if (!isAddressValidChecksum(address)) {
            return false;
        }

        // Check if the digital signature is valid
        if (!isDigitalSignatureValid(address)) {
            return false;
        }

        // TODO: Add more validation logic if needed

        return true;
    }

    bool Checksum::isAddressValidLength(const std::string& address) {
        // The address must be 64 characters long
        return address.length() == 64;
    }

    bool Checksum::isAddressValidChecksum(const std::string& address) {
        // The checksum is the last 8 characters of the address
        std::string checksum = address.substr(address.length() - 8);

        // Decode the Base58Check address to retrieve the original data
        std::vector<uint8_t> decodedData;
        if (!Base58Check::decode(address, decodedData)) {
            // Error occurred during decoding
            return false;
        }

        // Calculate the checksum using SHA3-256
        std::vector<uint8_t> decodedDataWithoutChecksum(decodedData.begin(), decodedData.end() - 4);
        unsigned char sha3Hash[32]; // Change the hash size
        sha3Hash256(decodedDataWithoutChecksum, sha3Hash); // Call the new hash function

        // Encode the hash using Base58
        std::string encodedHash = base58check_encode(sha3Hash, 32); // Change the hash size

        // Get the first 4 characters of the encoded hash as the calculated checksum
        std::string calculatedChecksum = encodedHash.substr(0, 4);

        // Compare the calculated checksum with the provided checksum
        return checksum == calculatedChecksum;
    }

    void Checksum::sha3Hash256(const std::vector<uint8_t>& data, unsigned char* hash) {
        // Convert data vector to array
        uint8_t dataArray[data.size()];
        std::copy(data.begin(), data.end(), dataArray);

        // Calculate SHA3-256 hash
        std::string dataString(reinterpret_cast<const char*>(dataArray), data.size());
        std::string hashString = SPHINXHash::sha3_256(dataString); // Call the new hash function

        // Convert the hash string to an array
        for (int i = 0; i < 32; ++i) {
            std::string hex = hashString.substr(i * 2, 2);
            hash[i] = std::stoi(hex, nullptr, 16);
        }
    }

    bool Checksum::isDigitalSignatureValid(const std::string& address) {
        // Extract the signature from the address
        std::string signature = address.substr(0, address.length() - 8);

        // Decode the Base58Check signature to retrieve the original signature data
        std::vector<uint8_t> decodedSignature;
        if (!Base58Check::decode(signature, decodedSignature)) {
            // Error occurred during decoding.
            return false;
        }

        // TODO: Perform digital signature validation logic

        return true;
    }

} // namespace SPHINXCheck

#endif  // CHECKSUM_H












