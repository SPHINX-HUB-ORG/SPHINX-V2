// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The provided code belongs to the SPHINXCheck namespace and includes a class called Checksum. Let's understand the class and its 
// functions:

// Class Checksum and its Public Member Functions:
    // bool validateAddress(const std::string& address): This is the primary function that validates the given address. It performs the 
    // following steps:
        // Calls the private member function isAddressValidLength to check if the address is of the correct length (64 characters). 
        // If not, it immediately returns false, indicating an invalid address.
        // Calls the private member function isAddressValidChecksum to verify if the address's checksum is valid. It uses the Base58Check 
        // decoding to retrieve the original data and then calculates a checksum based on the data using SPHINXKey::sphinxHash256 function
        // from "Key.cpp." It then compares the calculated checksum with the provided checksum. If they don't match, it returns false, 
        // indicating an invalid address.
        // Calls the private member function isDigitalSignatureValid to check if the digital signature of the address is valid. This part
        // is currently a placeholder (as indicated by the TODO comment) and requires additional implementation for the actual digital 
        // signature validation. For now, it always returns true.
        // If all the checks pass, the function returns true, indicating a valid address.

// Private Member Functions:
    // bool isAddressValidLength(const std::string& address): This function checks if the given address is of the correct length. It returns
    // true if the address length is 64 characters; otherwise, it returns false.
    // bool isAddressValidChecksum(const std::string& address): This function validates the checksum of the address. It performs the 
    // following steps:
        // Extracts the last 8 characters from the address, which represent the checksum.
        // Decodes the Base58Check address to retrieve the original data.
        // Calculates the checksum using the SPHINXKey::sphinxHash256 function from "Key.cpp" by excluding the last 4 bytes (checksum) 
        // from the decoded data.
        // Encodes the calculated hash as Base58 and retrieves the first 4 characters as the calculated checksum.
        // Compares the calculated checksum with the provided checksum and returns true if they match; otherwise, it returns false.
        // bool isDigitalSignatureValid(const std::string& address): This function currently serves as a placeholder for validating the 
        // digital signature of the address. It extracts the signature from the address, decodes it using Base58Check, and returns true. 
        // However, this part is not fully implemented and should be customized to perform the actual digital signature validation.

// Note that the code provided is a simplified version and may require additional implementation details for the Base58Check class, 
// digital signature validation, and other functionalities related to address validation in blockchain systems.
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



#include <string>
#include <vector>
#include <iostream>
#include <array>

#include "Consensus/Consensus.hpp"
#include "base58check.h"
#include "Checksum.hpp"
#include "Hash.hpp"
#include "Key.hpp" 

namespace SPHINXCheck {

    class Checksum {
    public:
        bool validateAddress(const std::string& address);

    private:
        bool isAddressValidLength(const std::string& address);
        bool isAddressValidChecksum(const std::string& address);
        bool isDigitalSignatureValid(const std::string& address);
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

        // Calculate the checksum using SPHINXHash::SPHINX_256
        std::vector<uint8_t> decodedDataWithoutChecksum(decodedData.begin(), decodedData.end() - 4);
        unsigned char sphinxHash[32];
        SPHINXKey::sphinxHash256(decodedDataWithoutChecksum, sphinxHash);

        // Encode the hash using Base58
        std::string encodedHash = base58check_encode(sphinxHash, 32);

        // Get the first 4 characters of the encoded hash as the calculated checksum
        std::string calculatedChecksum = encodedHash.substr(0, 4);

        // Compare the calculated checksum with the provided checksum
        return checksum == calculatedChecksum;
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


