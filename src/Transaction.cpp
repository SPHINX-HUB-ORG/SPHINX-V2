// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


/////////////////////////////////////////////////////////////////////////////////////////////////////////
// The code provided defines a namespace SPHINXTrx that contains the implementation of a Transaction class related to the SPHINX protocol. Let's go through the code:

  // The line using json = nlohmann::json; introduces an alias json for the nlohmann::json class from the Nlohmann JSON library. This allows to use json instead of the full class name.

  // The Transaction class has a default constructor, Transaction::Transaction(), which is not implemented in the provided code. This can assume that it contains the necessary logic to initialize a transaction object.

  // The addInput function, Transaction::addInput(const std::string& input), is not implemented in the provided code. This function is responsible for adding an input to the transaction.

  // The addOutput function, Transaction::addOutput(const std::string& output), is not implemented in the provided code. This function is responsible for adding an output to the transaction.

  // The serializeToJson function, Transaction::serializeToJson() const, serializes the transaction object into a JSON string representation. It uses the Nlohmann JSON library to convert the transaction data to a JSON object, assigns the data to the data JSON object, and then calls data.dump() to serialize the JSON object to a string. The serialized JSON string is returned.

  // The deserializeFromJson function, Transaction::deserializeFromJson(const std::string& jsonData), deserializes the transaction object from a JSON string representation. It uses the Nlohmann JSON library to parse the JSON string into a JSON object data using json::parse(jsonData). The function then extracts the transaction data from the data JSON object and updates the member variables of the transaction object accordingly.

  // The signTransaction function, Transaction::signTransaction(const std::string& privateKey), performs the signing of the transaction. It first calls the serializeToBinary function (not provided in the code) to obtain the binary representation of the transaction. Then, it uses the SPHINXUtils::hash function to calculate the hash of the serialized binary transaction. It calls other functions from the SPHINXUtils namespace (such as SPHINXUtils::generateRandomNonce, SPHINXUtils::verifySignature, and SPHINXUtils::checkFundsAvailability) to perform signing-related tasks, such as generating a random nonce, verifying the signature, and checking funds availability. Finally, it prints the signing information, including the private key used, the transaction hash, the nonce, and the validity of the signature and funds availability.

// This provided code defines a Transaction class within the SPHINXTrx namespace. The class contains functions to add inputs and outputs to the transaction, serialize and deserialize the transaction to/from JSON, and sign the transaction using various utility functions from the SPHINXUtils namespace.
/////////////////////////////////////////////////////////////////////////////////////////////////////////


#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "Transaction.hpp"
#include "json.hh"
#include "Asset.hpp"
#include "db.hpp"
#include "Sign.hpp"
#include "Mempool.hpp"
#include "MerkleBlock.hpp"
#include "Utxo.hpp"

using json = nlohmann::json;

using namespace SPHINXUtxo;

// Forward declarations for functions that are defined later in "Merkleblock.hpp"
std::string generateOrRetrieveSecretKeySeed();
std::string generateOrRetrievePublicKeySeed();
bool verifySignature(const std::string& data, const std::string& signature, const SPHINXMerkleBlock::SPHINXPubKey& publicKey);

namespace SPHINXTrx {

    void broadcastTransaction(const std::string& transactionData) {
        // Implement the logic to broadcast the transaction to the mempool
        std::cout << "Broadcasting transaction to the mempool: " << transactionData << std::endl;
    }

    std::string hash(const std::string& data);
    unsigned int generateRandomNonce();
    bool verifySignature(const std::string& data, const SPHINXPrivKey& privateKey);
    bool checkFundsAvailability(const std::string& transactionData);

    class Transaction {
    public:
        std::string data;
        std::string signature;
        SPHINXMerkleBlock::SPHINXPubKey publicKey;

        // Other member functions

        std::string toJson() const {
            json transactionJson;
            transactionJson["data"] = data;
            transactionJson["signature"] = signature;
            transactionJson["publicKey"] = SPHINXMerkleBlock::pubKeyToString(publicKey); // Convert publicKey to string
            return transactionJson.dump();
        }

        void fromJson(const std::string& jsonStr) {
            json transactionJson = json::parse(jsonStr);
            data = transactionJson["data"].get<std::string>();
            signature = transactionJson["signature"].get<std::string>();
            publicKey = SPHINXMerkleBlock::stringToPubKey(transactionJson["publicKey"].get<std::string>()); // Convert string to publicKey
        }

        void sign(const std::string& senderPrivateKey) {
            // Create a private key object from the string
            std::string transactionJson = toJson();
            std::string transactionHash = hash(transactionJson);

            // Sign the transaction using the private key
            signature = SPHINXMerkleBlock::SPHINXSign(transactionHash, senderPrivateKey);
        }

        bool isConfirmed() const {
            // Check if the transaction is confirmed
            // Implement the confirmation logic
            return true; // Replace with actual confirmation logic
        }

        std::string serializeToJson() const {
            json data;
            data["senderAddress"] = senderAddress;
            data["recipientAddress"] = recipientAddress;
            data["amount"] = amount;
            data["timestamp"] = timestamp;
            data["signature"] = signature;
            data["senderPublicKey"] = senderPublicKey;
            data["transactionData"] = transactionData; // Serialize transaction data
            return data.dump();
        }

        void deserializeFromJson(const std::string& jsonData) {
            json data = json::parse(jsonData);
            senderAddress = data["senderAddress"].get<std::string>();
            recipientAddress = data["recipientAddress"].get<std::string>();
            amount = data["amount"].get<double>();
            timestamp = data["timestamp"].get<std::time_t>();
            signature = data["signature"].get<std::string>();
            senderPublicKey = data["senderPublicKey"].get<std::string>();
            transactionData = data["transactionData"].get<std::string>(); // Deserialize transaction data
        }

        // New function to request UTXO data from SPHINXUtxo
        std::vector<UTXO> requestUTXOData(const std::string& address) {
            // Call the function from SPHINXUtxo to get UTXOs for the given address
            std::map<std::string, UTXO> utxoSet; // This will hold the UTXO data
            // Assuming there's a function in SPHINXUtxo to retrieve UTXO data for a specific address
            return findUTXOsForAddress(address, utxoSet);
        }

        std::string SPHINXTrx::Transaction::signTransaction(const std::string& privateKey) const {
            std::string transactionHash = hash(serializeToJson());

            // Call the checkFundsAvailability function from "utxo.cpp" to verify funds
            bool areFundsAvailable = checkFundsAvailability(serializeToJson());

            if (!areFundsAvailable) {
                std::cout << "Funds not available for the transaction." << std::endl;
                return ""; // Transaction signing failed due to insufficient funds
            }

            // Print the signing information
            std::cout << "Transaction signed with private key: " << privateKey << std::endl;
            std::cout << "Transaction Hash: " << transactionHash << std::endl;
            std::cout << "Nonce: " << nonce << std::endl;
            std::cout << "Signature Validity: " << (isSignatureValid ? "Valid" : "Invalid") << std::endl;
            std::cout << "Funds Availability: " << (areFundsAvailable ? "Available" : "Not Available") << std::endl;

            broadcastTransaction(transactionHash); // Broadcast the transaction to the mempool

            return transactionHash;
        }
    };
} // namespace SPHINXTrx








