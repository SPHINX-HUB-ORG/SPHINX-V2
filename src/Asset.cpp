// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// The provided code defines a namespace called SPHINXAsset and includes two classes: $SPX and AssetManager.

// 1. $SPX class:
  // The constructor $SPX(const std::string& name, const std::string& owner) initializes an asset with a given name and owner.
  // The getId() function returns the ID of the asset.
  // The getName() function returns the name of the asset.
  // The getOwner() function returns the current owner of the asset.
  // The setOwner(const std::string& newOwner) function updates the owner of the asset to the given new owner.
  // The buy(const std::string& buyer) function implements the logic for buying a crypto asset. It updates the ownership of the asset by setting the new owner to the given buyer.

// 2. AssetManager class:
  // The constructor AssetManager() initializes the blockchain data and database.
  // The buySPX(const std::string& assetId, const std::string& buyer, const std::string& payer) function buys a specific SPX asset. It finds the asset in the blockchain data, checks if it exists, updates the ownership by calling the buy() function of the asset, stores the transaction in the blockchain data, and pays the transaction fee.
  // The issueSPX(const std::string& assetName, const std::string& owner, const std::string& payer) function issues a new SPX asset. It generates a unique ID for the asset, generates a key pair using the SPHINXKey namespace, checks the total supply and the developer mining phase, performs the Proof-of-Work (PoW) algorithm to mine the asset, updates the total supply and developer mined supply, checks the halving threshold, stores the transaction in the blockchain data, and pays the transaction fee.
  // The setOwner(const std::string& assetId, const std::string& newOwner, const std::string& payer) function sets the owner of a specific asset. It finds the asset in the blockchain data, checks if it exists, updates the owner by calling the setOwner() function of the asset, stores the transaction in the blockchain data, and pays the transaction fee.
  // The transferSPX(const std::string& assetId, const std::string& newOwner, const std::string& payer) function transfers a specific SPX asset to a new owner. It finds the asset in the blockchain data, checks if it exists, updates the owner by calling the setOwner() function of the asset, stores the transaction in the blockchain data, and pays the transaction fee.
  // The generateUniqueId() function generates a unique ID for the asset using a hybrid key pair.
  // The payTransactionFee(const std::string& payer) function implements the logic to deduct the transaction fee from the payer's account. It currently prints a message indicating the payer of the transaction fee.
  // The findAsset(const std::string& assetId) function finds the asset in the blockchain data based on the given asset ID and returns a pointer to the asset. If the asset is not found, it returns a nullptr.
  // The halveBlockReward() function implements the logic to halve the block reward. It currently halves the block reward by dividing it by 2.
  // The generateTransactionId() function generates a unique transaction ID using a hybrid key pair.
  // The generateTransactionData() function generates the transaction data based on the current state of the asset or any other relevant information. It returns a string representing the transaction data.
  // The id member variable represents the ID of the asset.
  // The totalSupply member variable represents the total supply of the asset.
  // The maxSupply member variable represents the maximum supply of the asset.
  // The halvingThreshold member variable represents the halving threshold for the asset.
  // The blockReward member variable represents the current block reward for mining the asset.
  // The assets member variable is a vector that stores the assets.
  // The db member variable represents the database instance for storing transactions.

// Please note that the code provided is a simplified version and may require additional implementation details for the database, key generation, PoW algorithm, and other functionalities.
/////////////////////////////////////////////////////////////////////////////////////////////////////////



#include <iostream>
#include <string>
#include <vector>
#include <limits>
#include <algorithm>
#include <unordered_map>

#include "Key.hpp"
#include "Asset.hpp"
#include "Miner.hpp"
#include "PoW.hpp"
#include "Transaction.hpp"


namespace SPHINXAsset {

    class $SPX {
    public:
        $SPX(const std::string& name, const std::string& owner)
            : name(name), owner(owner) {}

        std::string getId() const {
            return id;
        }

        std::string getName() const {
            return name;
        }

        std::string getOwner() const {
            return owner;
        }

        void setOwner(const std::string& newOwner) {
            owner = newOwner;
        }

        void buy(const std::string& buyer) {
            // Implement the logic for buying a crypto asset
            // For example, yupdate the ownership of the asset and perform any necessary checks or operations
            // Implement custom logic here
            setOwner(buyer);
        }

    private:
        std::string id;
        std::string name;
        std::string owner;
    };

    class AssetManager {
    public:
        AssetManager() {
            // Initialize the blockchain data and database
        }

        void buySPX(const std::string& assetId, const std::string& buyer, const std::string& payer) {
            // Find the asset in the blockchain data
            $SPX* asset = findAsset(assetId);

            // Check if the asset exists
            if (asset == nullptr) {
                // The asset does not exist
                return;
            }

            // Buy the crypto asset
            asset->buy(buyer);

            // Add the transaction to the blockchain data
            db.storeTransaction(generateTransactionId(), generateTransactionData());

            // Pay the transaction fee
            payTransactionFee(payer);
        }

        void issueSPX(const std::string& assetName, const std::string& owner, const std::string& payer) {
            std::string generateUniqueId() {
            // Generate the key pair using SPHINXKey namespace
            SPHINXKey::HybridKeypair keyPair = SPHINXKey::generateKeyPair();

            // Use the generated key pair as needed
            std::string publicKey = keyPair.publicKey;

            // Generate a unique ID using the public key
            std::string uniqueId = SPHINXKey::generateAddress(publicKey);

            return uniqueId;

            // Generate the key pair using SPHINXKey namespace
            SPHINXKey::HybridKeypair keyPair = SPHINXKey::generateKeyPair();

            // Use the generated key pair as needed
            std::string publicKey = keyPair.publicKey;
            std::string address = SPHINXKey::generateAddress(publicKey);

            // Check if the total supply is less than the maximum supply
            if (totalSupply < maxSupply) {
                // Check if the system is still in the developer mining phase
                if (developerMining) {
                    // Set the desired number of coins per block reward during the developer mining phase
                    int issuanceAmount = 100;  // Set the desired number of coins per block reward during the developer mining phase

                    // Calculate the remaining supply for the developers to mine
                    int remainingSupplyForDevelopers = static_cast<int>(developerAllocationThreshold * maxSupply) - developersMinedSupply;

                    // Calculate the maximum supply to be mined in the current issuance
                    int maxSupplyToBeMined = std::min(remainingSupplyForDevelopers, issuanceAmount);

                    // Perform PoW algorithm to mine the asset
                    int requiredLeadingZeros = 5; // Set the difficulty of mining (number of leading zeros required in the hash)
                    std::cout << "Mining started..." << std::endl;
                    std::string minedHash = SPHINXPoW::performMining(requiredLeadingZeros);

                    for (int64_t nonce = 1; nonce < std::numeric_limits<int64_t>::max(); nonce++) {
                        // Perform PoW algorithm
                        std::string hash = assetName + owner + payer + std::to_string(nonce) + minedHash;
                        double k = SPHINXPoW::select_and_do_operation(hash, nonce);

                        // Check if the final hash meets the target criteria
                        if (SPHINXPoW::meets_target(k, target)) {
                            // Allocate the mined asset to developers
                            $SPX newAsset(assetName, owner);
                            assets.push_back(newAsset);
                            // Increase the total supply by 1
                            totalSupply++;

                            // Increment the developers' mined supply by the newly issued amount
                            developersMinedSupply += maxSupplyToBeMined;

                            // Check if the developers have mined the required allocation threshold
                            if (developersMinedSupply >= developerAllocationThreshold * maxSupply) {
                                developerMining = false; // Switch to normal mode
                            }

                            // Check if the halving threshold is reached
                            if (totalSupply == halvingThreshold) {
                                // Perform halving
                                halveBlockReward();
                            }

                            // Add the transaction to the blockchain data
                            db.storeTransaction(generateTransactionId(), generateTransactionData());

                            // Pay the transaction fee
                            payTransactionFee(payer);

                            break;
                        }
                    }
                }
            }
        }


        void setOwner(const std::string& assetId, const std::string& newOwner, const std::string& payer) {
            // Find the asset in the blockchain data
            $SPX* asset = findAsset(assetId);

            // Check if the asset exists
            if (asset == nullptr) {
                // The asset does not exist
                return;
            }

            // Set the new owner of the asset
            asset->setOwner(newOwner);

            // Add the transaction to the blockchain data
            db.storeTransaction(generateTransactionId(), generateTransactionData());

            // Pay the transaction fee
            payTransactionFee(payer);
        }

        void transferSPX(const std::string& assetId, const std::string& newOwner, const std::string& payer) {
            // Find the asset in the blockchain data
            $SPX* asset = findAsset(assetId);

            // Check if the asset exists
            if (asset == nullptr) {
                // The asset does not exist
                return;
            }

            // Set the new owner of the asset
            asset->setOwner(newOwner);

            // Add the transaction to the blockchain data
            db.storeTransaction(generateTransactionId(), generateTransactionData());

            // Pay the transaction fee
            payTransactionFee(payer);
        }

    private:
        std::string generateUniqueId() {
            // Generate a hybrid key pair
            SPHINXKey::HybridKeypair hybridKeyPair = SPHINXKey::generateKeyPair();

            // Extract the public key from the hybrid key pair
            std::string publicKey = hybridKeyPair.merged_key.x25519_key.public_key;

            // Generate a unique ID using the public key
            std::string uniqueId = SPHINXKey::generateAddress(publicKey);

            return uniqueId;
        }

        void payTransactionFee(const std::string& payer) {
            // Implement the payment logic here to deduct the transaction fee from the payer's account
            // For example, update the account balance or perform any necessary operations

            std::cout << "Transaction fee paid by: " << payer << std::endl;
        }

        $SPX* findAsset(const std::string& assetId) {
            // Find the asset in the blockchain data
            for (auto& asset : assets) {
                if (asset.getId() == assetId) {
                    return &asset;
                }
            }
            return nullptr; // Asset not found
        }

        void halveBlockReward() {
            // Implement the logic to halve the block reward
            // For example, reduce the block reward or token issuance rate

            // Example: Halve the block reward by dividing it by 2
            blockReward /= 2;
        }

        std::string generateTransactionId() {
            // Generate a hybrid key pair
            SPHINXKey::HybridKeypair hybridKeyPair = SPHINXKey::generateKeyPair();

            // Extract the public key from the hybrid key pair
            std::string publicKey = hybridKeyPair.merged_key.x25519_key.public_key;

            // Generate a unique transaction ID using the public key
            std::string transactionId = SPHINXKey::generateAddress(publicKey);

            return transactionId;
        }


        std::string generateTransactionData() {
            SPHINXTrx::Transaction transaction; // Create an instance of the Transaction class

            // Add inputs and outputs to the transaction
            transaction.addInput("Input 1");
            transaction.addInput("Input 2");
            transaction.addOutput("Output 1");
            transaction.addOutput("Output 2");

            // Serialize the transaction to JSON
            std::string jsonData = transaction.serializeToJson();

            // Generate a key pair
            auto keypair = SPHINXSign::generate_keypair();

            // Convert the private key vector to a C-style array (assuming it's 32 bytes)
            const uint8_t* privateKey = keypair.first.data();

            // Convert the public key vector to a C-style array (assuming it's 32 bytes)
            const uint8_t* publicKey = keypair.second.data();

            // Sign the transaction data using the private key
            std::string signature = SPHINXSign::sign_data(std::vector<uint8_t>(jsonData.begin(), jsonData.end()), privateKey, publicKey);

            // Call other functions from SPHINXUtils namespace to perform additional signing-related tasks if needed
            bool isSignatureValid = SPHINXUtils::verifySignature(transaction);
            bool areFundsAvailable = SPHINXUtils::checkFundsAvailability(transaction);

            // Print the signing information
            std::cout << "Transaction signed with private key: " << privateKey << std::endl;
            std::cout << "Signature: " << signature << std::endl;
            std::cout << "Signature Validity: " << (isSignatureValid ? "Valid" : "Invalid") << std::endl;
            std::cout << "Funds Availability: " << (areFundsAvailable ? "Available" : "Not Available") << std::endl;

            return jsonData;
        }

            std::string id;
            int totalSupply = 0; // Set the initial total supply to 0
            const int maxSupply = 50000000; // Set the maximum supply to 50 million
            const int halvingThreshold = 210000; // Set the halving threshold (e.g., 210,000 blocks)
            int blockReward = 50; // Set the initial block reward to 50
            std::vector<$SPX> assets;
            SPHINXDb::Db db; // Database instance
        };
    }
} // namespace SPHINXAsset







