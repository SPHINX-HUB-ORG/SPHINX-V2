// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The provided code defines a namespace called SPHINXAsset and includes two classes: $SPX and AssetManager.
// The system has several components: a token (SPX), an asset manager, and various reward and mining mechanisms. 
// Let's break down the code piece by piece and explain each part:

// Constants:
    // TOTAL_SUPPLY: The total supply of tokens, set to 50 million.
    // INITIAL_DEVELOPER_MINING_REWARD: The initial reward per block during the developer mining phase.
    // HALVING_PERIOD: The number of blocks per halving period.

// Variables:
    // currentSupply: The current total supply of tokens.
    // currentBlockHeight: The current block height.
    // developerMining: A flag indicating whether the system is in the developer mining phase.

// Namespace SPHINXAsset:
    // This namespace contains classes and functions that define the cryptocurrency system.

// Class SPX (Token):
    // This class represents a token. It has attributes like id, name, and owner (the current owner of the token).
    // The class has methods to get and set the owner and to simulate buying the token.

// Class AssetManager:
    // This class manages the creation, distribution, and ownership of tokens.

// buySPX Method:
    // Buys a specific amount of SPX tokens from an asset using the given buyer and payer.
    // Updates ownership of the asset, stores the transaction in the blockchain data, and pays the transaction fee.

// issueSPX Method:
    // Simulates the issuance of new SPX tokens.
    // Performs Proof of Work (PoW) mining during the developer mining phase.
    // Generates a unique ID, calculates issuance amounts, and allocates rewards to developers.
    // Halves the block reward when a halving threshold is reached.
    // Adds the transaction to the blockchain data and pays the transaction fee.

// distributeRewards Method:
    // Distributes rewards based on the current block height and phase of the system.
    // Rewards are distributed differently during the developer mining phase and the miner rewards phase.

// mineBlock Method:
    // Simulates mining a block by incrementing the current block height.
    // Distributes rewards based on the current phase.

// Ownership and Transfer Methods:
    // setOwner: Sets a new owner for a token asset.
    // transferSPX: Transfers ownership of an SPX token.

// Private Helper Methods:
    // generateUniqueId: Generates a unique ID using a public key.
    // payTransactionFee: Implements the logic for paying transaction fees.
    // findAsset: Searches for an asset by ID in the blockchain data.
    // distributeDeveloperRewards: Distributes rewards during the developer mining phase.
    // distributeMinerRewards: Distributes rewards to miners based on halving schedule.
    // halveBlockReward: Implements the logic to halve the block reward.
    // generateTransactionId: Generates a unique transaction ID using a public key.
    // generateTransactionData: Simulates generating transaction data and includes signature-related steps.

// Constants and Variables within AssetManager:
    // Additional constants and variables specific to the AssetManager class.

// Please note that the code provided is a simplified version and may require additional implementation details for 
// the database, key generation, PoW algorithm, and other functionalities. It includes concepts such as token issuance,
// ownership, mining, block rewards, and transaction processing. Some parts of the code involve placeholders or 
// simplified logic for educational purposes, and in a real-world application, many additional details and security 
// considerations would need to be addressed.
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



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


const int TOTAL_SUPPLY = 50000000; // 50 million tokens
const int INITIAL_DEVELOPER_MINING_REWARD = 100; // Initial reward per block during developer mining phase
const int HALVING_PERIOD = 210000; // Blocks per halving period
int currentSupply = 0; // Current total supply
int currentBlockHeight = 0; // Current block height

namespace SPHINXAsset {

    class SPX {
    public:
        // Constructor to initialize SPX object with name and owner
        SPX(const std::string& name, const std::string& owner)
            : name(name), owner(owner) {}

        // Get the ID of the SPX asset
        std::string getId() const {
            return id;
        }

        // Get the name of the SPX asset
        std::string getName() const {
            return name;
        }

        // Get the owner of the SPX asset
        std::string getOwner() const {
            return owner;
        }

        // Set the owner of the SPX asset to a new owner
        void setOwner(const std::string& newOwner) {
            owner = newOwner;
        }

        // Simulate buying the SPX asset by changing ownership
        void buy(const std::string& buyer) {
            setOwner(buyer);
        }

        private:
            std::string id;      // ID of the SPX asset
            std::string name;    // Name of the SPX asset
            std::string owner;   // Owner of the SPX asset
    };

    class AssetManager {
    public:
        AssetManager() {
            // Initialize the blockchain data and database
            currentSupply = 0; // Set the initial total supply to 0
            currentBlockHeight = 0; // Set the current block height to 0
            developerMining = true; // Start in developer mining phase
        }

        void buySPX(const std::string& assetId, const std::string& buyer, const std::string& payer) {
            // Find the asset in the blockchain data
            SPX* asset = findAsset(assetId);

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
            // Generate a unique ID using the public key
            std::string uniqueId = generateUniqueId();

            // Generate the key pair using SPHINXKey namespace
            SPHINXKey::HybridKeypair keyPair = SPHINXKey::generateKeyPair();

            // Use the generated key pair as needed
            std::string publicKey = keyPair.publicKey;

            // Check if the total supply is less than the maximum supply
            if (totalSupply < maxSupply) {
                // Check if the system is still in the developer mining phase
                if (developerMining) {
                    // Set the desired number of coins per block reward during the developer mining phase
                    int issuanceAmount = 100; // Set the desired number of coins per block reward during the developer mining phase

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
                            SPX newAsset(assetName, owner);
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

        void distributeRewards() {
            if (currentBlockHeight <= 5 * 30 * 24 * 60 * 4) {
                // Developer Mining Phase (first 5 months)
                currentSupply += INITIAL_DEVELOPER_MINING_REWARD;
            } else if (currentBlockHeight <= 210000) {
                // Transition to Miner Rewards Phase (remaining blocks of Year 1)
                currentSupply += INITIAL_DEVELOPER_MINING_REWARD;
            } else {
                // Miner Rewards Phase (Year 2 onwards)
                int currentHalvingPeriod = (currentBlockHeight - 210000) / HALVING_PERIOD;

                int reward = 100;

                // Determine reward based on halving schedule
                if (currentHalvingPeriod >= 1) {
                    reward /= 2;
                }
                if (currentHalvingPeriod >= 2) {
                    reward /= 2;
                }
                if (currentHalvingPeriod >= 3) {
                    reward /= 2;
                }
                if (currentHalvingPeriod >= 4) {
                    reward /= 2;
                }
                if (currentHalvingPeriod >= 5) {
                    reward /= 2;
                }

                currentSupply += reward;
            }
        }

        void mineBlock() {
            // Simulate mining a block
            currentBlockHeight++;

            if (developerMining) {
                distributeDeveloperRewards();
            } else {
                distributeMinerRewards();
            }
        }

        void setOwner(const std::string& assetId, const std::string& newOwner, const std::string& payer) {
            // Find the asset in the blockchain data
            SPX* asset = findAsset(assetId);

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
            SPX* asset = findAsset(assetId);

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

        SPX* findAsset(const std::string& assetId) {
            // Find the asset in the blockchain data
            for (auto& asset : assets) {
                if (asset.getId() == assetId) {
                    return &asset;
                }
            }
            return nullptr; // Asset not found
        }

        void distributeDeveloperRewards() {
            if (currentBlockHeight <= 5 * BLOCKS_PER_MONTH) {
                // Developer Mining Phase (first 5 months)
                currentSupply += INITIAL_DEVELOPER_MINING_REWARD;
            } else {
                developerMining = false; // Transition to miner rewards phase
                distributeMinerRewards();
            }
        }

        void distributeMinerRewards() {
            int currentHalvingPeriod = (currentBlockHeight - HALVING_START_BLOCK) / HALVING_PERIOD;

            if (currentHalvingPeriod >= HALVING_SCHEDULE.size()) {
                return; // Mining period ended
            }

            int reward = HALVING_SCHEDULE[currentHalvingPeriod];

            currentSupply += reward;
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

        int currentSupply = 0; // Current total supply
        int currentBlockHeight = 0; // Current block height
        bool developerMining = true; // Flag indicating developer mining phase

        const int BLOCKS_PER_MONTH = 30 * 24 * 60 * 4; // Number of blocks per month
        const int INITIAL_DEVELOPER_MINING_REWARD = 100; // Initial reward per block during developer mining phase
        const int HALVING_START_BLOCK = 5 * BLOCKS_PER_MONTH; // Block height to start halving rewards
        const int HALVING_PERIOD = 210000; // Blocks per halving period

        const std::vector<int> HALVING_SCHEDULE = {100, 50, 25, 12, 6}; // Halving reward schedule
    };
} // namespace SPHINXAsset
