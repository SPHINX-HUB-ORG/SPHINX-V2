// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The given code represents a Miner class in the SPHINXMiner namespace, which is responsible for mining blocks by finding valid 
// proof-of-work. 

    // Miner::Miner(): This is the constructor for the Miner class. It initializes the member variables difficulty_, 
    // rewardHalvingInterval_, and reward_ with their respective values. Additionally, it creates an instance of the 
    // SPHINXAsset::AssetManager class and issues the genesis block reward by calling the issueSPX function with the appropriate 
    // parameters.

    // Block Miner::mineBlock(const std::string& previousHash, const std::string& rewardAddress): This function is responsible for 
    // mining a new block. It takes the previousHash and rewardAddress as parameters. It initializes a blockData string by concatenating 
    // the previousHash and rewardAddress. It then enters a loop where it generates a hash by concatenating the blockData with a nonce 
    // value. The hash is checked for the proof-of-work requirement by comparing the first difficulty_ characters with the required 
    // number of leading zeros. If the proof-of-work requirement is met, a reward is issued to the miner using the issueSPX function from
    // the SPHINXAsset::AssetManager class. The loop breaks once a valid proof-of-work is found. Finally, a new Block object is created, 
    // and the reward transaction is added to it along with the current timestamp.

    // std::string Miner::calculateProofOfWork(const std::string& blockData, int difficulty): This function calculates the 
    // proof-of-work for a given blockData string and difficulty level. It repeatedly appends a "nonce" string to the blockData and 
    // calculates the hash using the SPHINXHash::SPHINX_256 function from the Hash.hpp file. It checks if the resulting proof-of-work 
    // satisfies the difficulty requirement (leading zeros), and once it does, it returns the proof-of-work string.

    // void Miner::performMining(): This function simulates the mining process. It contains two scenarios: the developer mining phase and
    // the normal mining phase. It initializes variables such as totalBlocks, developerBlocks, minedBlocks, developerMinedBlocks, 
    // developerMining, blockData, rewardAddress, and nonces with their respective values.

    // In the developer mining phase, the function enters a loop where it generates hashes with different nonce values and checks for 
    // valid proof-of-work. If a valid proof-of-work is found, a reward is issued to the miner, and the necessary counters are incremented.
    // Once the required number of developer blocks is mined, the function transitions to the normal mining phase.

    // In the normal mining phase, the function follows a similar loop, generating hashes and checking for valid proof-of-work. If a valid
    // proof-of-work is found, a reward is issued, and the necessary counters are updated. The loop continues until the total number of 
    // blocks is mined.

    // void Miner::updateReward(): This function checks if the current block height is at a reward halving interval (determined by 
    // rewardHalvingInterval_). If the condition is met, the reward is halved by dividing it by 2.

// This functions defined in Miner.cpp can create an instance of the Miner class, call the mineBlock function to mine new blocks, and 
// perform the mining process using the performMining function.
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


#include <chrono>
#include <cmath>
#include <iostream>
#include <vector>
#include <ctime>
#include <string>
#include <iostream>
#include "Miner.hpp"
#include "PoW.hpp"
#include "Hash.hpp"
#include "Block.hpp"
#include "Asset.hpp"
#include "Node.hpp"

namespace SPHINXMiner {

    Miner::Miner() : difficulty_(4), rewardHalvingInterval_(210000), reward_(50) {
        // Constructor implementation...
        SPHINXAsset::AssetManager assetManager;
        assetManager.issueSPX("Genesis Block Reward", rewardAddress, reward_, rewardAddress);
    }

    Block Miner::mineBlock(const std::string& previousHash, const std::string& rewardAddress) {
        // Mine a new block by finding a valid proof-of-work
        std::string blockData = previousHash + rewardAddress;
        int nonce = 0;

        while (true) {
            std::string hash = SPHINXHash::SPHINX_256(blockData + std::to_string(nonce)); // Use the SPHINX_256 function from Hash.hpp

            std::string proofOfWork = hash.substr(0, difficulty_);
            if (proofOfWork == std::string(difficulty_, '0')) {
                // Reward the miner with an asset
                SPHINXAsset::AssetManager assetManager;
                assetManager.issueSPX("Reward Asset", rewardAddress, reward_, rewardAddress); // Pass the reward amount as a parameter

                break;
            }

            // Increment the nonce to change the block data
            nonce++;
        }

        Block newBlock(previousHash);
        newBlock.addTransaction(rewardAddress + ":" + proofOfWork);
        newBlock.setTimestamp(std::time(nullptr));

        return newBlock;
    }

    std::string Miner::calculateProofOfWork(const std::string& blockData, int difficulty) {
        // Calculate the proof-of-work by finding a hash that satisfies the difficulty requirement
        std::string proofOfWork;
        std::string target(difficulty, '0');

        while (true) {
            std::string hash = SPHINXHash::SPHINX_256(blockData); // Use the SPHINX_256 function from Hash.hpp

            proofOfWork = hash.substr(0, difficulty);
            if (proofOfWork == target) {
                break;
            }

            // Increment the nonce to change the block data
            blockData += "nonce";
        }

        return proofOfWork;
    }

    void Miner::performMining() {
        SPHINXPoW::solveNonce(blockData, difficulty_); // Modify the parameters as needed

        int64_t totalBlocks = 50000000; // Total number of crypto assets to mine
        int64_t developerBlocks = totalBlocks * 0.3; // Number of crypto assets to be mined by developers

        int64_t minedBlocks = 0; // Counter for total mined crypto assets
        int64_t developerMinedBlocks = 0; // Counter for developer mined crypto assets

        bool developerMining = true; // Flag to indicate developer mining

        std::string blockData = ""; // Initialize blockData variable
        std::string rewardAddress = ""; // Initialize rewardAddress variable
        int64_t nonces = 1000000; // Define the number of nonces

        // Scenario 1: Developer Mining Phase
        while (developerMinedBlocks < developerBlocks) {
            for (int64_t nonce = 1; nonce < nonces; nonce++) {
                std::string hash = SPHINXHash::SPHINX_256(blockData + std::to_string(nonce)); // Use the SPHINX_256 function from Hash.hpp

                std::string proofOfWork = hash.substr(0, difficulty_);
                if (proofOfWork == std::string(difficulty_, '0')) {
                    // Reward the miner with an asset
                    SPHINXAsset::AssetManager assetManager;
                    assetManager.issueSPX("Reward Asset", rewardAddress, reward_); // Pass the reward amount as a parameter

                    minedBlocks++;
                    developerMinedBlocks++;

                    if (developerMinedBlocks >= developerBlocks) {
                        std::cout << "Developer mining phase completed. Transitioning to normal mining." << std::endl;
                        developerMining = false;
                    }

                    if (minedBlocks == totalBlocks) {
                        std::cout << "All crypto assets mined!" << std::endl;
                        return;
                    }

                    // Adjust the reward based on the block height
                    updateReward();

                    break;
                }

                // Increment the nonce to change the block data
                nonce++;
            }
        }

        // Scenario 2: Normal Mining Phase
        while (minedBlocks < totalBlocks) {
            for (int64_t nonce = 1; nonce < nonces; nonce++) {
                std::string hash = SPHINXHash::SPHINX_256(blockData + std::to_string(nonce)); // Use the SPHINX_256 function from Hash.hpp

                std::string proofOfWork = hash.substr(0, difficulty_);
                if (proofOfWork == std::string(difficulty_, '0')) {
                    // Reward the miner with an asset
                    SPHINXAsset::AssetManager assetManager;
                    assetManager.issueSPX("Reward Asset", rewardAddress, reward_); // Pass the reward amount as a parameter

                    minedBlocks++;

                    if (minedBlocks == totalBlocks) {
                        std::cout << "All crypto assets mined!" << std::endl;
                        return;
                    }

                    // Adjust the reward based on the block height
                    updateReward();

                    break;
                }

                // Increment the nonce to change the block data
                nonce++;
            }
        }
    }

    void Miner::updateReward() {
        // Check if the block height reaches a reward halving interval
        if ((blockHeight_ + 1) % rewardHalvingInterval_ == 0) {
            reward_ /= 2; // Halve the reward
        }
    }
} // namespace SPHINXMiner





