// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


/////////////////////////////////////////////////////////////////////////////////////////////////////////
// The code provided implements the Proof-of-Work (PoW) algorithm using the SPHINX mining algorithm. The goal of PoW is to find a nonce value that, when combined with the data, produces a hash value that meets a certain difficulty target. The difficulty is determined by the number of leading zeros required in the hash.

// The code is divided into two namespaces: SPHINXMiningAlgorithm and SPHINXPoW.

// The SPHINXMiningAlgorithm namespace contains functions related to the SPHINX mining algorithm. It includes the calculateHash function, which takes a message and the required number of leading zeros as input and returns the hash value.

// The meetsDifficultyTarget function checks if a given hash value meets the required difficulty target. It iterates over the first requiredLeadingZeros characters of the hash and checks if they are all zero. If any character is not zero, it returns false, indicating that the hash does not meet the difficulty target.

// The calculateHash function generates the hash by iterating over nonce values until a hash is found that meets the difficulty target. It starts with a nonce value of 0 and appends it to the message. It then calculates the hash using the SPHINX hash function SPHINXHash::SPHINX_256. If the generated hash meets the difficulty target, the function breaks out of the loop and returns the hash.

// The SPHINXPoW namespace contains functions specific to the PoW algorithm using the SPHINX mining algorithm.

// The solveNonce function takes the data and the desired difficulty as input and returns the nonce value that produces a hash meeting the difficulty target. It initializes the nonce and hash variables, and then creates an instance of the Miner class from SPHINXMiner. It iterates over nonce values, appending them to the data, and uses the mineBlock function from the Miner class to mine a block. The hash of the mined block is obtained, and if it meets the difficulty target, the loop is exited, and the hash is returned.

// The meetsDifficultyTarget function in the SPHINXPoW namespace is the same as the one in the SPHINXMiningAlgorithm namespace. It checks if a given hash meets the required difficulty target by comparing the first difficulty characters of the hash with the target value.

// The adjustDifficulty function adjusts the difficulty target based on the network hash rate and the developer mining flag. It calculates the expected number of blocks per day based on the average block time, adjusts the target blocks per day for developer mining, and calculates the network target hash rate. It then adjusts the difficulty target by reducing it by an adjustment factor, scaling it based on the ratio of the target hash rate to the network target hash rate, and increasing it back by the adjustment factor.

// This code implements a mining algorithm that involves calculating hash values, adjusting the difficulty, and performing mathematical operations on random values until a valid hash meeting the target is found. It also incorporates specific scenarios related to developer mining and timeout duration.
/////////////////////////////////////////////////////////////////////////////////////////////////////////



#ifndef POW_HPP
#define POW_HPP

#pragma once

#include <cmath>
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <cstdint>
#include <iomanip>
#include "Hash.hpp"
#include "Block.hpp"
#include "Miner.hpp"



namespace SPHINXMiningAlgorithm {
    std::string calculateHash(const std::string& message, int requiredLeadingZeros);

    // Custom function to check if the hash meets the difficulty target
    bool meetsDifficultyTarget(const std::string& hash, int requiredLeadingZeros) {
        // Check if the hash has the required number of leading zeros
        for (int i = 0; i < requiredLeadingZeros; i++) {
            if (hash[i] != '0') {
                return false;
            }
        }
        return true;
    }

    std::string calculateHash(const std::string& message, int requiredLeadingZeros) {
        std::string nonce;
        std::string concatenatedMessage;
        std::string hash;

        // Start iterating through nonce values until a desired condition is met
        for (int i = 0;; i++) {
            nonce = std::to_string(i); // Convert the iteration count to a string nonce value
            concatenatedMessage = message + nonce;
            hash = SPHINXHash::SPHINX_256(concatenatedMessage);

            // Check if the hash meets the difficulty target
            if (meetsDifficultyTarget(hash, requiredLeadingZeros)) {
                break; // Exit the loop when the condition is met
            }
        }

        return hash;
    }
} // namespace SPHINXMiningAlgorithm

namespace SPHINXPoW {
    std::string solveNonce(const std::string& data, int difficulty) {
    std::string nonce;
    std::string hash;

    Miner miner; // Create an instance of the Miner class from SPHINXMiner

    // Start iterating through nonce values until a desired condition is met
        for (int i = 0;; i++) {
            nonce = std::to_string(i); // Convert the iteration count to a string nonce value
            std::string dataWithNonce = data + nonce;

            // Call the mineBlock function from the Miner class to mine a block
            Block minedBlock = miner.mineBlock(dataWithNonce, rewardAddress); // Modify the parameters as needed

            // Get the hash of the mined block
            hash = minedBlock.getHash();

            // Check if the hash meets the difficulty target
            if (meetsDifficultyTarget(hash, difficulty)) {
                break; // Exit the loop when the condition is met
            }
        }

        return hash;
    }

    // Removed redundant namespace
    bool meetsDifficultyTarget(const std::string& hash, int difficulty) {
        // Convert the required leading zeros to an integer value
        int targetValue = 0;
        for (int i = 0; i < difficulty; i++) {
            targetValue = (targetValue * 16) + 0;
        }

        // Convert the hash substring to an integer value
        int hashValue = std::stoi(hash.substr(0, difficulty), 0, 16);

        // Check if the hash value meets the target value
        return hashValue <= targetValue;
    }

    void adjustDifficulty(double& target, double networkHashRate, bool developerMining) {
        // Calculate the expected number of blocks per day
        double averageBlockTime = 600.0; // Average block time in seconds (changed to double)
        double expectedBlocksPerDay = 24.0 * 60.0 * 60.0 / averageBlockTime; // Corrected calculation
        double targetBlocksPerDay = expectedBlocksPerDay;

        // Increase target blocks per day for developer mining
        if (developerMining) {
            targetBlocksPerDay *= 10.0;
        }

        // Calculate the network target hash rate
        double networkTargetHashRate = networkHashRate / targetBlocksPerDay;

        double adjustmentFactor = 2.0; // Adjust difficulty by a factor of 2

        // Reduce the target by the adjustment factor
        target /= adjustmentFactor;

        if (networkTargetHashRate > 0) {
            // Adjust the target based on the ratio of target hash rate to network target hash rate
            double ratio = target / networkHashRate;
            target *= ratio;
        }

        // Increase the target by the adjustment factor
        target *= adjustmentFactor;
    }

    void performMining();
        // Function definitions
        // Function to multiply upper and lower digits of a number
        inline double multiply(double k) {
            double upper_digits = std::floor(k / 1e16);
            double lower_digits = k - upper_digits * 1e16;
            if (lower_digits == 0 || upper_digits == 0) {
                return k;
            } else {
                return upper_digits * lower_digits;
            }
        }
    }

    // Function to extract 32 digits from a number
    inline double extract_32_digits(double k) {
        int n;
        double intpart;
        k = std::frexp(k, &n);
        k = std::modf(100 * k, &intpart);
        k = static_cast<int64_t>(k * 1e32);
        for (int i = 1; i < 34; i++) {
            if (k < 1e31) {
                k *= 10;
            }
        }
        return k;
    }

    // Function to select and perform mathematical operations based on a sequence number
    inline double select_and_do_operation(double k, int seq) {
        if (seq == 1) {
            k = 1 / k; // Division
        } else if (seq == 2) {
            k = (k * 10) / 1e32 + 0.01; // Multiplication, Division, and Addition
            k = std::log(k); // Natural logarithm
        } else if (seq == 3) {
            k = std::sqrt(k); // Square root
        } else if (seq == 4) {
            k = (10 * k) / 1e32; // Multiplication and Division
            k = std::exp(k); // Exponential
        } else if (seq == 5) {
            k = std::sin(k) + 1.01; // Sine function and Addition
        } else if (seq == 6) {
            k = k / 1e32; // Division
            k = std::asin(k); // Arcsine function
        } else if (seq == 7) {
            k = (10 * k) / 1e32 + 0.01; // Multiplication, Division, and Addition
            k = std::cos(k); // Cosine function
        } else if (seq == 8) {
            k = std::tan(k) + 1.01; // Tangent function and Addition
        } else if (seq == 9) {
            k = (10 * k) / 1e32; // Multiplication and Division
            k = std::atan(k); // Arctangent function
        } else if (seq == 10) {
            k = std::cosh(k) + 1.01; // Hyperbolic cosine function and Addition
        } else if (seq == 11) {
            k = std::tanh(k) + 1.01; // Hyperbolic tangent function and Addition
        } else if (seq == 12) {
            k = std::exp2(k) + 1.01; // Exponential (base 2) and Addition
        } else if (seq == 13) {
            k = std::expm1(k) + 1.01; // Exponential minus 1 and Addition
        } else if (seq == 14) {
            k = std::log10(k) + 1.01; // Base 10 logarithm and Addition
        } else if (seq == 15) {
            k = std::log1p(k) + 1.01; // Natural logarithm of (1 + x) and Addition
        } else if (seq == 16) {
            k = std::log2(k) + 1.01; // Base 2 logarithm and Addition
        } else if (seq == 17) {
            k = std::pow(2, k) + 1.01; // Power function (2 raised to the power of x) and Addition
        } else if (seq == 18) {
            k = std::sqrt(1 + k) + 1.01; // Square root and Addition
        } else if (seq == 19) {
            k = std::erf(k) + 1.01; // Error function and Addition
        } else if (seq == 20) {
            k = std::tgamma(k) + 1.01; // Gamma function and Addition
        } else if (seq == 21) {
            k = std::lgamma(k) + 1.01; // Natural logarithm of the absolute value of the gamma function and Addition
        } else {
            k = 1; // Default value
        }

        return k;
    }

    // Function to check if a number meets the target
    bool isValidHash(const std::string& hash, int requiredLeadingZeros) {
        // Check if the hash has the required number of leading zeros
        for (int i = 0; i < requiredLeadingZeros; i++) {
            if (hash[i] != '0') {
                return false;
            }
        }
        return true;
    }

    // Function to adjust the difficulty based on the network hash rate and developer mining flag
    void adjustDifficulty(double& target, double networkHashRate, bool developerMining) {
    // Calculate the expected number of blocks per day
        double averageBlockTime = 600; // Average block time in seconds
        double expectedBlocksPerDay = 24 * 60 * 60 / averageBlockTime;
        double targetBlocksPerDay = expectedBlocksPerDay;

        // Increase target blocks per day for developer mining
        if (developerMining) {
            targetBlocksPerDay *= 10;
        }

        // Calculate the network target hash rate
        double networkTargetHashRate = networkHashRate / targetBlocksPerDay;

        double adjustmentFactor = 2; // Adjust difficulty by a factor of 2

        // Reduce the target by the adjustment factor
        target /= adjustmentFactor;

        if (networkTargetHashRate > 0) {
            // Adjust the target based on the ratio of target hash rate to network target hash rate
            double ratio = target / networkTargetHashRate;
            target *= ratio;
        }

        // Increase the target by the adjustment factor
        target *= adjustmentFactor;
    }

// Function to perform the mining algorithm
void performMining() {
    // Define timeout duration (e.g., 10 minutes)
    const std::chrono::minutes timeoutDuration(10);
    auto startTime = std::chrono::steady_clock::now();

    double target = 1e100; // Initial target

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(1e-50, 1e50);
    double k = dis(gen); // Initialize variable k

    int seq = 1; // Initial sequence number
    double networkHashRate = 1e18; // Network hash rate
    bool developerMining = false; // Flag for developer mining

    // Scenario 1: Developer mining 30% of 50 million total assets with reduced difficulty mining by 50%
    double developerMiningPercentage = 0.3;
    double totalAssets = 50e6;
    double developerMiningAssets = developerMiningPercentage * totalAssets;
    double reducedDifficultyFactor = 0.5;

    // Calculate the number of assets for developer mining and adjust difficulty
    if (developerMining) {
        developerMiningAssets = developerMiningAssets * reducedDifficultyFactor;
        adjustDifficulty(target, networkHashRate, true);
    } else {
        adjustDifficulty(target, networkHashRate, false);
    }

    // Scenario 2: Enable probability for developer mining 30% to be done in 5 months
    int totalMonths = 5;
    double miningProbability = 1.0 / (totalMonths * 30);

    while (true) {
        k = dis(gen) * multiply(k); // Multiply k by a random value
        k = extract_32_digits(k); // Extract 32 digits from k
        k = select_and_do_operation(k, seq); // Select and perform a mathematical operation on k based on the sequence number
        seq = (seq % 21) + 1; // Increment the sequence number and wrap around to 1 if it exceeds 21
        adjustDifficulty(target, networkHashRate, developerMining); // Adjust the difficulty based on the target and network hash rate

        if (meetsDifficultyTarget(std::to_string(k), target)) { // Use meetsDifficultyTarget instead of meets_target
            // Scenario 3: Automatically switch to normal mining phase once developer mining is done
            if (developerMining && developerMiningAssets <= 0) {
                developerMining = false;
                adjustDifficulty(target, networkHashRate, false);
            }

            // Output the successful mining result
            std::cout << "Successful mining with k = " << std::fixed << std::setprecision(32) << k << std::endl;
            break;
        }

        // Scenario 4: Reduce the number of developer mining assets for each successful mining
        if (developerMining) {
            developerMiningAssets--;
        }

        // Scenario 5: Introduce a probability for developer mining to occur
        if (!developerMining && dis(gen) < miningProbability) {
            developerMining = true;
            adjustDifficulty(target, networkHashRate, true);
        }

        // Check if timeout duration has elapsed
        auto currentTime = std::chrono::steady_clock::now();
        if (currentTime - startTime >= timeoutDuration) {
            std::cout << "Mining timeout reached. No valid hash found within the specified time." << std::endl;
            return;  // Exit the function
        }
    }
} // namespace SPHINXPoW

#endif // POW_HPP