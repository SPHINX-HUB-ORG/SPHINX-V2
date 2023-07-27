// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef POW_HPP
#define POW_HPP

#pragma once

#include <iostream>
#include <cmath>
#include <random>
#include <chrono>
#include <vector>
#include <string>
#include "Lattice_reduction.hpp"
#include "Hash.hpp"


namespace SPHINXPoW {
    // Forward declaration
    void idealLatticeReduction(std::vector<std::vector<int>>& lattice);

    // Define the polynomial f of degree n
    std::vector<int> polynomial;

    // Function declarations
    std::vector<int> selectAndDoOperation(const std::vector<int>& polynomial, int seq);
    bool meetsTarget(const std::vector<int>& polynomial, int target);
    void adjustDifficulty(double& target, double networkHashRate, bool developerMining);
    void performProofOfWork();

    // Select and perform an operation based on the sequence number
    std::vector<int> selectAndDoOperation(const std::vector<int>& polynomial, int seq) {
        std::vector<int> result;

        if (seq == 11) {
            // Perform lattice reduction on the ideal lattice
            std::vector<std::vector<int>> idealLattice(polynomial.size());
            for (int i = 0; i < polynomial.size(); i++) {
                idealLattice[i].push_back(polynomial[i]);
            }

            idealLatticeReduction(idealLattice);

            for (int i = 0; i < idealLattice.size(); i++) {
                result.push_back(idealLattice[i][0]);
            }
        } else {
            // Handle other functions or operations specific to the ideal lattice
            // ...
        }

        return result;
    }

    // Check if the polynomial meets the target
    bool meetsTarget(const std::vector<int>& polynomial, int target) {
        std::string polynomialString;
        for (int i = 0; i < polynomial.size(); i++) {
            polynomialString += std::to_string(polynomial[i]);
        }

        int leadingZeros = 0;
        while (polynomialString[leadingZeros] == '0') {
            leadingZeros++;
        }

        return leadingZeros >= target;
    }

    // Adjust the difficulty target based on the network hash rate and mining status
    void adjustDifficulty(double& target, double networkHashRate, bool developerMining) {
        const double desiredHashRate = 2000000.0;  // Desired network hash rate
        const double adjustmentFactor = desiredHashRate / networkHashRate;  // Calculate adjustment factor based on the ratio of desired hash rate to network hash rate

        target *= adjustmentFactor;  // Increase the target difficulty by multiplying it with the adjustment factor

        if (developerMining) {
            target *= 0.5;  // Reduce the target difficulty by half if developers are mining
        } else {
            target /= adjustmentFactor;  // Decrease the target difficulty by dividing it by the adjustment factor
        }
    }

    // Perform the proof of work algorithm
    void performProofOfWork() {
        // Constants and variables initialization
        const int64_t iterations = 1000000;  // Adjust the number of iterations per nonce
        const int64_t nonces = 300;  // Total number of nonces
        std::string hash = "Your message";  // Initial hash

        std::random_device rd;  // Random device for generating random numbers
        std::mt19937 gen(rd());  // Mersenne Twister pseudo-random generator
        std::uniform_int_distribution<> dist(1, nonces);  // Uniform distribution for nonces

        double target = 1e18;  // Initial target difficulty

        const double networkHashRate = 2000000.0;  // Current network hash rate
        const double desiredHashRate = 2000000.0;  // Desired network hash rate

        const int64_t totalBlocks = 50000000;  // Total number of blocks to mine
        const int64_t developerBlocks = totalBlocks * 0.3;  // Number of blocks reserved for developers

        int64_t minedBlocks = 0;  // Number of mined blocks
        int64_t developerMinedBlocks = 0;  // Number of blocks mined by developers

        bool developerMining = true;  // Flag indicating if developers are mining

        // Loop over each nonce
        for (int64_t nonce = 1; nonce < nonces; nonce++) {
            hash += std::to_string(nonce);  // Update the hash with the nonce
            std::string finalHash = SPHINXHash::sha3_256(hash);  // Compute the final hash

            std::vector<int> polynomial(polynomial.size());  // Initialize the polynomial

            std::cout << "Current algorithm's function sequence:" << std::endl;
            for (int i = 0; i < polynomial.size(); i++) {
                std::cout << polynomial[i] << " ";
            }
            std::cout << std::endl;

            auto startTime = std::chrono::steady_clock::now();  // Start the timer for nonce processing

            // Perform proof of work iterations
            for (int64_t i = 1; i < iterations; i++) {
                for (int seq = 0; seq < polynomial.size(); seq++) {
                    // Select and perform an operation based on the sequence number

                    // Check if developers are mining and the developer-mined block count is less than the developer block limit
                    if (developerMining && developerMinedBlocks < developerBlocks) {
                        polynomial = selectAndDoOperation(polynomial, polynomial[seq]);  // Select and perform an operation on the polynomial

                        // Check if the resulting polynomial meets the target difficulty
                        if (meetsTarget(polynomial, target)) {
                            minedBlocks++;  // Increment the total mined blocks count
                            developerMinedBlocks++;  // Increment the developer-mined blocks count
                            developerMining = false;  // Set developer mining status to false
                            std::cout << "Mined block #" << minedBlocks << " (Developer Mined)" << std::endl;  // Print a message indicating a mined block by a developer
                            break;  // Exit the loop
                        }
                    }
                    // If developers are not mining or the developer block limit has been reached
                    else {
                        polynomial = selectAndDoOperation(polynomial, polynomial[seq]);  // Select and perform an operation on the polynomial

                        // Check if the resulting polynomial meets the target difficulty
                        if (meetsTarget(polynomial, target)) {
                            minedBlocks++;  // Increment the total mined blocks count
                            std::cout << "Mined block #" << minedBlocks << std::endl;  // Print a message indicating a mined block
                            break;  // Exit the loop
                        }
                    }
                }

                auto endTime = std::chrono::steady_clock::now();  // Stop the timer for nonce processing
                auto elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();  // Calculate the elapsed time

                // Calculate the energy consumption based on the elapsed time and desired hash rate
                double energyConsumption = (elapsedTime / 1000.0) * (desiredHashRate / 1000000.0);

                std::cout << "Nonce: " << nonce << ", Elapsed Time: " << elapsedTime << " ms, Energy Consumption: " << energyConsumption << " kWh" << std::endl;

                // Check if the total mined blocks count has reached the total block limit
                if (minedBlocks >= totalBlocks) {
                    break;  // Exit the loop if the block limit has been reached
                }
            }

            std::cout << "Elapsed time for nonce " << nonce << ": " << elapsedTime << " ms" << std::endl;  // Print the elapsed time for the current nonce
            std::cout << "----------------------------------------" << std::endl;

            // Check if the total mined blocks count has reached the total block limit
            if (minedBlocks >= totalBlocks) {
                break;  // Exit the outer loop if the block limit has been reached
            }

            // Check if developers are mining and the developer block limit has been reached
            if (developerMining && developerMinedBlocks >= developerBlocks) {
                developerMining = false;  // Set developer mining status to false
                std::cout << "Developer mining phase ends." << std::endl;  // Print a message indicating the end of the developer mining phase
            }

            // Check if the current nonce is a multiple of 10
            if (nonce % 10 == 0) {
                adjustDifficulty(target, networkHashRate, developerMining);  // Adjust the difficulty based on network hash rate
                std::cout << "Difficulty adjusted. New target: " << target << std::endl;  // Print the new difficulty target
            }
        }

        std::cout << "Total mined blocks: " << minedBlocks << std::endl;
    }
}  // namespace SPHINXPoW


#endif // POW_HPP

