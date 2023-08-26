// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef POW_HPP
#define POW_HPP

#include <cmath>
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <cstdint>
#include <iomanip>


namespace SPHINXMiningAlgorithm {
    std::string calculateHash(const std::string& message, int requiredLeadingZeros);
    bool meetsDifficultyTarget(const std::string& hash, int requiredLeadingZeros);
}

namespace SPHINXPoW {
    bool meetsDifficultyTarget(const std::string& hash, int difficulty);
    void adjustDifficulty(double& target, double networkHashRate, bool developerMining);
    void performMining();

    // Function definitions
    inline double multiply(double k);
    inline double extract_32_digits(double k);
    inline double select_and_do_operation(double k, int seq);
    bool isValidHash(const std::string& hash, int requiredLeadingZeros);
}

#endif // SPHINX_MINING_HPP
