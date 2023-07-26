// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.



#ifndef MINER_HPP
#define MINER_HPP

#include <string>
#include "Block.hpp"

namespace SPHINXMiner {

    class Miner {
    public:
        Miner();
        Block mineBlock(const std::string& previousHash, const std::string& rewardAddress);
        void performMining();

    private:
        int difficulty_;
        int rewardHalvingInterval_;
        int reward_;

        std::string calculateProofOfWork(const std::string& blockData, int difficulty);
        void updateReward();
    };

} // namespace SPHINXMiner

#endif // MINER_HPP


