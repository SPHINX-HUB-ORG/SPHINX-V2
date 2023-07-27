// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef CONSENSUS_HPP
#define CONSENSUS_HPP

#pragma once

#include <iostream>
#include <vector>
#include <Transaction.hpp>
#include <Utils.hpp>
#include "Contract.hpp"


namespace SPHINXConsensus {

    class Consensus {
    public:
        Consensus();

        void addVerifiedTransaction(const SPHINXContract::Transaction& transaction);

        void validateAndAddTransaction(const SPHINXContract::Transaction& transaction);

        // Implement other consensus-related functions...

    private:
        std::vector<SPHINXContract::Transaction> verifiedTransactions;

        // Add other member variables and functions...
    };

} // namespace SPHINXConsensus


#endif /* CONSENSUS_HPP */

