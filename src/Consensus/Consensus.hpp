/*
 *  Copyright (c) (2023) SPHINX_ORG
 *  Authors:
 *    - (C kusuma) <thekoesoemo@gmail.com>
 *      GitHub: (https://github.com/cahyaksm)
 *  Contributors:
 *    - (Contributor 1) <email1@example.com>
 *      Github: (https://github.com/yourgit)
 *    - (Contributor 2) <email2@example.com>
 *      Github: (https://github.com/yourgit)
 */



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

