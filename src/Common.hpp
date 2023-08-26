// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef COMMON_HPP
#define COMMON_HPP

#include <vector>
#include <string>
#include "Transaction.hpp"
#include "Utils.hpp" // Include the header file for the Utils namespace
#include "Node.hpp"
#include "Mempool.hpp"


class Common {
public:
    Common();

    void broadcastTransaction(const Transaction& transaction); // Modify the parameter type to "Transaction"

    // Other member functions...

private:
    SPHINXMempool::Mempool mempool(common); // Instantiate the SPHINXMempool object
    std::vector<std::string> SPHINXNodes; // Instantiate the SPHINXNodes vector
    std::vector<Transaction> SPHINXMempool; // Instantiate the SPHINXMempool vector

    // Private member functions...
};

#endif // COMMON_HPP
