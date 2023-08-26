// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINX_FEES_HPP
#define SPHINX_FEES_HPP

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>

namespace SPHINXFees {

    // Define a basic transaction structure
    struct Transaction {
        std::string from;
        std::string to;
        double amount;
        double gasPrice;
        double gasLimit;
        double energyConsumed; // New field to represent energy consumption
    };

    // Placeholder functions for blockchain state management
    extern std::unordered_map<std::string, double> balances; // Map of account balances

    // Function declarations
    double calculateTransactionFee(const Transaction& tx);
    void processTransactions(const std::vector<Transaction>& transactions);

    double getBalance(const std::string& account);
    void deductFee(const std::string& account, double amount);
    void addBalance(const std::string& account, double amount);
    bool validateSenderBalance(const std::string& sender, double amount);
    void updateBlockchainState(const Transaction& tx, double fee);

} // End of namespace SPHINXFees

#endif // SPHINX_FEES_HPP

