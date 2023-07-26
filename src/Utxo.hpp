// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef UTXO_HPP
#define UTXO_HPP

#include <string>
#include <map>
#include <vector>

namespace SPHINXUtxo {

    // Define UTXO data structure
    struct UTXO {
        std::string txOutputId;
        int index;
        double amount;
        std::string recipientAddress;
        // Add other relevant fields
    };

    // UTXO Update Functions
    void updateUTXOSet(const SPHINXBlock::Block& block, std::map<std::string, UTXO>& utxoSet);
    void updateUTXOSet(const SPHINXTrx::Transaction& transaction, std::map<std::string, UTXO>& utxoSet);

    // UTXO Validation Function
    bool validateTransaction(const SPHINXTrx::Transaction& transaction, const std::map<std::string, UTXO>& utxoSet);

    // UTXO Retrieval Functions
    std::vector<UTXO> findUTXOsForAddress(const std::string& address, const std::map<std::string, UTXO>& utxoSet);
    UTXO getUTXO(const std::string& utxoId, const std::map<std::string, UTXO>& utxoSet);
    double getTotalUTXOAmount(const std::map<std::string, UTXO>& utxoSet);

} // namespace SPHINXUtxo

#endif // UTXO_HPP
