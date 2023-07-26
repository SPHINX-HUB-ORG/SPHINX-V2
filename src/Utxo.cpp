// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <string>
#include <map>
#include <vector>
#include "utxo.hpp"
#include "transaction.hpp"
#include "block.hpp"
#include "db.hpp"

namespace SPHINXUtxo {

    // Define UTXO data structure
    struct UTXO {
        std::string txOutputId;
        int index;
        double amount;
        std::string recipientAddress;
        // Add other relevant fields
    };

    // Assume we have a data structure to keep track of spent UTXOs
    std::unordered_set<std::string> spentUTXOs;

    bool isUTXOSpent(const UTXO& utxo) {
        // Check if the UTXO is in the set of spent UTXOs
        return spentUTXOs.find(utxo.txOutputId + std::to_string(utxo.index)) != spentUTXOs.end();
    }
    
    bool checkFundsAvailability(const std::string& transactionData) {
        // Deserialize the transactionData JSON and extract the senderAddress and UTXOs
        // Get the UTXOs for the senderAddress from the UTXO set

        for (const auto& utxo : senderUTXOs) {
            if (isUTXOSpent(utxo)) {
                return false; // Funds not available if any UTXO is already spent
            }
        }

        return true; // Funds available if all UTXOs are not spent
    }

    void updateUTXOSet(const SPHINXBlock::Block& block, std::map<std::string, UTXO>& utxoSet) {
        // Iterate through all transactions in the block
        for (const std::string& transactionId : block.getTransactions()) {
            // Load the transaction from the database using SPHINXDb
            SPHINXTrx::Transaction transaction = SPHINXDb::loadTransactionFromDatabase(transactionId);

            // Iterate through all transaction inputs
            for (const SPHINXTrx::Input& input : transaction.getInputs()) {
                // Find the UTXO corresponding to the input and remove it from the UTXO set
                std::string utxoId = input.getUTXOId();
                utxoSet.erase(utxoId);
            }

            // Iterate through all transaction outputs
            for (int i = 0; i < transaction.getOutputs().size(); ++i) {
                const SPHINXTrx::Output& output = transaction.getOutputs()[i];
                // Create a new UTXO and add it to the UTXO set
                UTXO utxo;
                utxo.txOutputId = transaction.getId();
                utxo.index = i;
                utxo.amount = output.getAmount();
                utxo.recipientAddress = output.getRecipientAddress();
                // Add other relevant fields

                // Generate a unique identifier for the UTXO (you may concatenate txOutputId and index)
                std::string utxoId = utxo.txOutputId + std::to_string(utxo.index);

                // Add the UTXO to the UTXO set
                utxoSet[utxoId] = utxo;
            }
        }
    }

    // Additional function to update UTXO set based on individual transaction
    void updateUTXOSet(const SPHINXTrx::Transaction& transaction, std::map<std::string, UTXO>& utxoSet) {
        // Iterate through all transaction inputs
        for (const SPHINXTrx::Input& input : transaction.getInputs()) {
            // Find the UTXO corresponding to the input and remove it from the UTXO set
            std::string utxoId = input.getUTXOId();
            utxoSet.erase(utxoId);
        }

        // Iterate through all transaction outputs
        for (int i = 0; i < transaction.getOutputs().size(); ++i) {
            const SPHINXTrx::Output& output = transaction.getOutputs()[i];
            // Create a new UTXO and add it to the UTXO set
            UTXO utxo;
            utxo.txOutputId = transaction.getId();
            utxo.index = i;
            utxo.amount = output.getAmount();
            utxo.recipientAddress = output.getRecipientAddress();
            // Add other relevant fields

            // Generate a unique identifier for the UTXO (you may concatenate txOutputId and index)
            std::string utxoId = utxo.txOutputId + std::to_string(utxo.index);

            // Add the UTXO to the UTXO set
            utxoSet[utxoId] = utxo;
        }
    }

    // UTXO Validation Function
    // Validate a transaction
    bool validateTransaction(const SPHINXTrx::Transaction& transaction, const std::map<std::string, UTXO>& utxoSet) {
        double inputTotal = 0.0;
        double outputTotal = 0.0;

        for (const SPHINXTrx::Input& input : transaction.getInputs()) {
            std::string utxoId = input.getUTXOId();
            auto utxoIt = utxoSet.find(utxoId);
            if (utxoIt == utxoSet.end()) {
                // The input UTXO doesn't exist
                return false;
            }
            inputTotal += utxoIt->second.amount;
        }

        for (const SPHINXTrx::Output& output : transaction.getOutputs()) {
            outputTotal += output.getAmount();
        }

        return inputTotal >= outputTotal;
    }

    // UTXO Retrieval Functions
    // Find all UTXOs for a given address
    std::vector<UTXO> findUTXOsForAddress(const std::string& address, const std::map<std::string, UTXO>& utxoSet) {
        std::vector<UTXO> utxosForAddress;
        for (const auto& entry : utxoSet) {
            const UTXO& utxo = entry.second;
            if (utxo.recipientAddress == address) {
                utxosForAddress.push_back(utxo);
            }
        }
        return utxosForAddress;
    }

    // Get UTXO by its ID
    UTXO getUTXO(const std::string& utxoId, const std::map<std::string, UTXO>& utxoSet) {
        auto it = utxoSet.find(utxoId);
        if (it != utxoSet.end()) {
            return it->second;
        } else {
            // Handle case when UTXO with the given ID does not exist
            throw std::runtime_error("UTXO not found");
        }
    }

    // Get total amount of UTXOs in the UTXO set
    double getTotalUTXOAmount(const std::map<std::string, UTXO>& utxoSet) {
        double totalAmount = 0.0;
        for (const auto& entry : utxoSet) {
            const UTXO& utxo = entry.second;
            totalAmount += utxo.amount;
        }
        return totalAmount;
    }
} // namespace SPHINXUtxo

