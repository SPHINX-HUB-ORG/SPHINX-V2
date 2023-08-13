// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef WALLET_HPP
#define WALLET_HPP

#pragma once

#include <iostream>
#include <vector>
#include <random>
#include <ctime>

using json = nlohmann::json;

namespace SPHINXWallet {

    struct WalletInfo {
        std::string address;
        std::string privateKey;
        std::string encryptedPassphrase;
        double balance;
        std::vector<SPHINXTrx::Transaction> transactions;
    };

    class Wallet {
    public:
        Wallet();

        void generateAccount();
        void getAccountBalance();
        void sendTransaction(const std::string& recipientAddress, double amount);
        void getTransactionHistory();
        void createToken(const std::string& tokenName, const std::string& tokenSymbol);
        void transferToken(const std::string& recipientAddress, const std::string& tokenSymbol, double amount);
        void createWallet();
        void initiateTransaction(const std::string& recipientAddress, double amount);

        std::string requestDecryption(const std::string& encryptedData);
        std::string generateSmartContractAddress(const std::string& publicKey, const std::string& contractName);
        std::string generateRandomWord(std::vector<std::string>& wordList);

    private:
        std::string generateWalletAddress();
        std::string generatePrivateKey();
        void saveWalletInfo(const std::string& walletAddress, const std::string& privateKey, const std::string& encryptedPassphrase);
        void loadWalletInfo();
        std::string serializeData(const SPHINXDb::Data& data);
        SPHINXDb::Data deserializeData(const std::string& serializedData);

        std::string encryptPassphrase(const std::string& passphrase);
        std::string decryptPassphrase(const std::string& encryptedPassphrase);
        double fetchAccountBalance(const std::string& address);
        std::vector<SPHINXTrx::Transaction> fetchTransactionHistory(const std::string& address);
        bool isValidPassphrase(const std::string& passphrase);
        bool isWalletAddressInUse(const std::string& address);
        double loadBalance();
        std::vector<SPHINXTrx::Transaction> loadTransactionHistory();
        std::string getPublicKey();

        std::string walletAddress_;
        std::string privateKey_;
        std::string encryptedPassphrase_;
        double balance_;
        std::vector<SPHINXTrx::Transaction> transactions_;
        std::string passphrase_; // Add a member variable for passphrase
        WalletInfo walletInfo_; // Add a member variable for wallet information
    };
} // namespace SPHINXWallet

#endif // WALLET_HPP
