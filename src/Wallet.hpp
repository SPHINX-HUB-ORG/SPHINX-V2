// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef WALLET_HPP
#define WALLET_HPP

#pragma once

#include <random>
#include <string>
#include <vector>


namespace SPHINXWallet {

    struct WalletInfo {
        std::string address;
        std::string privateKey;
        std::string encryptedPassphrase;
        double balance;
        std::vector<SPHINXTrx::Transaction> transactions;
    };

    class Wallet {
    private:
        WalletInfo walletInfo_;
        std::string walletAddress_;
        std::string privateKey_;
        std::string passphrase_;

        std::string generateWalletAddress();
        std::string generatePrivateKey();
        std::string encryptPassphrase(const std::string& passphrase);
        std::string decryptPassphrase(const std::string& encryptedPassphrase);
        std::string serializeData(const SPHINXDb::Data& data);
        SPHINXDb::Data deserializeData(const std::string& serializedData);
        void saveWalletInfo(const std::string& walletAddress, const std::string& privateKey, const std::string& encryptedPassphrase);
        void loadWalletInfo();

    public:
        Wallet();
        void initiateTransaction(const std::string& recipientAddress, double amount);
        void createWallet();
        void accessWallet(const std::string& walletAddress, const std::string& passphrase);
        void signOut();
        WalletInfo getWalletInfo() const;
        bool sendTransaction(const std::string& recipient, double amount);
        double getWalletBalance();
        std::vector<SPHINXTrx::Transaction> getTransactionHistory();
        std::string getPublicKey();
        bool validateAddress(const std::string& address);
        void importWallet(const std::string& walletData);
        std::string exportWallet();
    };

} // namespace SPHINXWallet

#endif /* WALLET_HPP */


