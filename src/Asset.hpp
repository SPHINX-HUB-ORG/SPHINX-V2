// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef ASSET_HPP
#define ASSET_HPP

#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <limits>
#include <algorithm>
#include <unordered_map>

#include "Key.hpp"
#include "Asset.hpp"
#include "Miner.hpp"
#include "PoW.hpp"
#include "Transaction.hpp"


namespace SPHINXAsset {

    class SPX {
    public:
        SPX(const std::string& name, const std::string& owner)
            : name(name), owner(owner) {}

        std::string getId() const;
        std::string getName() const;
        std::string getOwner() const;
        void setOwner(const std::string& newOwner);
        void buy(const std::string& buyer);

    private:
        std::string id;
        std::string name;
        std::string owner;
    };

    class AssetManager {
    public:
        AssetManager();
        void buySPX(const std::string& assetId, const std::string& buyer, const std::string& payer);
        void issueSPX(const std::string& assetName, const std::string& owner, const std::string& payer);
        void setOwner(const std::string& assetId, const std::string& newOwner, const std::string& payer);
        void transferSPX(const std::string& assetId, const std::string& newOwner, const std::string& payer);

    private:
        std::string generateUniqueId();
        void payTransactionFee(const std::string& payer);
        SPX* findAsset(const std::string& assetId);
        void halveBlockReward();
        std::string generateTransactionId();
        std::string generateTransactionData();

        std::vector<SPX> assets;
        int totalSupply = 0;
        const int maxSupply = 50000000;
        const int halvingThreshold = 210000;
        int blockReward = 50;
        SPHINXDb::Db db;
    };

    std::string SPX::getId() const {
        return id;
    }

    std::string SPX::getName() const {
        return name;
    }

    std::string SPX::getOwner() const {
        return owner;
    }

    void SPX::setOwner(const std::string& newOwner) {
        owner = newOwner;
    }

    void SPX::buy(const std::string& buyer) {
        setOwner(buyer);
    }

    AssetManager::AssetManager() {
        // Initialize the blockchain data and database
    }

    void AssetManager::buySPX(const std::string& assetId, const std::string& buyer, const std::string& payer) {
        SPX* asset = findAsset(assetId);
        if (asset == nullptr) {
            return;
        }
        asset->buy(buyer);
        db.storeTransaction(generateTransactionId(), generateTransactionData());
        payTransactionFee(payer);
    }

    void AssetManager::issueSPX(const std::string& assetName, const std::string& owner, const std::string& payer) {
        if (totalSupply < maxSupply) {
            if (developerMining) {
                int issuanceAmount = 100;
                int remainingSupplyForDevelopers = static_cast<int>(developerAllocationThreshold * maxSupply) - developersMinedSupply;
                int maxSupplyToBeMined = std::min(remainingSupplyForDevelopers, issuanceAmount);
                std::cout << "Mining started..." << std::endl;
                std::string minedHash = SPHINXPoW::performMining(requiredLeadingZeros);
                for (int64_t nonce = 1; nonce < std::numeric_limits<int64_t>::max(); nonce++) {
                    std::string hash = assetName + owner + payer + std::to_string(nonce) + minedHash;
                    double k = SPHINXPoW::select_and_do_operation(hash, nonce);
                    if (SPHINXPoW::meets_target(k, target)) {
                        SPX newAsset(assetName, owner);
                        assets.push_back(newAsset);
                        totalSupply++;
                        developersMinedSupply += maxSupplyToBeMined;
                        if (developersMinedSupply >= developerAllocationThreshold * maxSupply) {
                            developerMining = false;
                        }
                        if (totalSupply == halvingThreshold) {
                            halveBlockReward();
                        }
                        db.storeTransaction(generateTransactionId(), generateTransactionData());
                        payTransactionFee(payer);
                        break;
                    }
                }
            }
        }
    }

    void AssetManager::setOwner(const std::string& assetId, const std::string& newOwner, const std::string& payer) {
        SPX* asset = findAsset(assetId);
        if (asset == nullptr) {
            return;
        }
        asset->setOwner(newOwner);
        db.storeTransaction(generateTransactionId(), generateTransactionData());
        payTransactionFee(payer);
    }

    void AssetManager::transferSPX(const std::string& assetId, const std::string& newOwner, const std::string& payer) {
        SPX* asset = findAsset(assetId);
        if (asset == nullptr) {
            return;
        }
        asset->setOwner(newOwner);
        db.storeTransaction(generateTransactionId(), generateTransactionData());
        payTransactionFee(payer);
    }

    std::string AssetManager::generateUniqueId() {
        SPHINXKey::HybridKeypair hybridKeyPair = SPHINXKey::generateKeyPair();
        std::string publicKey = hybridKeyPair.merged_key.x25519_key.public_key;
        std::string uniqueId = SPHINXKey::generateAddress(publicKey);
        return uniqueId;
    }

    void AssetManager::payTransactionFee(const std::string& payer) {
        std::cout << "Transaction fee paid by: " << payer << std::endl;
    }

    SPX* AssetManager::findAsset(const std::string& assetId) {
        for (auto& asset : assets) {
            if (asset.getId() == assetId) {
                return &asset;
            }
        }
        return nullptr;
    }

    void AssetManager::halveBlockReward() {
        blockReward /= 2;
    }

    std::string AssetManager::generateTransactionId() {
        SPHINXKey::HybridKeypair hybridKeyPair = SPHINXKey::generateKeyPair();
        std::string publicKey = hybridKeyPair.merged_key.x25519_key.public_key;
        std::string transactionId = SPHINXKey::generateAddress(publicKey);
        return transactionId;
    }

    std::string AssetManager::generateTransactionData() {
        SPHINXTrx::Transaction transaction;
        transaction.addInput("Input 1");
        transaction.addInput("Input 2");
        transaction.addOutput("Output 1");
        transaction.addOutput("Output 2");
        std::string jsonData = transaction.serializeToJson();
        auto keypair = SPHINXSign::generate_keypair();
        const uint8_t* privateKey = keypair.first.data();
        const uint8_t* publicKey = keypair.second.data();
        std::string signature = SPHINXSign::sign_data(std::vector<uint8_t>(jsonData.begin(), jsonData.end()), privateKey, publicKey);
        bool isSignatureValid = SPHINXUtils::verifySignature(transaction);
        bool areFundsAvailable = SPHINXUtils::checkFundsAvailability(transaction);
        std::cout << "Transaction signed with private key: " << privateKey << std::endl;
        std::cout << "Signature: " << signature << std::endl;
        std::cout << "Signature Validity: " << (isSignatureValid ? "Valid" : "Invalid") << std::endl;
        std::cout << "Funds Availability: " << (areFundsAvailable ? "Available" : "Not Available") << std::endl;
        return jsonData;
    }
} // namespace SPHINXAsset

#endif // ASSET_HPP