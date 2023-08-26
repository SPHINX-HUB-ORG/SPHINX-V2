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
        // Constructor to initialize SPX object with name and owner
        SPX(const std::string& name, const std::string& owner)
            : name(name), owner(owner) {}

        // Get the ID of the SPX asset
        std::string getId() const;

        // Get the name of the SPX asset
        std::string getName() const;

        // Get the owner of the SPX asset
        std::string getOwner() const;

        // Set the owner of the SPX asset to a new owner
        void setOwner(const std::string& newOwner);

        // Simulate buying the SPX asset by changing ownership
        void buy(const std::string& buyer);

    private:
        std::string id;      // ID of the SPX asset
        std::string name;    // Name of the SPX asset
        std::string owner;   // Owner of the SPX asset
    };

    class AssetManager {
    public:
        AssetManager();

        void buySPX(const std::string& assetId, const std::string& buyer, const std::string& payer);

        void issueSPX(const std::string& assetName, const std::string& owner, const std::string& payer);

        void distributeRewards();

        void mineBlock();

        void setOwner(const std::string& assetId, const std::string& newOwner, const std::string& payer);

        void transferSPX(const std::string& assetId, const std::string& newOwner, const std::string& payer);

    private:
        std::string generateUniqueId();

        void payTransactionFee(const std::string& payer);

        SPX* findAsset(const std::string& assetId);

        void distributeDeveloperRewards();

        void distributeMinerRewards();

        void halveBlockReward();

        std::string generateTransactionId();

        std::string generateTransactionData();

        int currentSupply; // Current total supply
        int currentBlockHeight; // Current block height
        bool developerMining; // Flag indicating developer mining phase

        const int BLOCKS_PER_MONTH; // Number of blocks per month
        const int INITIAL_DEVELOPER_MINING_REWARD; // Initial reward per block during developer mining phase
        const int HALVING_START_BLOCK; // Block height to start halving rewards
        const int HALVING_PERIOD; // Blocks per halving period

        const std::vector<int> HALVING_SCHEDULE; // Halving reward schedule
    };

} // namespace SPHINXAsset

#endif // SPHINX_ASSET_HPP
