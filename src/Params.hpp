// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef PARAMS_HPP
#define PARAMS_HPP

#include <stdexcept>
#include <fstream>
#include <array>
#include <iostream>
#include <string>
#include <vector>

namespace SPHINXParams {
    class MainParams {
    public:
        std::string networkName;
        uint32_t magicNumber;
        std::string genesisMessage;

        MainParams();

        // Getter functions to access the member variables
        int getMaxBlockSize() const;
        std::string getConsensusAlgorithm() const;
        int getDifficultyLevel() const;
        int getMaxTransactionsPerBlock() const;
        int getTargetBlockInterval() const;
        double getBlockReward() const;
        double getTransactionFee() const;
        // Add getter functions for additional member variables

        // Setter functions to modify the member variables (if needed)
        void setMaxBlockSize(int size);
        void setConsensusAlgorithm(const std::string& algorithm);
        void setDifficultyLevel(int level);
        void setMaxTransactionsPerBlock(int maxTransactions);
        void setTargetBlockInterval(int interval);
        void setBlockReward(double reward);
        void setTransactionFee(double fee);
        // Add setter functions for additional member variables

    private:
        int maxBlockSize_;
        std::string consensusAlgorithm_;
        int difficultyLevel_;
        // Add more member variables for other configurations
        int maxTransactionsPerBlock_;
        int targetBlockInterval_;
        double blockReward_;
        double transactionFee_;
        // Add more member variables for additional configurations
        int signatureKeySize_;
        int targetBlockTime_;
        int blockRewardHalvingInterval_;
        int maxTimestampAdjustment_;
        uint32_t mainNetMagicBytes_;
        uint32_t testNetMagicBytes_;
        int mainNetTargetSpacing_;
        int testNetTargetSpacing_;
        int mainNetTargetTimespan_;
        int testNetTargetTimespan_;
        int mainNetDifficultyRetargetInterval_;
        int testNetDifficultyRetargetInterval_;
        int mainNetMaxTargetDifficulty_;
        int testNetMaxTargetDifficulty_;
        int mainNetDefaultPort_;
        int testNetDefaultPort_;
        std::string bridgeAddress_;
        std::string bridgeSecret_;
        uint32_t requiredConfirmations_;
        uint32_t blockIntervalSeconds_;
        size_t maxBlockSizeBytes_;
        std::string mainNetAddressPrefix_;
        std::string testNetAddressPrefix_;
        // Add more member variables for additional configurations
    };

    // Sender username and 2FA code for authentication
    extern const std::string senderUsername;
    extern const std::string sender2FACode;

    // Define the network magic bytes for each network
    extern constexpr uint32_t MainNetMagicBytes = 0xD9B4BEF9; // Replace with the actual magic bytes for the MainNet
    extern constexpr uint32_t TestNetMagicBytes = 0x0709110B; // Replace with the actual magic bytes for the TestNet

    // Define the genesis block information for each network
    extern const std::string MainNetGenesisBlockHash; // Replace with the actual hash of the MainNet genesis block
    extern const std::string TestNetGenesisBlockHash; // Replace with the actual hash of the TestNet genesis block

    // Define the target spacing and target timespan for each network
    extern constexpr int MainNetTargetSpacing = 600; // Replace with the actual target spacing for MainNet (in seconds)
    extern constexpr int TestNetTargetSpacing = 120; // Replace with the actual target spacing for TestNet (in seconds)
    extern constexpr int MainNetTargetTimespan = 201600; // Replace with the actual target timespan for MainNet (in seconds)
    extern constexpr int TestNetTargetTimespan = 403200; // Replace with the actual target timespan for TestNet (in seconds)

    // Define the Proof of Work parameters for each network
    extern constexpr int MainNetDifficultyRetargetInterval = 2016; // Replace with the actual difficulty retarget interval for MainNet
    extern constexpr int TestNetDifficultyRetargetInterval = 2016; // Replace with the actual difficulty retarget interval for TestNet
    extern constexpr int MainNetBlockRewardHalvingInterval = 210000; // Replace with the actual block reward halving interval for MainNet
    extern constexpr int TestNetBlockRewardHalvingInterval = 210000; // Replace with the actual block reward halving interval for TestNet
    extern constexpr int MainNetMaxTargetDifficulty = 0x1e0fffff; // Replace with the actual maximum target difficulty for MainNet
    extern constexpr int TestNetMaxTargetDifficulty = 0x1e0fffff; // Replace with the actual maximum target difficulty for TestNet

    // Define the default network port number for each network
    extern constexpr int MainNetDefaultPort = 8333; // Replace with the actual default port number for MainNet
    extern constexpr int TestNetDefaultPort = 18333; // Replace with the actual default port number for TestNet

    extern std::string BRIDGE_ADDRESS;
    extern std::string BRIDGE_SECRET;
    extern constexpr uint32_t REQUIRED_CONFIRMATIONS = 6;
    extern constexpr uint32_t BLOCK_INTERVAL_SECONDS = 10;
    extern constexpr size_t MAX_BLOCK_SIZE_BYTES = 1024 * 1024; // 1 MB
    extern constexpr double TRANSACTION_FEE = 0.001; // Fee in the blockchain's native currency

    // Define the address prefixes for each network
    extern const std::string MainNetAddressPrefix; // Replace with the actual address prefix for MainNet
    extern const std::string TestNetAddressPrefix; // Replace with the actual address prefix for TestNet

    // Define the checkpoint blocks for each network
    extern const std::vector<std::string> MainNetCheckpointBlocks; // Replace with the actual checkpoint block hashes for MainNet
    extern const std::vector<std::string> TestNetCheckpointBlocks; // Replace with the actual checkpoint block hashes for TestNet

} // namespace SPHINXParams

#endif // PARAMS_HPP

