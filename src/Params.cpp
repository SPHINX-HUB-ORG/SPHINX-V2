// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <stdexcept>
#include <fstream>
#include <array>
#include <iostream>
#include <string>
#include <vector>
#include <ctime>

#include "Params.hpp"
#include "Chain.hpp"
#include "Block.hpp"
#include "Sign.hpp"

namespace SPHINXParams {

    MainParams::MainParams()
        : networkName("SPHINXNetwork"), magicNumber(0xabcdef), genesisMessage("Welcome to Post-Quantum era, The Beginning of a Secured-Trustless Network will start from here - SPHINX Network"),
        maxBlockSize_(1024),  // Default maximum block size
        consensusAlgorithm_("PoW"),  // Default consensus algorithm
        difficultyLevel_(1),  // Default difficulty level
        maxTransactionsPerBlock_(1000),  // Default maximum transactions per block
        targetBlockInterval_(600),  // Default target block interval in seconds
        blockReward_(50.0),  // Default block reward amount
        transactionFee_(0.001)  // Default transaction fee
    {
        // You can add more initializations here based on your requirements.
        // Initialize additional member variables here
        signatureKeySize_ = 256;  // Default signature key size
        targetBlockTime_ = 600;  // Default target block time in seconds
        blockRewardHalvingInterval_ = 210000;  // Default block reward halving interval
        maxTimestampAdjustment_ = 7200;  // Default maximum timestamp adjustment in seconds
        mainNetMagicBytes_ = 0xD9B4BEF9;  // Default magic bytes for MainNet
        testNetMagicBytes_ = 0x0709110B;  // Default magic bytes for TestNet
        mainNetTargetSpacing_ = 600;  // Default target spacing for MainNet in seconds
        testNetTargetSpacing_ = 120;  // Default target spacing for TestNet in seconds
        mainNetTargetTimespan_ = 201600;  // Default target timespan for MainNet in seconds
        testNetTargetTimespan_ = 403200;  // Default target timespan for TestNet in seconds
        mainNetDifficultyRetargetInterval_ = 2016;  // Default difficulty retarget interval for MainNet
        testNetDifficultyRetargetInterval_ = 2016;  // Default difficulty retarget interval for TestNet
        mainNetMaxTargetDifficulty_ = 0x1e0fffff;  // Default maximum target difficulty for MainNet
        testNetMaxTargetDifficulty_ = 0x1e0fffff;  // Default maximum target difficulty for TestNet
        mainNetDefaultPort_ = 8333;  // Default default port number for MainNet
        testNetDefaultPort_ = 18333;  // Default default port number for TestNet
        bridgeAddress_ = "my_bridge_address";  // Default bridge address
        bridgeSecret_ = "my_bridge_secret_key";  // Default bridge secret key
        requiredConfirmations_ = 6;  // Default required confirmations
        blockIntervalSeconds_ = 10;  // Default block interval in seconds
        maxBlockSizeBytes_ = 1024 * 1024;  // Default maximum block size in bytes (1 MB)
        mainNetAddressPrefix_ = "M";  // Default address prefix for MainNet
        testNetAddressPrefix_ = "T";  // Default address prefix for TestNet
        // Add more initializations here for additional member variables
    }

    int SPHINXParams::MainParams::getMaxBlockSize() const {
        return maxBlockSize_;
    }

    std::string SPHINXParams::MainParams::getConsensusAlgorithm() const {
        return consensusAlgorithm_;
    }

    int SPHINXParams::MainParams::getDifficultyLevel() const {
        return difficultyLevel_;
    }

    void SPHINXParams::MainParams::setMaxBlockSize(int size) {
        maxBlockSize_ = size;
    }

    void SPHINXParams::MainParams::setConsensusAlgorithm(const std::string& algorithm) {
        consensusAlgorithm_ = algorithm;
    }

    void SPHINXParams::MainParams::setDifficultyLevel(int level) {
        difficultyLevel_ = level;
    }

    // Mining Difficulty
    constexpr int MiningDifficulty = 4; // Specify the desired difficulty level

    // Maximum Block Size in bytes
    constexpr uint32_t MaxBlockSizeBytes = 1024 * 1024; // 1 MB

    // Maximum Timestamp Offset in seconds
    constexpr uint32_t MaxTimestampOffset = 600; // 10 minutes

    // Difficulty Adjustment Interval (Example: Adjust difficulty every 2016 blocks)
    constexpr uint32_t DifficultyAdjustmentInterval = 2016;

    // Genesis Block Information
    const std::string GenesisBlockHash = "xxxxxxxxxxxxxxxx"; // Replace with the actual hash of the genesis block
    const std::time_t GenesisBlockTimestamp = 1234567890; // Replace with the actual timestamp of the genesis block

    // Proof-of-Work (PoW) Parameters
    constexpr uint32_t TargetBlockTime = 600; // 10 minutes (in seconds)
    // Define other PoW parameters if applicable

    // Block Verification Parameters
    constexpr int SignatureKeySize = 256; // Replace with the actual key size used for signatures

    // Block Size Limit (Maximum number of transactions in a block)
    constexpr uint32_t MaxTransactionsPerBlock = 1000;

    // Time between Blocks (Target time interval between blocks)
    constexpr uint32_t TargetBlockInterval = 600; // 10 minutes (in seconds)

    // Block Reward Halving Interval (Example: Block reward halving every 210,000 blocks)
    constexpr uint32_t BlockRewardHalvingInterval = 210000;

    // Mining Reward Parameters (Example: Block reward and transaction fee settings)
    constexpr double BlockReward = 50.0; // Replace with the actual block reward amount
    constexpr double TransactionFee = 0.001; // Fee in the blockchain's native currency

    // Signature Verification Algorithm
    const std::string SPHINXSign::SignatureAlgorithm = "SPHINXSIGN";

    // Timestamp Adjustment Rules (Example: Allow timestamp adjustment within 2 hours)
    constexpr uint32_t MaxTimestampAdjustment = 7200; // 2 hours (in seconds)

    // Sender username and 2FA code for authentication
    const std::string senderUsername = "your_username";
    const std::string sender2FACode = "your_2fa_code";

    // Define the network magic bytes for each network
    constexpr uint32_t MainNetMagicBytes = 0xD9B4BEF9; // Replace with the actual magic bytes for the MainNet
    constexpr uint32_t TestNetMagicBytes = 0x0709110B; // Replace with the actual magic bytes for the TestNet

    // Define the genesis block information for each network
    const std::string MainNetGenesisBlockHash = "xxxxxxxxxxxxxxxx"; // Replace with the actual hash of the MainNet genesis block
    const std::string TestNetGenesisBlockHash = "yyyyyyyyyyyyyyyy"; // Replace with the actual hash of the TestNet genesis block

    // Define the target spacing and target timespan for each network
    constexpr int MainNetTargetSpacing = 600; // Replace with the actual target spacing for MainNet (in seconds)
    constexpr int TestNetTargetSpacing = 120; // Replace with the actual target spacing for TestNet (in seconds)
    constexpr int MainNetTargetTimespan = 201600; // Replace with the actual target timespan for MainNet (in seconds)
    constexpr int TestNetTargetTimespan = 403200; // Replace with the actual target timespan for TestNet (in seconds)

    // Define the Proof of Work parameters for each network
    constexpr int MainNetDifficultyRetargetInterval = 2016; // Replace with the actual difficulty retarget interval for MainNet
    constexpr int TestNetDifficultyRetargetInterval = 2016; // Replace with the actual difficulty retarget interval for TestNet
    constexpr int MainNetBlockRewardHalvingInterval = 210000; // Replace with the actual block reward halving interval for MainNet
    constexpr int TestNetBlockRewardHalvingInterval = 210000; // Replace with the actual block reward halving interval for TestNet
    constexpr int MainNetMaxTargetDifficulty = 0x1e0fffff; // Replace with the actual maximum target difficulty for MainNet
    constexpr int TestNetMaxTargetDifficulty = 0x1e0fffff; // Replace with the actual maximum target difficulty for TestNet

    // Define the default network port number for each network
    constexpr int MainNetDefaultPort = 8333; // Replace with the actual default port number for MainNet
    constexpr int TestNetDefaultPort = 18333; // Replace with the actual default port number for TestNet

    std::string BRIDGE_ADDRESS = "my_bridge_address";
    std::string BRIDGE_SECRET = "my_bridge_secret_key";
    constexpr uint32_t REQUIRED_CONFIRMATIONS = 6;
    constexpr uint32_t BLOCK_INTERVAL_SECONDS = 10;
    constexpr size_t MAX_BLOCK_SIZE_BYTES = 1024 * 1024; // 1 MB
    constexpr double TRANSACTION_FEE = 0.001; // Fee in the blockchain's native currency

    // Define the address prefixes for each network
    const std::string MainNetAddressPrefix = "M"; // Replace with the actual address prefix for MainNet
    const std::string TestNetAddressPrefix = "T"; // Replace with the actual address prefix for TestNet

    // Define the checkpoint blocks for each network
    const std::vector<std::string> MainNetCheckpointBlocks = {
        "blockhash1", "blockhash2", "blockhash3" // Replace with the actual checkpoint block hashes for MainNet
    };
    const std::vector<std::string> TestNetCheckpointBlocks = {
        "blockhash1", "blockhash2", "blockhash3" // Replace with the actual checkpoint block hashes for TestNet
    };
} // namespace SPHINXParams
