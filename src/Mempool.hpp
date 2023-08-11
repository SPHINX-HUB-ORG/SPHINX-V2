// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINX_MEMPOOL_HPP
#define SPHINX_MEMPOOL_HPP

#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include "json.hpp"

namespace SPHINXTrx {

    enum class TransactionType {
        ASSET_CREATION,
        MINTING,
        BURNING,
        TRANSFER,
        MEMBER_ADDITION,
        MEMBER_REMOVAL
    };

    class Transaction {
        // Define Transaction class members and methods...
    };

    class AssetCreationTransaction : public Transaction {
        // Define AssetCreationTransaction class members and methods...
    };

    class MintingTransaction : public Transaction {
        // Define MintingTransaction class members and methods...
    };

    // Define other transaction classes...

} // namespace SPHINXTrx

namespace SPHINXCommon {

    class Common {
    public:
        void processMempool(const SPHINXTrx::Transaction& transaction) {
            // Implement mempool processing logic...
        }
    };

} // namespace SPHINXCommon

namespace SPHINXNode {

    void processTransaction(const std::string& node, const std::string& transactionData) {
        // Implement node transaction processing logic...
    }

} // namespace SPHINXNode

namespace SPHINXMempool {

    using namespace SPHINXTrx;
    using json = nlohmann::json;

    class SPHINXMempool {
    private:
        SPHINXCommon::Common& common;

    public:
        SPHINXMempool(SPHINXCommon::Common& commonRef) : common(commonRef) {
            // Constructor implementation...
        }

        // Rest of the class implementation...

    };

} // namespace SPHINXMempool

#endif // SPHINX_MEMPOOL_HPP
