// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.



#ifndef NODE_HPP
#define NODE_HPP

#pragma once

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

#include "json.hh"
#include "Node.hpp"
#include "Utils.hpp"
#include "Consensus/Consensus.hpp"

using json = nlohmann::json;

namespace SPHINXNode {

    class SPHINXNodes {
    public:
        SPHINXNodes();

        void handleTransactionRequest(const Transaction& transaction);

        void receiveTransaction(const std::string& transaction);

        void verifyTransactions();

        void performProofOfWork();

        // New function for cross-chain communication
        void handleCrossChainCommunication(const std::string& message);

        // Function to get the latest SPHINXChain from the network and find the longest one
        json getSPHINXChainFromNodes(const std::vector<int>& listOfNodes);

        // Function to send the new SPHINX_Chain to the network
        void sendNewSPHINXChain(const std::vector<int>& listOfNodes, const std::string& json);

    private:
        std::vector<std::string> mempool;
        SPHINXConsensus::Consensus consensus; // Add the Consensus class instance
        SPHINXCommon::Common common; // Add the Common class instance
    };

} // namespace SPHINXNode

#endif // SPHINX_NODES_HPP


