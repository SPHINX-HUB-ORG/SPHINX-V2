// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The given code represents a Node class in the SPHINXNode namespace, which is responsible for handling transactions and verifying them 
// within a network. Here's an explanation of the code:

  // The constructor initializes a Node object. The specific implementation details are not provided in the given code snippet.
  // The handleTransactionRequest function handles incoming transaction requests. It takes a Transaction object as input and broadcasts 
  // the transaction using the broadcastTransaction function from the common namespace. The specific implementation details of the 
  // broadcastTransaction function are not provided in the given code snippet.
  // The receiveTransaction function is responsible for receiving a transaction and adding it to the mempool container. The transactions 
  // are stored as strings in the mempool vector.
  // The verifyTransactions function iterates over the transactions in the mempool vector and verifies each transaction using various 
  // utility functions from the Utils namespace. The provided utility functions verifySignature, checkFundsAvailability, and 
  // adhereToNetworkRules are called to perform signature verification, check fund availability, and ensure adherence to network rules, 
  // respectively.
  // If a transaction passes all the verification checks, it is added to the consensus object using the addVerifiedTransaction function. 
  // The specific implementation details of the addVerifiedTransaction function and the consensus algorithm are not provided in the 
  // given code snippet.
  // Other node-related functions are expected to be implemented within the Node class, but their specific details are not given in the 
  // provided code snippet.

// In summary, the Node class handles transaction requests, receives transactions, verifies them using utility functions, and performs 
// additional verification and consensus algorithm operations. It acts as a node within a network to process and validate transactions.
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

#include "Node.hpp"
#include "Utils.hpp"
#include "Requests.hpp"
#include "Miner.hpp"
#include "Consensus/Consensus.hpp"
#include "Requests.hpp"
#include "json.hh"
#include "Server_http.hpp"
#include "P2P.hpp"
#include "P2Pmanager.hpp"
#include "Message.hpp"


using json = nlohmann::json;

namespace SPHINXNode {

    class SPHINXNodes {
    public:
        SPHINXNodes() {
            // Initialize node components
        }

        void handleTransactionRequest(const Transaction& transaction) {
            mempool.addTransaction(transaction);
        }

        void verifyTransactions() {
            // Verify transactions within mempool
            mempool.verifyTransactions();
        }

        void performProofOfWork() {
            // Check if consensus is reached before performing proof-of-work
            if (SPHINXConsensus::isConsensusReached()) {
                // Perform SPHINX consensus before proof-of-work
                performSPHINXConsensus();

                // Continue with proof-of-work
                SPHINXMiner::Miner miner;
                miner.startMining();
            } else {
                std::cout << "Consensus is not reached. Cannot perform proof-of-work." << std::endl;
            }
        }

        // New function for cross-chain communication
        void handleCrossChainCommunication(const std::string& message) {
            // Implement the logic to handle cross-chain communication using the specified protocol
            // Example: Send the message to an external blockchain network

            // Perform SPHINXConsensus before cross-chain communication
            SPHINXConsensus::performSPHINXConsensus();

            // Send the message using the CrossChainProtocol
            CrossChainProtocol::sendMessage(message);
        }

        nlohmann::json SPHINXNodes::getSPHINXChainFromNodes(const std::vector<int>& listOfNodes) {
            return SPHINXHttp::getSPHINXChainFromNodes(listOfNodes);
        }

        void sendNewSPHINXChain(const std::vector<int>& listOfNodes, const std::string& json) {
            // Call the function from "Requests.hpp" to send the new SPHINX_Chain to the network
            SPHINXHttp::sendNewSPHINXChain(listOfNodes, json);
        }

    private:
        SPHINXMempool::Mempool mempool;
        SPHINXP2P::P2PManager p2pManager;
        SPHINXConsensus::Consensus consensus;
        SPHINXCommon::Common common;
    };
} // namespace SPHINXNode