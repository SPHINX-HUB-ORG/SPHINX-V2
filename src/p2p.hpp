// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINXP2P_HPP
#define SPHINXP2P_HPP

#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <mutex>

#include "p2p_manager.hpp"


using json = nlohmann::json;

namespace SPHINXP2P {

    enum class MessageType {
        SPHINXBlock,
        // Add other message types as needed
    };

    struct SPHINXBlock {
        // Define SPHINXBlock structure and serialization/deserialization methods
        std::string data;

        std::string serialize() const {
            return data;
        }

        void deserialize(const std::string& serializedData) {
            data = serializedData;
        }

        std::string getData() const {
            return data;
        }
    };

    struct NetworkMessage {
        MessageType type;
        std::string data;

        std::string getData() const {
            return data;
        }

        MessageType getType() const {
            return type;
        }
    };

    class P2PManager {
    public:
        P2PManager() {
            start();
        }

        void start();

        void initializeNetworkingParameters();

        void initializePeerManager();

        void initializeSyncManager();

        void initializeNetworkingThreads();

        void receiveMessages();

        void handleMessage(const NetworkMessage& message);

        NetworkMessage createSPHINXBlockMessage(const SPHINXBlock& sphinxBlock);

        void broadcastMessage(const NetworkMessage& message);

        void handleSPHINXBlockMessage(const NetworkMessage& message);

        void connectToPeer(const std::string& peerAddress);

        void disconnectFromPeer(const std::string& peerAddress);

        NetworkMessage receiveMessage();

        // Add other member variables and functions as needed

    private:
        int port;
        std::string ipAddress;
        std::vector<std::string> connectedPeers;
        std::mutex syncMutex;

        // Implement your JSON-RPC message sending logic here
        void sendNetworkMessage(const std::string& peerAddress, const std::string& jsonData);

    };

} // namespace SPHINXP2P

#endif // SPHINXP2P_HPP
