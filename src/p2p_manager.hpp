// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINXP2P_HPP
#define SPHINXP2P_HPP

#include <iostream>
#include <string>
#include <vector>
#include <mutex>
#include <thread>

namespace SPHINXP2P {

    enum class MessageType {
        Block,
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
        P2PManager();

        void start();

        void initializeNetworkingParameters();

        void initializePeerManager();

        void initializeSyncManager();

        void initializeNetworkingThreads();

        void receiveMessages();

        void handleMessage(const NetworkMessage& message);

        NetworkMessage createBlockMessage(const SPHINXBlock& block);

        void broadcastMessage(const NetworkMessage& message);

        void handleBlockMessage(const NetworkMessage& message);

        void connectToPeer(const std::string& peerAddress);

        void disconnectFromPeer(const std::string& peerAddress);

        NetworkMessage receiveMessage();

    private:
        int port;
        std::string ipAddress;
        std::vector<std::string> connectedPeers;
        std::mutex syncMutex;

        void sendNetworkMessage(const std::string& peerAddress, const std::string& jsonData);

    };

} // namespace SPHINXP2P
