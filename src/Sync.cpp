// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <iostream>
#include <vector>

#include "Block.hpp"
#include "p2p.hpp"
#include "Sync.hpp"
#include "p2p_manager.hpp"

namespace SPHINXSync {

    class SyncManager {
    public:
        void initiateSync(Node& node) {
            std::vector<Peer> peers = findPeersToSyncWith(node);
            requestMissingBlocksFromPeers(node, peers);
        }

        void handleReceivedBlocks(Node& node, const std::vector<Block>& blocks) {
            sync.processReceivedBlocks(node, blocks);
            if (moreBlocksNeeded(node)) {
                initiateSync(node);
            }
        }

    private:
        Sync sync;

        std::vector<Peer> findPeersToSyncWith(Node& node) {
            // Logic to discover and select peers for synchronization
            std::vector<Peer> peers;
            for (const Peer& peer : node.getKnownPeers()) {
                if (peer.isSyncable()) {
                    peers.push_back(peer);
                }
            }
            return peers;
        }

        void requestMissingBlocksFromPeers(Node& node, const std::vector<Peer>& peers) {
            for (const Peer& peer : peers) {
                Block lastKnownBlock = node.getLastKnownBlock();
                NetworkMessage requestMessage = createBlockRequestMessage(lastKnownBlock);
                sendRequestMessageToPeer(requestMessage, peer);
            }
        }

        bool moreBlocksNeeded(Node& node) {
            // Check if there are more blocks needed for synchronization
            if (node.getLastKnownBlock().index + 1 <= node.getChain().getHeight()) {
                return true;
            }
            return false;
        }

        NetworkMessage createBlockRequestMessage(const Block& block) {
            // Create a NetworkMessage requesting blocks after the specified block
            NetworkMessage requestMessage;
            requestMessage.type = NetworkMessageType::BlockRequest;
            requestMessage.blockHash = block.hash;
            return requestMessage;
        }

        void sendRequestMessageToPeer(const NetworkMessage& message, const Peer& peer) {
            // Send the request message to the specified peer
            P2PManager::getInstance().sendNetworkMessage(peer.address, message.serialize());
        }
    };
} // namespace SPHINXSync
