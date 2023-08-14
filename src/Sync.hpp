// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINX_SYNC
#define SPHINX_SYNC

#include <iostream>
#include <vector>

#include "block.hpp"
#include "peer.hpp"
#include "sync.hpp"
#include "p2p_manager.hpp"

namespace SPHINXSync {

    class SyncManager {
    public:
        void initiateSync(Node& node);
        void handleReceivedBlocks(Node& node, const std::vector<Block>& blocks);

    private:
        Sync sync;

        std::vector<Peer> findPeersToSyncWith(Node& node);
        void requestMissingBlocksFromPeers(Node& node, const std::vector<Peer>& peers);
        bool moreBlocksNeeded(Node& node);
        NetworkMessage createBlockRequestMessage(const Block& block);
        void sendRequestMessageToPeer(const NetworkMessage& message, const Peer& peer);
    };

} // namespace SPHINXSync
#endif // SPHINX_SYNC
