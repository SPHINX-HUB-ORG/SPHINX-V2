// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.



#ifndef SPHINXP2P_HPP
#define SPHINXP2P_HPP

#include <string>
#include "Sync.hpp"

namespace SPHINXP2P {

    struct NetworkMessage {
        enum class MessageType {
            BlockRequest,
            Blocks,
            // Add more message types as needed
        };

        MessageType type;
        std::string senderAddress;
        std::string receiverAddress;
        std::string payload; // Actual message content

        // Serialize and deserialize functions
        std::string serialize() const;
        static NetworkMessage deserialize(const std::string& serialized);
    };

} // namespace SPHINXP2P

#endif // MESSAGE_HPP
