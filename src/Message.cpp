// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.

#include "Message.hpp"

struct NetworkMessage {
    enum MessageType {
        BlockRequest,
        Blocks,
        // Add more message types as needed
    };

    MessageType type;
    std::string senderAddress;
    std::string receiverAddress;
    std::string payload; // Actual message content

    // Serialize and deserialize functions
    std::string serialize() const {
        // Serialize the message fields into a string format
        std::string serializedMessage = std::to_string(type) + ","
                                      + senderAddress + ","
                                      + receiverAddress + ","
                                      + payload;
        return serializedMessage;
    }

    static NetworkMessage deserialize(const std::string& serialized) {
        NetworkMessage message;
        // Deserialize the string into message fields
        size_t pos = 0;
        size_t delimiterPos;
        
        // Parse MessageType
        delimiterPos = serialized.find(",");
        message.type = static_cast<MessageType>(std::stoi(serialized.substr(pos, delimiterPos - pos)));
        pos = delimiterPos + 1;

        // Parse senderAddress
        delimiterPos = serialized.find(",", pos);
        message.senderAddress = serialized.substr(pos, delimiterPos - pos);
        pos = delimiterPos + 1;

        // Parse receiverAddress
        delimiterPos = serialized.find(",", pos);
        message.receiverAddress = serialized.substr(pos, delimiterPos - pos);
        pos = delimiterPos + 1;

        // Remaining is payload
        message.payload = serialized.substr(pos);
        
        return message;
    }
};