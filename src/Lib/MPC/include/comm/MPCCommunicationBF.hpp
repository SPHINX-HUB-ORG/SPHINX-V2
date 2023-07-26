
#pragma once

#include <memory>

#include "../../include/comm/CommBF.hpp"

class ProtocolPartyDataBF {
private:
    int id;
    std::shared_ptr<CommPartyBF> channel;  // Channel between this party to every other party in the protocol.

public:
    ProtocolPartyDataBF() {}
    ProtocolPartyDataBF(int id, std::shared_ptr<CommPartyBF> channel)
            : id (id), channel(channel){
    }

    int getID() { return id; }
    std::shared_ptr<CommPartyBF> getChannel() { return channel; }
};

class MPCCommunicationBF {

public:
    static std::vector< std::shared_ptr<ProtocolPartyDataBF> > setCommunication(int id, int numParties, std::string configFile);
};

