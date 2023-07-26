//
// Created by moriya on 04/01/17.
//

#ifndef MPCCOMMUNICATION_H
#define MPCCOMMUNICATION_H

#include <fstream>
#include "Comm.hpp"
#include "../infra/ConfigFile.hpp"
#include "../infra/json.hpp"

using json = nlohmann::json;

class ProtocolPartyData {
private:
    int id;
    shared_ptr<CommParty> channel;  // Channel between this party to every other party in the protocol.

public:
    ProtocolPartyData() {}
    ProtocolPartyData(int id, shared_ptr<CommParty> channel)
            : id (id), channel(channel){
    }

    int getID() { return id; }
    shared_ptr<CommParty> getChannel() { return channel; }
};



class MPCCommunication {
private :
    boost::asio::io_service io_service;
public:
    ~MPCCommunication(){
        io_service.stop();


    }
    static vector<shared_ptr<ProtocolPartyData>> setCommunication(boost::asio::io_service & io_service, int id,
            int numParties, const string & configFile);
    vector<shared_ptr<CommParty>> setCommunication(int id, int numParties, string configFile);

    void printNetworkStats(vector<shared_ptr<ProtocolPartyData>> &parties, int partyID,
                           vector<pair<string, string>> &arguments);

};


#endif //MPCCOMMUNICATION_H
