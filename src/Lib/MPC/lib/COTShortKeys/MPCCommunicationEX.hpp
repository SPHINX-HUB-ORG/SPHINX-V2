//
// Created by moriya on 04/01/17.
//

#ifndef MPCCOMMUNICATION__EX_H
#define MPCCOMMUNICATION__EX_H

#include "../../include/interactive_mid_protocols/OTBatch.hpp"
#include "../../include/interactive_mid_protocols/OTExtensionBristol.hpp"
#include "../../include/comm/CommBF.hpp"

class ProtocolPartyDataEX {
private:
    int id;
    shared_ptr<CommParty> channel;  // Channel between this party to every other party in the protocol.

public:
    ProtocolPartyDataEX() {}
    ProtocolPartyDataEX(int id, shared_ptr<CommParty> channel)
            : id (id), channel(channel){
    }

    int getID() { return id; }
    shared_ptr<CommParty> getChannel() { return channel; }
};

vector<shared_ptr<ProtocolPartyDataEX> > MPCEXsetCommunication (		boost::asio::io_service & io_service, 
  													  					int partyID,
                                                                    	const string & selfAddr,	
																		bool isSelfpOne,
																		const vector<string> & peerIps);



#endif //MPCCOMMUNICATION_H
