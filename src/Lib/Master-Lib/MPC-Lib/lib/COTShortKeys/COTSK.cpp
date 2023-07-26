#include "COTSK.h"
#include "COTSK_types.h"
#include "COTSK_impl.h"
#include "MPCCommunicationEX.hpp"
#include "../../include/comm/Comm.hpp"


/*********************************************
    COTSK_pOne::COTSK_pOne
**********************************************/
COTSK_pOne::COTSK_pOne(	uint8_t lBits,
	  				    uint8_t numSessions,
					    uint32_t maxExpandBits,
						int partyIdInCommitee,
  						const string & serverAddr,
						const vector<string> &peerIps) :
    _senders(peerIps.size()),_nPeers(peerIps.size()),_lBits(lBits),_numSessions(numSessions) {
 	assert(_nPeers <= 100);

	_peers = MPCEXsetCommunication(_io_service, partyIdInCommitee, serverAddr, true ,peerIps);

	for (int i=0; i < _nPeers; i++) {
		int baseOTport = BASEOT_FIRST_PORT + partyIdInCommitee + 100*i;
		_senders[i] = new COTSK_Sender(serverAddr, baseOTport, _peers[i]->getChannel(), _lBits, _numSessions, maxExpandBits);
	}
		
}
/*********************************************
    COTSK_pOne::initialize
**********************************************/
void COTSK_pOne::initializeOrRekey(uint8_t sessionId ,const byte * delta) {

	vector<thread> threads(_nPeers);
    for (int i=0; i<_nPeers; i++) {
		threads[i] = thread(&COTSK_Sender::initializeOrRekey,_senders[i], sessionId, delta);
    }
	for (int i=0; i<_nPeers; i++) {
		  threads[i].join();
	}	
}

/*********************************************
    COTSK_pOne::extend
**********************************************/
void COTSK_pOne::extend (uint8_t sessionId,uint32_t size_bits, vector<byte *> & q_i_j) {

	vector<thread> threads(_nPeers);
 	for (int i=0; i<_nPeers; i++) {
		threads[i] = thread(&COTSK_Sender::extend,_senders[i], sessionId, size_bits , q_i_j[i]);
    }
	for (int i=0; i<_nPeers; i++) {
		  threads[i].join();
	}	

}


/*********************************************
    COTSK_pTwo::COTSK_pTwo
**********************************************/
COTSK_pTwo::COTSK_pTwo(uint8_t lBits, 
					   uint8_t numSessions,
					   uint32_t maxExpandBits,
					   int partyIdInCommitee, 
					   const string & serverAddr,
					   const vector<string> &peerIps): 
	_receivers(peerIps.size()),	_nPeers(peerIps.size()),_lBits(lBits),_numSessions(numSessions)

{
	assert(_nPeers <= 100);
	_peers = MPCEXsetCommunication(_io_service, partyIdInCommitee, serverAddr, false ,peerIps);
	
	for (int i=0; i < _nPeers; i++) {
		int baseOTport = BASEOT_FIRST_PORT + 100*partyIdInCommitee + i;
		_receivers[i] = new COTSK_Receiver(baseOTport,_peers[i]->getChannel(),_lBits,_numSessions,maxExpandBits);
	}

}
/*********************************************
    COTSK_pTwo::initialize
**********************************************/
void COTSK_pTwo::initializeOrRekey(uint8_t sessionId) {
	
 	vector<thread> threads(_nPeers);
    for (int i=0; i<_nPeers; i++) {
		threads[i] = thread(&COTSK_Receiver::initializeOrRekey,_receivers[i], sessionId);
 	}
	for (int i=0; i<_nPeers; i++) {
		  threads[i].join();
	}
}

/*********************************************
    COTSK_pTwo::extend()
**********************************************/
void COTSK_pTwo::extend(
					uint8_t sessionId,
					uint32_t size_bits,
					const byte *x_and_r, 
					vector<byte *> & t_j_i_out) {
	
	vector<thread> threads(_nPeers);
    for (int i=0; i<_nPeers; i++) {
		threads[i] = thread(&COTSK_Receiver::extend,_receivers[i], sessionId, size_bits , x_and_r, t_j_i_out[i]);
    }
	for (int i=0; i<_nPeers; i++) {
		  threads[i].join();
	}
}

/*********************************************
    COMM : Moved to here so we have one COTSK.o 
	output
**********************************************/
vector<shared_ptr<ProtocolPartyDataEX> > MPCEXsetCommunication (boost::asio::io_service & io_service, 
                                                               int partyID,
                                                               const string & selfAddr,
                                                               bool isSelfpOne,  
                                                               const vector<string> & peerIps) {
    
    int nPeers = peerIps.size();
    vector<shared_ptr<ProtocolPartyDataEX>> parties(nPeers);
  
    SocketPartyData me, other;
		
 	int role = isSelfpOne ? 0 : 1; //0 server, 1 client
    
    for (int i=0; i<nPeers; i++) {
		int port =  isSelfpOne ? (FIRST_PORT + 100*partyID + i) : (FIRST_PORT + partyID + 100*i);
        me = SocketPartyData(boost_ip::address::from_string(selfAddr),port);
        other = SocketPartyData(boost_ip::address::from_string(peerIps[i]), port);
        shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, me, other, role);
        cout << " role: "  << role << " peer: " << i << " port: " << port << endl ;
		channel->join(500, 30000);
 		cout << "after join" << endl;
        parties[i] = make_shared<ProtocolPartyDataEX>(i, channel);
     }

    return parties;

}
