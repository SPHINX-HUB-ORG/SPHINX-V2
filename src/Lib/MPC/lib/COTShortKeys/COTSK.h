#ifndef __COTSK_H___
#define __COTSK_H___

#include <cstdint>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <cassert>
#include <OT/BitVector.h>
#include <boost/asio.hpp>

#include "../../include/primitives/Prg.hpp"
#include "MPCCommunicationEX.hpp"
#include "COTSK_Receiver_impl.h"
#include "COTSK_Sender_impl.h"

/**
* Facade for the OT functionality with shorty keys
* This is the only file that needs to be included and used directly 
* Written by: Assi Barak, April 2018
*/


class COTSK_pOne {
	public:	
		/**
		* Construct a party in pOne group. (Pi). a single COTSK_pOne should be used 
		* to run the ROT protocol with all Pj parties. Each process (player) can be in one commitee
		*(P1 or P2), both (in this case it holds both instances), or none (if not in any commitee)
		* each method is handles by spawning a thread for each peer Pj, and running the method for that
		* party handler on the thread. The party handley can block (snd(),rcv()) as it only blocks its thread
		* 
		* Parameters:
		*
		* [in] lBits    - length of short key in bits. should in range 1..32.
		*		   	    - All values are supported( for example 5).
 		*			    - lbits = 1 is a special case (no check-correlation)
		*               - KNOWN LIMITATION - for this version, L <= 16 (no larger transpose yet)			
		*
		* There are 3 required communication parameters: 
		*
		* [in] partyIdInCommitee - Id of self party in commitee P1. This is an Id relative to the 
		*               commitee only. for example, if we have 20 parties (0..19), parties 3, 4, 7 
		*               for commitee P1 , then for party 4, the  partyIdInCommitee is 1 (3 is 0, 7 is 2)
		*
		* [in] selfAddr - Self IP address of the party. 
		*
		* [in] peerIps - vector with ip address of each peer. The channel uses port seperation,
		*              - so the same IP can be used multiple times in the list. for example, if the 
		*              - list includes 3 times "127.0.0.1", we assume 3 peers on localhost
		*              - the list only includes the ips of peers in the committee. 
		*
		*              - KNOWN LIMITATION - The class supports up to 100 peers, due to the port 
		*	           - allocation scheme
		*
		* the constructor also opens all communication channels.
		*/
		COTSK_pOne(uint8_t  lBits,
				   uint8_t  numSessions,
				   uint32_t maxExpandBits,
	 			   int partyIdInCommitee,            
				   const string & selfAddr,
				   const vector<string> &peerIps); 
	
		/**
		* Initialize the Party. This runs the Base Protocol (Bristol_OT_Extension) with all peers.
		* Parameters:
		*
		*/
		void initializeOrRekey(uint8_t sessionId, const byte * delta);  
	
		
		/**
		* Extend. Local party is i. Runs the protocol for m bits, with each of the peers j
		*
		* Parameters:
		*
		* [out] q_i_j . A vector of bit vectors, one for each peer. in the bit vectors, each
		* 				byte stores 8 values (0,1).
		* 				Important! the memory for the bit vectors is handled internally
		* 				by the pOne class. It is valid until the next call to extend. There is no need 
		* 				to free memory. From my understanding of the use case, there is no need to copy as well
		*
		*/
		void extend (  uint8_t sessionId  , uint32_t size_bits, vector<byte *> & q_i_j);
		
	
	private:
		boost::asio::io_service _io_service;
		vector<shared_ptr<ProtocolPartyDataEX>> _peers;	
		vector<COTSK_Sender *> _senders;
		int _nPeers;
		uint32_t _lBits;
		uint8_t _numSessions;
	
};

class COTSK_pTwo {
	
	public:
		/**
		* Construct a party in pTwo group. (Pj). a single COTSK_pOne should be used 
		* to run the ROT protocol with all Pj parties. Each process (player) can be in one commitee
		*(P1 or P2), both (in this case it holds both instances), or none (if not in any commitee)
		* each method is handles by spawning a thread for each peer Pi, and running the method for that
		* party handler on the thread. The party handler can block (snd(),rcv()) as it only blocks its thread
		* 
		* Parameters:
		*
		* [in] lBits    - length of short key in bits. should in range 1..32.
		*		   	    - All values are supported( for example 5).
 		*			    - lbits = 1 is a special case (no check-correlation)
		*               - KNOWN LIMITATION - for this version, L <= 16 (no larger transpose yet)			
		*
		* There are 3 required communication parameters: 
		*
		* [in] partyIdInCommitee - Id of self party in commitee P1. This is an Id relative to the 
		*               commitee only. for example, if we have 20 parties (0..19), parties 3, 4, 7 
		*               for commitee P1 , then for party 4, the  partyIdInCommitee is 1 (3 is 0, 7 is 2)
		*
		* [in] selfAddr - Self IP address of the party. 
		*
		* [in] peerIps - vector with ip address of each peer. The channel uses port seperation,
		*              - so the same IP can be used multiple times in the list. for example, if the 
		*              - list includes 3 times "127.0.0.1", we assume 3 peers on localhost
		*              - the list only includes the ips of peers in the committee. 
		*
		*              - KNOWN LIMITATION - The class supports up to 100 peers, due to the port 
		*	           - allocation scheme
		*
		* the constructor also opens all communication channels.
		*/		COTSK_pTwo(	uint8_t lBits,
						   	uint8_t numSessions,
						    uint32_t maxExpandBits,
						   	int partyIdInCommitee,
				   			const string & selfAddr,
				   			const vector<string> &peerIps);
	
		/**
		* Initialize the Party. This runs the Base Protocol (Bristol_OT_Extension) with all peers.
		* No input is required. Inputs are set by the other party.
		*/
		void initializeOrRekey(uint8_t sessionId);

			/**
		* Extend. Local party is j. Runs the protocol for m bits, with each of the peers i
		* Parameters:
		*
		* [in] x_h_j - bit vector of x_h_j. note that the same x_h_j is used for all peers i
		*            - If the caller holds x_h_j in a BitVector, you can pass in the octets() 
		*
		* 
		* [out] t_j_i_out
		*			   - A vector of bit vectors, one for each peer. in the bit vectors, each
		* 				byte stores 8 values (0,1).
		* 				Important! the memory for the bit vectors is handled internally
		* 				by the pOne class. It is valid until the next call to extend. There is no need 
		* 				to free memory. From my understanding of the use case, there is no need to copy as well
		*
		* 				KNOWN_LIMITATION - It would be nicer to return a vector of BitVector classes, however the
		* 				current implementation of BitVector cannot accept external memory.
		*/
		void extend( uint8_t sessionId,
					 uint32_t size_bits,
					 const byte *x_and_r,
					 vector<byte *> & t_j_i_out);	
	
		
	private:
		boost::asio::io_service _io_service;
		vector<shared_ptr<ProtocolPartyDataEX>> _peers;	
		vector<COTSK_Receiver *> _receivers;
		int _nPeers;
		uint32_t _lBits;
		uint8_t _numSessions;
};










#endif

