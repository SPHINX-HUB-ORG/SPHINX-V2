/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* Libscapi uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


#pragma once
#include "CommitmentScheme.hpp"
#include "CommitmentSchemePedersen.hpp"

/**
* Concrete implementation of committer that executes the Pedersen trapdoor commitment
* scheme in the committer's point of view.
* This commitment is also a trapdoor commitment in the sense that the receiver after
* the commitment phase has a trapdoor value, that if known by the committer would enable
* it to decommit to any value. 
* This trapdoor is output by the receiver and can be used by a higher-level application
* (e.g., by the ZK transformation of a sigma protocol to a zero-knowledge proof of knowledge).
*
* For more information see Protocol 6.5.3, page 164 of Efficient Secure Two-Party Protocols
* by Hazay-Lindell.
*
* The pseudo code of this protocol can be found in Protocol 3.3 of pseudo codes document
* at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*/
class CmtPedersenTrapdoorCommitter : public CmtPedersenCommitter {
public:
	/**
	* Constructor that receives a connected channel (to the receiver) and chooses default dlog and random.
	* The receiver needs to be instantiated with the default constructor too.
	*/
	CmtPedersenTrapdoorCommitter(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) : CmtPedersenCommitter(channel, random) {};

	/**
	* Constructor that receives a connected channel (to the receiver), the DlogGroup agreed upon between them and a SecureRandom object.
	* The Receiver needs to be instantiated with the same DlogGroup, otherwise nothing will work properly.
	*/
	CmtPedersenTrapdoorCommitter(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) :
		CmtPedersenCommitter(channel, dlog, random) {};

	/**
	* Validate the h value received from the receiver in the pre process phase.
	* @param trap the trapdoor outputed from the receiver's commit phase.
	* @return true, if valid; false, otherwise.
	*/
	bool validate(const shared_ptr<CmtRCommitPhaseOutput> & trap) {
		auto trapdoor = dynamic_pointer_cast<CmtRTrapdoorCommitPhaseOutput>(trap);
		if (!trapdoor)
			throw invalid_argument("the given trapdor should be an instance of CmtRTrapdoorCommitPhaseOutput");
		// check that g^trapdoor equals to h.
		auto gToTrap = dlog->exponentiate(dlog->getGenerator().get(), trapdoor->getTrap());
		return (*gToTrap == *h);
	}
};

/**
* Concrete implementation of receiver that executes the Pedersen trapdoor commitment
* scheme in the receiver's point of view.
* This commitment is also a trapdoor commitment in the sense that the receiver after
* the commitment phase has a trapdoor value, that if known by the committer would enable
* it to decommit to any value. 
* This trapdoor is output by the receiver and can be used by a higher-level application
* (e.g., by the ZK transformation of a sigma protocol to a zero-knowledge proof of knowledge).<p>
* For more information see Protocol 6.5.3, page 164 of <i>Efficient Secure Two-Party Protocols</i>
* by Hazay-Lindell.
* The pseudo code of this protocol can be found in Protocol 3.3 of pseudo codes
* document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*/
class CmtPedersenTrapdoorReceiver : public CmtPedersenReceiver {
public:
	/**
	* Constructor that receives a connected channel (to the receiver),
	* the DlogGroup agreed upon between them and a SecureRandom object.
	* The committer needs to be instantiated with the same DlogGroup,
	* otherwise nothing will work properly.
	*/
	CmtPedersenTrapdoorReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg()) :
		CmtPedersenReceiver(channel, dlog, prg) {};

	/**
	* Returns the receiver's trapdoor from the preprocess phase.
	*/
	biginteger getTrapdoor() { return trapdoor; };

	shared_ptr<CmtRCommitPhaseOutput> receiveCommitment() override {
		// get the output from the super.receiverCommiotment.
		auto output = CmtPedersenReceiverCore::receiveCommitment();
		// wrap the output with the trapdoor.
		return make_shared<CmtRTrapdoorCommitPhaseOutput>(trapdoor, output->getCommitmentId());
	};
};

