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
#include "../../include/primitives/HashOpenSSL.hpp"
#include "../primitives/Prg.hpp"

/**
* Concrete implementation of decommitment message used by SimpleHash commitment scheme.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtPedersenHashDecommitmentMessage : public CmtCDecommitmentMessage {
private:
	shared_ptr<BigIntegerRandomValue> r; //Random value sampled during the commitment stage;
	shared_ptr<vector<byte>> x; //Committer's private input x 

public:
	CmtPedersenHashDecommitmentMessage() {}

	/**
	* Constructor that sets the given committed value and random value.
	* @param x the committed value
	* @param r the random value used for commit.
	*/
	CmtPedersenHashDecommitmentMessage(const shared_ptr<BigIntegerRandomValue> & r, const shared_ptr<vector<byte>> & x) {
		this->r = r;
		this->x = x;
	}
	
	shared_ptr<void> getX() override { return x; }
	vector<byte> getXValue() { return *x; }

	shared_ptr<RandomValue> getR() override { return r; }

	// network serialization implementation:
	void initFromString(const string & s) override;
	string toString() override;

};

/**
* Concrete implementation of committer that executes the Pedersen hash commitment
* scheme in the committer's point of view.
*
* This is a perfectly-hiding commitment that can be used to commit to a value of any length. 
*
* For more information see Protocol 6.5.3, page 164 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.
*
* The pseudo code of this protocol can be found in Protocol 3.2 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtPedersenHashCommitter : public CmtPedersenCommitterCore, public PerfectlyHidingCmt, public CmtOnByteArray {
	/*
	* Runs the following protocol:
	* "Run COMMIT_PEDERSEN to commit to value H(x).
	* For decommitment, send x and the receiver verifies that the commitment was to H(x). "
	*/

private:
	shared_ptr<CryptographicHash> hash;
	
public:
	/**
	* This constructor uses a default Dlog Group and default Cryptographic Hash. They keep the condition that
	* the size in bytes of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	* An established channel has to be provided by the user of the class.
	* @throws invalid_argument
	*/
	CmtPedersenHashCommitter(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) : CmtPedersenCommitterCore(channel, random) {
		hash = make_shared<OpenSSLSHA256>(); 	//This default hash suits the default DlogGroup of the underlying Committer.
		if (hash->getHashedMsgSize() > (int) bytesCount(dlog->getOrder())) {
			throw invalid_argument("The size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup.");
		}
	}

	/**
	* This constructor receives as arguments an instance of a Dlog Group and an instance
	* of a Cryptographic Hash such that they keep the condition that the size in bytes
	* of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	* Otherwise, it throws invalid_argument.
	* An established channel has to be provided by the user of the class.
	* @param channel an established channel obtained via the Communication Layer
	* @param dlog
	* @param hash
	* @param random
	* @throws invalid_argument if the size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup
	* @throws SecurityLevelException if the Dlog Group is not DDH
	* @throws InvalidDlogGroupException if the parameters of the group do not conform the type the group is supposed to be
	* @throws CheatAttemptException if the commetter suspects that the receiver is trying to cheat.
	*/
	CmtPedersenHashCommitter(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, const shared_ptr<CryptographicHash> & hash, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/*
	* Runs COMMIT_ElGamal to commit to value H(x).
	* @return the created commitment.
	*/
	shared_ptr<CmtCCommitmentMsg> generateCommitmentMsg(const shared_ptr<CmtCommitValue> & input, long id) override; 

	shared_ptr<CmtCDecommitmentMessage> generateDecommitmentMsg(long id) override;

	/**
	* This function samples random commit value and returns it.
	* @return the sampled commit value
	*/
	shared_ptr<CmtCommitValue> sampleRandomCommitValue() override;

	shared_ptr<CmtCommitValue> generateCommitValue(const vector<byte> & x) override {
		return make_shared<CmtByteArrayCommitValue>(make_shared<vector<byte>>(x));
	}

	/**
	* This function converts the given commit value to a byte array.
	* @param value
	* @return the generated bytes.
	*/
	vector<byte> generateBytesFromCommitValue(CmtCommitValue* value) override; 

};

/**
* Concrete implementation of receiver that executes the Pedersen hash commitment
* scheme in the receiver's point of view.
*
* This is a perfectly-hiding commitment that can be used to commit to a value of any length. 
*
* For more information see Protocol 6.5.3, page 164 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.
* The pseudo code of this protocol can be found in Protocol 3.2 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtPedersenHashReceiver : public CmtPedersenReceiverCore, public PerfectlyHidingCmt, public CmtOnByteArray {

	/*
	* runs the following protocol:
	* "Run COMMIT_PEDERSEN to commit to value H(x).
	* For decommitment, send x and the receiver verifies that the commitment was to H(x). "
	*/

private:
	shared_ptr<CryptographicHash> hash;

public:
	/**
	* This constructor uses a default Dlog Group and default Cryptographic Hash. They keep the condition that
	* the size in bytes of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	* An established channel has to be provided by the user of the class.
	* @param channel
	*/
	CmtPedersenHashReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) : CmtPedersenReceiverCore(channel, random) {
		hash = make_shared<OpenSSLSHA256>(); 		//This default hash suits the default DlogGroup of the underlying Committer.
	}

	/**
	* This constructor receives as arguments an instance of a Dlog Group and an instance
	* of a Cryptographic Hash such that they keep the condition that the size in bytes
	* of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	* Otherwise, it throws IllegalArgumentException.
	* An established channel has to be provided by the user of the class.
	* @param channel an established channel obtained via the Communication Layer
	* @param dlog
	* @param hash
	* @param random
	* @throws invalid_argument if the size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup
	* @throws SecurityLevelException if the Dlog Group is not DDH
	* @throws InvalidDlogGroupException if the parameters of the group do not conform the type the group is supposed to be
	*/
	CmtPedersenHashReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, const shared_ptr<CryptographicHash> & hash, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	shared_ptr<CmtCommitValue> receiveDecommitment(long id) override;

	/**
	* Verifies that the commitment was to H(x).
	*/
	shared_ptr<CmtCommitValue> verifyDecommitment(CmtCCommitmentMsg* commitmentMsg,	CmtCDecommitmentMessage* decommitmentMsg) override; 

	/**
	* This function converts the given commit value to a byte array.
	* @param value
	* @return the generated bytes.
	*/
	vector<byte> generateBytesFromCommitValue(CmtCommitValue* value) override; 

};