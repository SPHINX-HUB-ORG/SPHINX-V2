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
#include "../comm/Comm.hpp"
#include "../../include/primitives/DlogOpenSSL.hpp"
#include <map>


/**
* Concrete implementation of commitment message used by Pedersen commitment scheme.
*/
class CmtPedersenCommitmentMessage : public CmtCCommitmentMsg{
	// in Pedersen schemes the commitment object is a groupElement. 
	// in order to this class be a serializable, we get it as GroupElementSendableData.
private:
	shared_ptr<GroupElementSendableData> c = NULL;
	long id=0; // the id of the commitment
public:
	/**
	* Constructor that sets the commitment and id.
	* @param c the actual commitment object. In Pedersen schemes the commitment object is a groupElement.
	* @param id the commitment id.
	*/
	CmtPedersenCommitmentMessage(const shared_ptr<GroupElementSendableData> & c, long id = 0) {
		this->c = c;
		this->id = id;
	};

	shared_ptr<void> getCommitment() override { return c; };
	long getId() override { return id; };

	// SerializedNetwork implementation:
	string toString() override {
		return to_string(id) + ':' + c->toString();
	}

	void initFromString(const string & raw) override {
		auto str_vec = explode(raw, ':');
		id = stol(str_vec[0]);
		if (str_vec.size() == 3) {
			str_vec[1] += ":" + str_vec[2];
		}
		c->initFromString(str_vec[1]);
	};
};

/**
* Concrete implementation of decommitment message used by Pedersen commitment scheme.
*/
class CmtPedersenDecommitmentMessage : public CmtCDecommitmentMessage {
private:
	shared_ptr<biginteger> x; // committer's private input x in Zq
	shared_ptr<BigIntegerRandomValue> r; // random value sampled during the sampleRandomValues stage;
public:
	/**
	* Constructor that sets the given committed value and random value.
	* @param x the committed value
	* @param r the random value used for commit.
	*/
	CmtPedersenDecommitmentMessage(const shared_ptr<biginteger> & x = make_shared<biginteger>(0), const shared_ptr<BigIntegerRandomValue> & r = NULL) {
		this->x = x;
		this->r = r;
	};

	shared_ptr<RandomValue> getR() override { return r; };
	biginteger getRValue() { return r->getR(); }
	shared_ptr<void> getX() override { return x; };
	biginteger getXValue() { return *x; }

	// network serialization implementation:
	void initFromString(const string & s) override {
		auto vec = explode(s, ':');
		*x = biginteger(vec[0]);
		biginteger rVal(vec[1]);
		r = make_shared<BigIntegerRandomValue>(rVal);
	}
	string toString() override { return x->str() + ':' + getRValue().str(); };
};

/**
* This class holds the values used by the Pedersen Committer during the commitment phase
* for a specific value that the committer commits about.
* This value is kept attached to a random value used to calculate the commitment,
* which is also kept together in this structure.
*/
class CmtPedersenCommitmentPhaseValues : public CmtCommitmentPhaseValues {
private:
	// The value that the committer sends to the receiver in order to
	// commit commitval in the commitment phase.
	shared_ptr<GroupElement> computedCommitment;

public:
	/**
	* Constructor that sets the given random value, committed value and the commitment object.
	* This constructor is package private. It should only be used by the classes in the package.
	* @param r random value used for commit.
	* @param commitVal the committed value
	* @param computedCommitment the commitment
	*/
	CmtPedersenCommitmentPhaseValues(const shared_ptr<RandomValue> & r,
		const shared_ptr<CmtCommitValue> & commitVal, const shared_ptr<GroupElement> & computedCommitment) : CmtCommitmentPhaseValues(r, commitVal) {
		this->computedCommitment = computedCommitment;
	};

	/**
	* Returns the value that the committer sends to the receiver in order to commit commitval in 
	* the commitment phase.
	*/
	shared_ptr<void> getComputedCommitment() override { return computedCommitment; };
};

/*
* This abstract class performs all the core functionality of the receiver side of Pedersen commitment.
* Specific implementations can extend this class and add or override functions as necessary.
*/
class CmtPedersenReceiverCore : public virtual CmtReceiver {
	/*
	* runs the following protocol:
	* "Commit phase
	*		SAMPLE a random value a <- Zq
	*		COMPUTE h = g^a
	*		SEND h to C
	*		WAIT for message c from C
	*		STORE values (h,c)
	*	Decommit phase
	*		WAIT for (r, x)  from C
	*		IF  c = g^r * h^x AND x <- Zq
	*	    	OUTPUT ACC and value x
	*		ELSE
	*	        OUTPUT REJ"
	*
	*/

protected:
	shared_ptr<CommParty> channel;
	shared_ptr<DlogGroup> dlog;
	shared_ptr<PrgFromOpenSSLAES> random;
	biginteger trapdoor; // sampled random value in Zq that will be the trpadoor.
	// h is a value calculated during the creation of this receiver and is sent to
	// the committer once in the beginning.
	shared_ptr<GroupElement> h;

	/**
	* This constructor only needs to get a connected channel (to the committer). 
	* All the other needed elements have default values.
	* If this constructor is used for the recevier then also the default constructor 
	* needs to be used by the committer.
	*/
	CmtPedersenReceiverCore(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random, const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"));

private:
	biginteger qMinusOne;

	/**
	* Runs the preprocess stage of the protocol:
	* "SAMPLE a random value a <- Zq
	*	COMPUTE h = g^a
	*	SEND h to C".
	* The pre-process phase is performed once per instance.
	* If different values are required, a new instance of the receiver and the committer
	* need to be created.
	*/
	void preProcess();
public:
	/**
	* Wait for the committer to send the commitment. When the message is received and
	* after reconstructing the group element, save it in the commitmentMap using the id
	* also received in the message.
	* Pseudo code:<P>
	* "WAIT for message c from C
	*  STORE values (h,c)".
	*/
	shared_ptr<CmtRCommitPhaseOutput> receiveCommitment() override;

	/**
	* Wait for the decommitter to send the decommitment message.
	* If there had been a commitment for the requested id then proceed with validation,
	* otherwise reject.
	*/
	shared_ptr<CmtCommitValue> receiveDecommitment(long id) override;

	/**
	* Run the decommitment phase of the protocol:
	* "IF  c = g^r * h^x AND x <- Zq
	*	    OUTPUT ACC and value x
	*	ELSE
	*	    OUTPUT REJ".	
	* @param id of the commitment
	* @return the committed value
	*/
	shared_ptr<CmtCommitValue> verifyDecommitment(CmtCCommitmentMsg* commitmentMsg,
		CmtCDecommitmentMessage* decommitmentMsg) override;

	vector<shared_ptr<void>> getPreProcessedValues() override;
	
	shared_ptr<void> getCommitmentPhaseValues(long id) override;
};

/**
* This abstract class performs all the core functionality of the committer side of
* Pedersen commitment. 
* Specific implementations can extend this class and add or override functions as necessary.
*/
class CmtPedersenCommitterCore : public virtual CmtCommitter {
	/*
	* runs the following protocol:
	* "Commit phase
	*		IF NOT VALID_PARAMS(G,q,g)
	*			REPORT ERROR and HALT
	*		WAIT for h from R
	*		IF NOT h in G
	*			REPORT ERROR and HALT
	* 		SAMPLE a random value r <- Zq
	* 		COMPUTE  c = g^r * h^x
	* 		SEND c
	*	Decommit phase
	*		SEND (r, x) to R
	*		OUTPUT nothing."
	*
	*/
protected:
	
	shared_ptr<DlogGroup> dlog;
	shared_ptr<PrgFromOpenSSLAES> random;
	
	// the content of the message obtained from the receiver during the pre-process phase which occurs upon construction.
	shared_ptr<GroupElement> h;

	/**
	* Constructor that receives a connected channel (to the receiver),
	* the DlogGroup agreed upon between them and a SecureRandom object.
	* The Receiver needs to be instantiated with the same DlogGroup, 
	* otherwise nothing will work properly.
	*/
	CmtPedersenCommitterCore(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random, const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"));

private:
	biginteger qMinusOne;

	/**
	* Runs the preprocess phase of the commitment scheme:
	* "WAIT for h from R
	* IF NOT h in G
	*	REPORT ERROR and HALT"
	*/
	void preProcess();
	/**
	* Receives message from the receiver.
	* @return the received message
	*/
	shared_ptr<GroupElementSendableData> waitForMessageFromReceiver();

public:
	/**
	* Runs the following line of the commitment scheme: 
	* 	COMPUTE  c = g^r * h^x". 
	* with predetermined randomness r
	*/
	shared_ptr<CmtCCommitmentMsg> generateCommitmentMsg(const shared_ptr<CmtCommitValue> & input, biginteger r, long id) override;


	/**
	* Runs the following lines of the commitment scheme:
	* "SAMPLE a random value r <- Zq
	* 	COMPUTE  c = g^r * h^x".
	*/
	shared_ptr<CmtCCommitmentMsg> generateCommitmentMsg(const shared_ptr<CmtCommitValue> & input, long id) override;
	
	shared_ptr<CmtCDecommitmentMessage> generateDecommitmentMsg(long id) override;
	
	vector<shared_ptr<void>> getPreProcessValues() override;
};

/**
* Concrete implementation of committer that executes the Pedersen commitment scheme 
* in the committer's point of view.
* For more information see Protocol 6.5.3, page 164 of 
* <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.
* The pseudo code of this protocol can be found in Protocol 3.1 of pseudo codes 
* document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*/
class CmtPedersenCommitter : public CmtPedersenCommitterCore, public PerfectlyHidingCmt, public CmtOnBigInteger {
public:
	/**
	* Constructor that receives a connected channel (to the receiver)
	* and chooses default dlog and random.
	* The receiver needs to be instantiated with the default constructor too.
	* @param channel
	*/
	CmtPedersenCommitter(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) : CmtPedersenCommitterCore(channel, random) {};

	
	/**
	* Constructor that receives a connected channel (to the receiver), 
	* the DlogGroup agreed upon between them and a SecureRandom object.
	* The Receiver needs to be instantiated with the same DlogGroup, 
	* otherwise nothing will work properly.
	*/
	CmtPedersenCommitter(const shared_ptr<CommParty> & channel,	const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) :
		CmtPedersenCommitterCore(channel, random, dlog) {};
	
	shared_ptr<CmtCommitValue> generateCommitValue(const vector<byte> & x) override {
		biginteger bi = decodeBigInteger(x.data(), x.size());
		return make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(bi));
	};
	vector<byte> generateBytesFromCommitValue(CmtCommitValue* value) override;

	shared_ptr<CmtCommitValue> sampleRandomCommitValue() override {
		auto val = getRandomInRange(0, dlog->getOrder() - 1, random.get());
		return make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(val));
	}
};

/**
* Concrete implementation of receiver that executes the Pedersen commitment
* scheme in the receiver's point of view.
* For more information see Protocol 6.5.3, page 164 of
* <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 3.1 of pseudo codes 
* document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*/
class CmtPedersenReceiver : public CmtPedersenReceiverCore, public PerfectlyHidingCmt, public CmtOnBigInteger {
public:
	/**
	* Constructor that receives a connected channel (to the receiver) and chooses default dlog and random.
	* The committer needs to be instantiated with the default constructor too.
	* @param channel
	*/
	CmtPedersenReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) : CmtPedersenReceiverCore(channel, random) {};

	/**
	* Constructor that receives a connected channel (to the receiver), the DlogGroup agreed upon between them and a SecureRandom object.
	* The committer needs to be instantiated with the same DlogGroup, otherwise nothing will work properly.
	* @param channel
	* @param dlog
	* @param random
	* @throws SecurityLevelException if the given dlog is not DDH secure
	* @throws InvalidDlogGroupException if the given dlog is not valid.
	* @throws IOException if there was a problem in the communication
	*/
	CmtPedersenReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) :
		CmtPedersenReceiverCore(channel, random, dlog) {};

	/**
	* This function converts the given commit value to a byte array.
	* @param value
	* @return the generated bytes.
	*/
	vector<byte> generateBytesFromCommitValue(CmtCommitValue* value) override;
};

class ZKPOKFromSigmaCmtPedersenProver;
/**
* Concrete implementation of committer with proofs.
* This implementation uses ZK based on SigmaPedersenKnowledge and SIgmaPedersenCommittedValue.
*/
class CmtPedersenWithProofsCommitter : public CmtPedersenCommitter, public CmtWithProofsCommitter {
private:
	// proves that the committer knows the committed value.
	shared_ptr<ZKPOKFromSigmaCmtPedersenProver> knowledgeProver;
	// proves that the committed value is x.
	// usually, if the commitment scheme is PerfectlyBinding secure, than a ZK is used to prove committed value.
	// in Pedersen, this is not the case since Pedersen is not PerfectlyBinding secure.
	// in order to be able to use the Pedersen scheme we need to prove committed value with ZKPOK instead.
	shared_ptr<ZKPOKFromSigmaCmtPedersenProver> committedValProver;

	/**
	* Creates the ZK provers using sigma protocols that prove Pedersen's proofs.
	* @param t
	*/
	void doConstruct(int t, const shared_ptr<PrgFromOpenSSLAES> & random);

public:
	/**
	* Default constructor that gets the channel and creates the ZK provers with default Dlog group.
	* @param channel
	*/
	CmtPedersenWithProofsCommitter(const shared_ptr<CommParty> & channel, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) : CmtPedersenCommitter(channel, random) {
		doConstruct(t, random);
	};

	/**
	* Constructor that gets the channel, dlog, statistical parameter and random and uses them to
	* create the ZK provers.
	* @param channel
	* @param dlog
	* @param t statistical parameter
	* @param random
	*/
	CmtPedersenWithProofsCommitter(const shared_ptr<CommParty> & channel, int t, const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) :
		CmtPedersenCommitter(channel, dlog, random) {
		doConstruct(t, random);
	};

	void proveKnowledge(long id) override;
	void proveCommittedValue(long id) override;
};

class ZKPOKFromSigmaCmtPedersenVerifier;

/**
* Concrete implementation of receiver with proofs.
* This implementation uses ZK based on SigmaPedersenKnowledge and SIgmaPedersenCommittedValue.
*/
class CmtPedersenWithProofsReceiver : public CmtPedersenReceiver, public CmtWithProofsReceiver {
private:
	// Verifies that the committer knows the committed value.
	shared_ptr<ZKPOKFromSigmaCmtPedersenVerifier> knowledgeVerifier;
	// Verifies that the committed value is x.
	// Usually, if the commitment scheme is PerfectlyBinding secure, than a ZK is used to verify committed value.
	// In Pedersen, this is not the case since Pedersen is not PerfectlyBinding secure.
	// In order to be able to use the Pedersen scheme we need to verify committed value with ZKPOK instead.
	shared_ptr<ZKPOKFromSigmaCmtPedersenVerifier> committedValVerifier;
	/**
	* Creates the ZK verifiers using sigma protocols that verifies Pedersen's proofs.
	* @param t
	*/
	void doConstruct(int t, const shared_ptr<PrgFromOpenSSLAES> & prg);
public:
	/**
	* Default constructor that gets the channel and creates the ZK verifiers with default Dlog group.
	* @param channel
	*/
	CmtPedersenWithProofsReceiver(const shared_ptr<CommParty> & channel, int t, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg()) : CmtPedersenReceiver(channel, prg) {
		doConstruct(t, prg);
	};

	/**
	* Constructor that gets the channel, dlog, statistical parameter and random and uses them to create the ZK provers.
	* @param channel
	* @param dlog
	* @param t statistical parameter
	* @param random
	*/
	CmtPedersenWithProofsReceiver(const shared_ptr<CommParty> & channel, int t, const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg()) :
		CmtPedersenReceiver(channel, dlog, prg) {
		doConstruct(t, prg);
	};

	bool verifyKnowledge(long id) override;
	shared_ptr<CmtCommitValue> verifyCommittedValue(long id) override;
};

