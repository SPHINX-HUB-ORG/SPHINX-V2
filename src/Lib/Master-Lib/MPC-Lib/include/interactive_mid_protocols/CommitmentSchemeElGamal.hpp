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
#include "ZeroKnowledge.hpp"
#include "../mid_layer/ElGamalEnc.hpp"

/**
* This class holds the values used by the ElGamal Committer during the commitment phase
* for a specific value that the committer commits about.
* This value is kept attached to a random value used to calculate the commitment,
* which is also kept together in this structure.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtElGamalCommitmentPhaseValues : public CmtCommitmentPhaseValues {
private:
	//The value that the committer sends to the receiver in order to commit commitval in the commitment phase.
	shared_ptr<AsymmetricCiphertext> computedCommitment;

public:
	/**
	* Constructor that sets the given random value, committed value and the commitment object.
	* This constructor is package private. It should only be used by the classes in the package.
	* @param r random value used for commit.
	* @param commitVal the committed value
	* @param computedCommitment the commitment
	*/
	CmtElGamalCommitmentPhaseValues(const shared_ptr<RandomValue> & r, const shared_ptr<CmtCommitValue> & commitVal, const shared_ptr<AsymmetricCiphertext> & computedCommitment)
		: CmtCommitmentPhaseValues(r, commitVal) {
		this->computedCommitment = computedCommitment;
	}

	/**
	* Returns the value that the committer sends to the receiver in order to commit
	* commitval in the commitment phase.
	* @return the commitment value
	*/
	shared_ptr<void> getComputedCommitment() override {	return computedCommitment; }
};

/**
* Concrete implementation of commitment message used by ElGamal commitment scheme.
*
*/
class CmtElGamalCommitmentMessage : public CmtCCommitmentMsg {

	// In ElGamal schemes the commitment object is a ElGamalCiphertext
	//In order to this class be a serializable, we get it as ElGamalCiphertextSendableData. 
private:
	shared_ptr<AsymmetricCiphertextSendableData> cipherData;
	long id; //The id of the commitment

public:
	/**
	* Constructor that sets the commitment and id.
	* @param cipherData the actual commitment object. In ElGamal schemes the commitment object is a ElGamalCiphertextSendableData.
	* @param id the commitment id.
	*/
	CmtElGamalCommitmentMessage(const shared_ptr<AsymmetricCiphertextSendableData> & cipherData = NULL, long id = 0) {
		this->cipherData = cipherData;
		this->id = id;
	}

	/**
	* Returns the commitment value. In this case the instance of the commitment is ElGamalCiphertextSendableData.
	*/
	shared_ptr<void> getCommitment() {	return cipherData; }

	/**
	* Returns the commitment id.
	*/
	long getId() { return id; }

	// network serialization implementation:
	void initFromString(const string & s) override {
		auto vec = explode(s, ':');
		id = stol(vec[0]);
		string inner = "";
		for (size_t i = 0; i < vec.size() - 1; i++) {
			inner += vec[1 + i];
			inner += ":";
		}
		cipherData->initFromString(inner);
	}
	string toString() override { return to_string(id) + ":" + cipherData->toString(); };
};

/**
* Concrete implementation of decommitment message used by ElGamal commitment scheme.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtElGamalDecommitmentMessage : public CmtCDecommitmentMessage {


private:
	//This message is common to ElGamal on GroupElement and on byte[].
	//In order to enable this, x value can hold every serializable object.
	shared_ptr<string> x;
	shared_ptr<BigIntegerRandomValue> r; //Random value sampled during the sampleRandomValues stage;

public:
	/**
	* Constructor that sets the given committed value and random value.
	* @param x the committed value
	* @param r the random value used for commit.
	*/
	CmtElGamalDecommitmentMessage(const shared_ptr<string> & x = NULL, const shared_ptr<BigIntegerRandomValue> & r = NULL) {
		this->x = x;
		this->r = r;
	}

	/**
	* Returns the committed value.
	*/
	shared_ptr<void> getX() override { return x; }
	string getXValue() { return *x; }

	/**
	* Returns the random value used for commit.
	*/
	shared_ptr<RandomValue> getR() override { return r;	}

	// network serialization implementation:
	void initFromString(const string & s) override {
		auto vec = explode(s, ':');
		if (vec.size() == 2) {
			x = make_shared<string>(vec[0]);
			r = make_shared<BigIntegerRandomValue>(biginteger(vec[1]));
		} else if (vec.size() == 3) {
			x = make_shared<string>(vec[0] + ":" + vec[1]);
			r = make_shared<BigIntegerRandomValue>(biginteger(vec[2]));
		} 
	}

	string toString() override { return *x + ":" + r->getR().str(); };
};

/**
* This abstract class performs all the core functionality of the committer side of
* ElGamal commitment.
* Specific implementations can extend this class and add or override functions as necessary.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtElGamalCommitterCore : public virtual CmtCommitter {
	/*
	* runs the following protocol:
	* "Commit phase
	*		IF NOT VALID_PARAMS(G,q,g)
	*			REPORT ERROR and HALT
	*		SAMPLE random values  a,r <- Zq
	*		COMPUTE h = g^a
	*		COMPUTE u = g^r and v = h^r * x
	*		SEND c = (h,u,v) to R
	*	Decommit phase
	*		SEND (r, x)  to R
	*		OUTPUT nothing"
	*
	*/

private:
	/**
	* The pre-process is performed once within the construction of this object.
	* If the user needs to generate new pre-process values then it needs to disregard
	* this instance and create a new one.
	* Runs the following lines from the pseudo code:
	* "SAMPLE random values  a<- Zq
	*	COMPUTE h = g^a"
	* @throws IOException
	*/
	void preProcess();

protected:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<PrgFromOpenSSLAES> random;
	biginteger qMinusOne;
	shared_ptr<ElGamalEnc> elGamal;
	shared_ptr<ElGamalPublicKey> publicKey;
	shared_ptr<ElGamalPrivateKey> privateKey;

	/**
	* Constructor that receives a connected channel (to the receiver),
	* the DlogGroup agreed upon between them, the encryption object and a SecureRandom.
	* The Receiver needs to be instantiated with the same DlogGroup,
	* otherwise nothing will work properly.
	*/
	CmtElGamalCommitterCore(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, const shared_ptr<ElGamalEnc> & elGamal, const shared_ptr<PrgFromOpenSSLAES> & random);

public:

	/**
	* Computes the commitment object of the commitment scheme. <p>
	* Pseudo code:<p>
	* "SAMPLE random values  r <- Zq <p>
	*	COMPUTE u = g^r and v = h^r * x". <p>
	* @return the created commitment.
	*/
	shared_ptr<CmtCCommitmentMsg> generateCommitmentMsg(const shared_ptr<CmtCommitValue> & input, long id) override;

	shared_ptr<CmtCDecommitmentMessage> generateDecommitmentMsg(long id) override; 

	vector<shared_ptr<void>> getPreProcessValues() override;
};



/**
* This class implements the committer side of the ElGamal commitment. <p>
* It uses El Gamal encryption for  group elements, that is, the encryption class used is
* ScElGamalOnGroupElement. This default cannot be changed.<p>
*
* The pseudo code of this protocol can be found in Protocol 3.4 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtElGamalOnGroupElementCommitter : public CmtElGamalCommitterCore, public PerfectlyBindingCmt, public CmtOnGroupElement {

public:
	/**
	* This constructor lets the caller pass the channel and the dlog group to work with. The El Gamal option (ScElGamalOnGroupElement)is set by default by the constructor and cannot be changed.
	* @param channel used for the communication
	* @throws SecurityLevelException
	* @throws InvalidDlogGroupException
	*/
	CmtElGamalOnGroupElementCommitter(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"), const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg())
		: CmtElGamalCommitterCore(channel, dlog, make_shared<ElGamalOnGroupElementEnc>(dlog), random) {}

	shared_ptr<CmtCCommitmentMsg> generateCommitmentMsg(const shared_ptr<CmtCommitValue> & input, long id) override; 

	/**
	* This function samples random commit value and returns it.
	* @return the sampled commit value
	*/
	shared_ptr<CmtCommitValue> sampleRandomCommitValue() override {
		return make_shared<CmtGroupElementCommitValue>(dlog->createRandomElement());
	}

	shared_ptr<CmtCommitValue> generateCommitValue(const vector<byte> & x) override {
		throw UnsupportedOperationException("El Gamal committer cannot generate a CommitValue from a byte[], since there isn't always a suitable encoding");
	}

	/**
	* This function converts the given commit value to a byte array.
	* @param value
	* @return the generated bytes.
	*/
	vector<byte> generateBytesFromCommitValue(CmtCommitValue* value) override;

};

/**
* This abstract class performs all the core functionality of the receiver side of ElGamal commitment.
* Specific implementations can extend this class and add or override functions as necessary.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtElGamalReceiverCore : public virtual CmtReceiver {

	/*
	* runs the following protocol:
	* "Commit phase
	*		WAIT for a value c
	*		STORE c
	*	Decommit phase
	*		WAIT for (r, x)  from C
	*		Let c = (h,u,v); if not of this format, output REJ
	*		IF NOT
	*			VALID_PARAMS(G,q,g), AND
	*			h <-G, AND
	*			u=g^r
	*			v = h^r * x
	*			x in G
	*		      OUTPUT REJ
	*		ELSE
	*		      OUTPUT ACC and value x"
	*
	*/
private:
	/**
	* Sets the given parameters and execute the preprocess phase of the scheme.
	*/
	void doConstruct(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, const shared_ptr<ElGamalEnc> & elGamal);

	/**
	* The pre-process is performed once within the construction of this object.
	* If the user needs to generate new pre-process values then it needs to disregard
	* this instance and create a new one.
	*/
	void preProcess();

protected:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<CommParty> channel;
	shared_ptr<ElGamalEnc> elGamal;
	shared_ptr<ElGamalPublicKey> publicKey;

	virtual shared_ptr<CmtElGamalCommitmentMessage> getCommitmentMsg() = 0; 

public:
	/**
	* Constructor that receives a connected channel (to the receiver),
	* the DlogGroup agreed upon between them and the encryption object.
	* The committer needs to be instantiated with the same DlogGroup,
	* otherwise nothing will work properly.
	*/
	CmtElGamalReceiverCore(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, const shared_ptr<ElGamalEnc> & elGamal) {
		doConstruct(channel, dlog, elGamal);
	}

	/**
	* Runs the commit phase of the commitment scheme.<p>
	* Pseudo code:<p>
	* "WAIT for a value c<p>
	*	STORE c".
	* @return the output of the commit phase.
	*/
	shared_ptr<CmtRCommitPhaseOutput> receiveCommitment() override; 

	/**
	* Runs the decommit phase of the commitment scheme.<p>
	* Pseudo code:<p>
	* "WAIT for (r, x)  from C<p>
	*	Let c = (h,u,v); if not of this format, output REJ<p>
	*	IF NOT<p>
	*		u=g^r <p>
	*		v = h^r * x<p>
	*		x in G<p>
	*		OUTPUT REJ<p>
	*	ELSE<p>
	*	    OUTPUT ACC and value x"
	* @param id
	* @return the committed value if the decommit succeeded; null, otherwise.
	*/
	shared_ptr<CmtCommitValue> receiveDecommitment(long id) override; 

	vector<shared_ptr<void>> getPreProcessedValues() override;
};

/**
* This class implements the receiver side of the ElGamal commitment. <p>
* It uses El Gamal encryption for  group elements, that is, the encryption class used is
* ScElGamalOnGroupElement. This default cannot be changed.<p>
*
* The pseudo code of this protocol can be found in Protocol 3.4 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtElGamalOnGroupElementReceiver : public CmtElGamalReceiverCore, public PerfectlyBindingCmt, public CmtOnGroupElement {
protected:
	shared_ptr<CmtElGamalCommitmentMessage> getCommitmentMsg() override;

public:
	/**
	* This constructor lets the caller pass the channel and the dlog group to work with.
	* The El Gamal option (ScElGamalOnGroupElement)is set by default by the constructor
	* and cannot be changed.
	* @param channel used for the communication
	* @param dlog Dlog group
	*/
	CmtElGamalOnGroupElementReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"))
		: CmtElGamalReceiverCore(channel, dlog, make_shared<ElGamalOnGroupElementEnc>(dlog)) {}

	/**
	* Proccesses the decommitment phase.
	* "IF NOT
	*		u=g^r 
	*		v = h^r * x
	*		x in G<p>
	*		OUTPUT REJ
	*	ELSE<p>
	*	    OUTPUT ACC and value x"
	* @param id the id of the commitment.
	* @param msg the receiver message from the committer
	* @return the committed value if the decommit succeeded; null, otherwise.
	*/
	shared_ptr<CmtCommitValue> verifyDecommitment(CmtCCommitmentMsg* commitmentMsg,
		CmtCDecommitmentMessage* decommitmentMsg) override; 

	/**
	* This function converts the given commit value to a byte array.
	* @param value
	* @return the generated bytes.
	*/
	vector<byte> generateBytesFromCommitValue(CmtCommitValue* value) override;

};

/**
* This class implements the committer side of the ElGamal commitment.
*
* It uses El Gamal encryption for byte arrays, that is, the encryption class used is
* ScElGamalOnbyteArray. This default cannot be changed.
*
* The pseudo code of this protocol can be found in Protocol 3.4 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class CmtElGamalOnByteArrayCommitter : public CmtElGamalCommitterCore, public PerfectlyBindingCmt, public CmtOnByteArray {

	/**
	* This constructor lets the caller pass the channel, the dlog group and the
	* KeyDerivation function to work with.
	* The El Gamal option (ScElGamalOnByteArray)is set by default by the constructor
	* and cannot be changed.
	* @param channel used for the communication
	* @param dlog	Dlog group
	* @param kdf key derivation function
	* @param random
	* 
	*/
public:
	CmtElGamalOnByteArrayCommitter(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"),
		const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>()), const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg())
		: CmtElGamalCommitterCore(channel, dlog, make_shared<ElGamalOnByteArrayEnc>(dlog, kdf), random) {}
	
	shared_ptr<CmtCCommitmentMsg> generateCommitmentMsg(const shared_ptr<CmtCommitValue> & input, long id) override;

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
* This class implements the receiver side of the ElGamal commitment. 
* It uses El Gamal encryption for byte arrays, that is, the encryption class used is
* ScElGamalOnByteArray. This default cannot be changed.
*
* The pseudo code of this protocol can be found in Protocol 3.4 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*/
class CmtElGamalOnByteArrayReceiver : public CmtElGamalReceiverCore , public PerfectlyBindingCmt, public CmtOnByteArray {
private:
	shared_ptr<KeyDerivationFunction> kdf;

protected:
	shared_ptr<CmtElGamalCommitmentMessage> getCommitmentMsg() override;

public:
	/**
	* This constructor lets the caller pass the channel, the dlog group and the
	* KeyDerivation function to work with.
	* The ElGamal option (ScElGamalOnByteArray)is set by default by the constructor
	* and cannot be changed.
	* @throws CheatAttemptException if the receiver suspects the committer trying to cheat.
	* @throws SecurityLevelException if the given dlog is not DDH - secure
	* @throws InvalidDlogGroupException if the given dlog is not valid
	*/
	CmtElGamalOnByteArrayReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"),
		const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>())) : CmtElGamalReceiverCore(channel, dlog, make_shared<ElGamalOnByteArrayEnc>(dlog, kdf)) {
		this->kdf = kdf;
	}

	/**
	* Proccesses the decommitment phase.
	* "IF NOT<p>
	*		u=g^r <p>
	*		v = h^r * x<p>
	*		x in G<p>
	*		OUTPUT REJ<p>
	*	ELSE<p>
	*	    OUTPUT ACC and value x"
	* @param id the id of the commitment.
	* @param msg the receiver message from the committer
	* @return the committed value if the decommit succeeded; null, otherwise.
	*/
	shared_ptr<CmtCommitValue> verifyDecommitment(CmtCCommitmentMsg* commitmentMsg,
		CmtCDecommitmentMessage* decommitmentMsg) override; 

	/**
	* This function converts the given commit value to a byte array.
	* @param value
	* @return the generated bytes.
	*/
	vector<byte> generateBytesFromCommitValue(CmtCommitValue* value) override;
};

/**
* Concrete implementation of committer with proofs.
* This implementation uses ZK based on SigmaElGamalKnowledge and SIgmaElGamalCommittedValue.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class CmtElGamalWithProofsCommitter : public CmtElGamalOnGroupElementCommitter, public CmtWithProofsCommitter {
private:

	//Proves that the committer knows the committed value.
	shared_ptr<ZKPOKFromSigmaCmtPedersenProver> knowledgeProver;
	//Proves that the committed value is x.
	shared_ptr<ZKFromSigmaProver> committedValProver;

public:
	/**
	* Default constructor that gets the channel and creates the ZK provers with default Dlog group.
	*/
	CmtElGamalWithProofsCommitter(const shared_ptr<CommParty> & channel, int t, const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"), const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg());

	void proveKnowledge(long id) override; 
	void proveCommittedValue(long id) override;
};

/**
* Concrete implementation of receiver with proofs.
*
* This implementation uses ZK based on SigmaElGamalKnowledge and SIgmaElGamalCommittedValue.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class CmtElGamalWithProofsReceiver : public CmtElGamalOnGroupElementReceiver, public CmtWithProofsReceiver {
private:

	//Verifies that the committer knows the committed value.
	shared_ptr<ZKPOKFromSigmaCmtPedersenVerifier> knowledgeVerifier;
	//Proves that the committed value is x.
	shared_ptr<ZKFromSigmaVerifier> committedValVerifier;

public:
	
	/**
	* Constructor that gets the channel, dlog, statistical parameter and random and uses
	* them to create the ZK verifiers.
	* @param t statistical parameter
	*/
	CmtElGamalWithProofsReceiver(const shared_ptr<CommParty> & channel, int t, const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"), const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg());

	bool verifyKnowledge(long id) override; 

	shared_ptr<CmtCommitValue> verifyCommittedValue(long id) override; 
};



