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
#include "../../include/primitives/HashOpenSSL.hpp"
#include "../../include/primitives/Prg.hpp"

/**
* This class holds the values used by the SimpleHash Committer during the commitment phase
* for a specific value that the committer commits about.
* This value is kept attached to a random value used to calculate the commitment,
* which is also kept together in this structure.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtSimpleHashCommitmentValues :public CmtCommitmentPhaseValues {
private:
	//The value that the committer sends to the receiver in order to commit commitval in the commitment phase.
	shared_ptr<vector<byte>> computedCommitment;

public:
	/**
	* Constructor that sets the given random value, committed value and the commitment object.
	* This constructor is package private. It should only be used by the classes in the package.
	* @param r random value used for commit.
	* @param commitVal the committed value
	* @param computedCommitment the commitment
	*/
	CmtSimpleHashCommitmentValues(const shared_ptr<RandomValue> & r, const shared_ptr<CmtCommitValue> & commitVal, const shared_ptr<vector<byte>> & computedCommitment)
		: CmtCommitmentPhaseValues(r, commitVal), computedCommitment(computedCommitment){}

	shared_ptr<void> getComputedCommitment() override { return computedCommitment; };

};

/**
* Concrete implementation of commitment message used by SimpleHash commitment scheme.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtSimpleHashCommitmentMessage : public CmtCCommitmentMsg {
	friend class boost::serialization::access;
private:
	// In SimpleHash schemes the commitment object is a vector<byte>. 
	shared_ptr<vector<byte>> c;
	long id; //The id of the commitment

public:
	/**
	* Constructor that sets the commitment and id.
	* @param c the actual commitment object. In simple hash schemes the commitment object is a byte vector.
	* @param id the commitment id.
	*/
	CmtSimpleHashCommitmentMessage(const shared_ptr<vector<byte>> & c = NULL, long id = 0) : c(c), id(id){}

	/**
	* Returns the commitment value.
	*/
	shared_ptr<void> getCommitment() override { return c; }
	shared_ptr<vector<byte>> getCommitmentArray() { return c; }

	/**
	* Returns the commitment id.
	*/
	long getId() override { return id; };

	// network serialization implementation:
	void initFromString(const string & s) override;
	string toString() override;

	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		ar & boost::serialization::base_object<CmtCCommitmentMsg>(*this);
		ar & c;
		ar & id;
	}

};

/**
* Concrete implementation of decommitment message used by SimpleHash commitment scheme.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtSimpleHashDecommitmentMessage : public CmtCDecommitmentMessage {
	friend class boost::serialization::access;
private:
	shared_ptr<ByteArrayRandomValue> r; //Random value sampled during the commitment stage;
	shared_ptr<vector<byte>> x; //Committer's private input x 

public:
	CmtSimpleHashDecommitmentMessage() {}

	/**
	* Constructor that sets the given committed value and random value.
	* @param x the committed value
	* @param r the random value used for commit.
	*/
	CmtSimpleHashDecommitmentMessage(const shared_ptr<ByteArrayRandomValue> & r, const shared_ptr<vector<byte>> & x) : r(r), x(x){}

	shared_ptr<void> getX() override { return x; }
	shared_ptr<vector<byte>> getXValue() { return x; }

	shared_ptr<RandomValue> getR() override { return r; }
	vector<byte> getRArray() { return r->getR(); }

	// network serialization implementation:
	void initFromString(const string & s) override;
	string toString() override;

	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		ar & boost::serialization::base_object<CmtCDecommitmentMessage>(*this);
		ar & x;
		ar & r;
	}
};

/**
* This class implements the committer side of Simple Hash commitment.
*
* This is a commitment scheme based on hash functions. 
* It can be viewed as a random-oracle scheme, but its security can also be viewed as a
* standard assumption on modern hash functions. Note that computational binding follows
* from the standard collision resistance assumption. 
*
* The pseudo code of this protocol can be found in Protocol 3.6 of pseudo codes document at  https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtSimpleHashCommitter : public CmtCommitter, public SecureCommit, public CmtOnByteArray {

	/*
	* runs the following protocol:
	* "Commit phase
	*		SAMPLE a random value r <- {0, 1}^n
	*		COMPUTE c = H(r,x) (c concatenated with r)
	*		SEND c to R
	*	Decommit phase
	*		SEND (r, x)  to R
	*		OUTPUT nothing"
	*/

private:
	shared_ptr<CryptographicHash> hash;
	int n;
	shared_ptr<PrgFromOpenSSLAES> prg;
	
public:
	
	/**
	* Constructor that receives a connected channel (to the receiver), the hash function
	* agreed upon between them, a SecureRandom object and a security parameter n.
	* The Receiver needs to be instantiated with the same hash, otherwise nothing will work properly.
	* @param channel
	* @param hash
	* @param random
	* @param n security parameter
	*
	*/
	CmtSimpleHashCommitter(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg(), const shared_ptr<CryptographicHash> & hash = make_shared<OpenSSLSHA256>(), int n = 32);

	/**
	* Runs the following lines of the commitment scheme:
	* "SAMPLE a random value r <- {0, 1}^n
	*	COMPUTE c = H(r,x) (c concatenated with r)".
	* @return the generated commitment.
	*
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
	* No pre-process is performed for Simple Hash Committer, therefore this function
	* returns empty vector.
	*/
	vector<shared_ptr<void>> getPreProcessValues() override {
		vector<shared_ptr<void>> empty;
		return empty;
	}

	/**
	* This function converts the given commit value to a byte array.
	* @param value
	* @return the generated bytes.
	*/
	vector<byte> generateBytesFromCommitValue(CmtCommitValue* value) override;
};

/**
* This class implements the receiver side of Simple Hash commitment.
*
* This is a commitment scheme based on hash functions. 
* It can be viewed as a random-oracle scheme, but its security can also be viewed as a standard assumption on modern hash functions.
* Note that computational binding follows from the standard collision resistance assumption. 
*
* The pseudo code of this protocol can be found in Protocol 3.6 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtSimpleHashReceiver : public CmtReceiver, public SecureCommit, public CmtOnByteArray {

	/*
	* runs the following protocol:
	* "Commit phase
	*		WAIT for a value c
	*		STORE c
	*	Decommit phase
	*		WAIT for (r, x)  from C
	*		IF NOT
	*			c = H(r,x), AND
	*			x <- {0, 1}^t
	*		      OUTPUT REJ
	*		ELSE
	*		      OUTPUT ACC and value x"
	*/

private:

	shared_ptr<CommParty> channel;
	shared_ptr<CryptographicHash> hash;
	int n; //security parameter.

	void doConstruct(const shared_ptr<CommParty> & channel, const shared_ptr<CryptographicHash> & hash, int n = 32);

public:
	/**
	* Constructor that receives a connected channel (to the receiver) and chosses default
	* values for the hash function, SecureRandom object and a security parameter n.
	*/
	CmtSimpleHashReceiver(const shared_ptr<CommParty> & channel) {
		doConstruct(channel, make_shared<OpenSSLSHA256>());
	}


	/**
	* Constructor that receives a connected channel (to the receiver), the hash function
	* agreed upon between them and a security parameter n.
	* The committer needs to be instantiated with the same DlogGroup, otherwise nothing will work properly.
	* @param channel
	* @param hash
	* @param n security parameter
	*
	*/
	CmtSimpleHashReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<CryptographicHash> & hash, int n = 32) {
		doConstruct(channel, hash, n);
	}

	/**
	* Run the commit phase of the protocol:
	* "WAIT for a value c
	*	STORE c".
	*/
	shared_ptr<CmtRCommitPhaseOutput> receiveCommitment() override;

	/**
	* Run the decommit phase of the protocol:
	* "WAIT for (r, x)  from C
	*	IF NOT
	*		c = H(r,x), AND
	*		x <- {0, 1}^t
	*		OUTPUT REJ
	*	ELSE
	*	  	OUTPUT ACC and value x".
	*/
	shared_ptr<CmtCommitValue> receiveDecommitment(long id) override;

	shared_ptr<CmtCommitValue> verifyDecommitment(CmtCCommitmentMsg* commitmentMsg, CmtCDecommitmentMessage* decommitmentMsg) override;

	/**
	* No pre-process is performed for Simple Hash Receiver, therefore this function returns null!
	*/
	vector<shared_ptr<void>> getPreProcessedValues() override {
		vector<shared_ptr<void>> empty;
		return empty;
	}

	/**
	* This function converts the given commit value to a byte array.
	* @param value
	* @return the generated bytes.
	*/
	vector<byte> generateBytesFromCommitValue(CmtCommitValue* value) override;
};

BOOST_SERIALIZATION_ASSUME_ABSTRACT(CmtCCommitmentMsg)
BOOST_SERIALIZATION_ASSUME_ABSTRACT(CmtCDecommitmentMessage)
