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
#include "RandomValue.hpp"
#include "../cryptoInfra/PlainText.hpp"
#include "../comm/Comm.hpp"

/**
* Abstract class of the receiver's output of the commit phase.
* All receivers have output from the commit phase, that at least includes the commitment id.
*/
class CmtRCommitPhaseOutput: public NetworkSerialized {
public:
	/**
	* Returns the id of the received commitment message.
	*/
	virtual long getCommitmentId() = 0;
};

/**
* Concrete class of receiver's output from the commit phase.
* In the basic case, the receiver outputs the id of the received commitment.
*/
class CmtRBasicCommitPhaseOutput : public CmtRCommitPhaseOutput {
protected:
	long commitmentId;
public:
	/**
	* Constructor that sets the given commitment id.
	*/
	CmtRBasicCommitPhaseOutput(long commitmentId) { this->commitmentId = commitmentId; };
	/**
	* Returns the id of the received commitment message.
	*/
	long getCommitmentId() override { return commitmentId; };
	// network serialization implementation:
	string toString() override { return to_string(commitmentId); }
	void initFromString(const string & s) { commitmentId = stol(s); }
};

/**
* Concrete class of receiver's output from the commit phase.
* In the trapdoor case, the receiver outputs the id of the received commitment and the trapdoor.
*/
class CmtRTrapdoorCommitPhaseOutput : public CmtRBasicCommitPhaseOutput {
private:
	biginteger trap;
public:
	CmtRTrapdoorCommitPhaseOutput() : CmtRTrapdoorCommitPhaseOutput(0, 0) {};
	/**
	* Constructor that sets the given commitment id.
	* @param trapdoor the receiver's trapdoor for this commitment.
	* @param commitmentId the id of the received commitment message.
	*/
	CmtRTrapdoorCommitPhaseOutput(const biginteger & trapdoor, long commitmentId) :
		CmtRBasicCommitPhaseOutput(commitmentId) {
		this->trap = trapdoor;
	};
	/**
	* Returns the trapdoor of this commitment.
	*/
	biginteger getTrap() { return trap; };
	
	// network serialization implementation:
	string toString() override {
		return to_string(commitmentId) + ':' + trap.str();
	}
	void initFromString(const string & raw) override {
		auto vec = explode(raw, ':');
		assert(vec.size() == 2);
		commitmentId = stol(vec[0]);
		trap = biginteger(vec[1]);
	};
};

/**
* Abstract class for commit value.
* Each commit value type (like BigInteger, Byte[], etc) should derive this class.
*/
class CmtCommitValue {
public:
	/**
	* The committed values can vary, therefore returns a void pointer
	* @return the committed value.
	*/
	virtual shared_ptr<void> getX() = 0;
	/**
	* Converts the committed value into a plaintext in order to encrypt it.
	* @return the plaintext contains this commit value.
	*/
	virtual shared_ptr<Plaintext> convertToPlaintext() = 0;

	virtual bool operator==(const CmtCommitValue & other) = 0;

	virtual string toString() = 0;
};

/**
* Concrete implementation of CommitValue where the committed value is a GroupElement.
*/
class CmtGroupElementCommitValue : public CmtCommitValue {
private:
	shared_ptr<GroupElement> x; // the committed value
public:
	/**
	* Constructor that sets the commit value.
	*/
	CmtGroupElementCommitValue(const shared_ptr<GroupElement> & x) { this->x = x; };
	/**
	* Returns the committed GroupElement. Client needs to cast result to GroupElement*
	*/
	shared_ptr<void> getX() override { return x; }
	/**
	* Converts the committed value to a GroupElementPlaintaxt.
	*/
	shared_ptr<Plaintext> convertToPlaintext() override {
		auto res = make_shared<GroupElementPlaintext>(x);
		return res; 
	};

	bool operator==(const CmtCommitValue & other) override {
		auto temp = dynamic_cast<const CmtGroupElementCommitValue*>(&other);
		if (temp == NULL) {
			throw invalid_argument("the given argument should be an instance of CmtGroupElementCommitValue");
		}
		return *x == *(temp->x);
	}

	string toString() override { return x->generateSendableData()->toString(); }
};

/**
* Abstract class of the committer's commit phase values.
* Classes derived this class will hold the value to commit,
* the computed commitment and the random values used for the computation.
*/
class CmtCommitmentPhaseValues {
private:
	// The random value used in the computation of the commitment for the specific commitval.
	shared_ptr<RandomValue> r;
	// The value that the committer commits about. This value is not sent to the receiver in the 
	// commitment phase, it is sent in the decommitment phase.
	shared_ptr<CmtCommitValue> x;
public:
	CmtCommitmentPhaseValues() {}
	CmtCommitmentPhaseValues(const shared_ptr<RandomValue> & r, const shared_ptr<CmtCommitValue> & x) : r(r), x(x){}
	
	/**
	* Returns the random value used for commit the value.
	*/
	shared_ptr<RandomValue> getR() { return r; }

	/**
	* Returns the committed value.
	*/
	shared_ptr<CmtCommitValue> getX() { return x; }

	/**
	* The commitment objects can be vary in the different commitment scheme.
	* Therefore, Returns a void pointer.
	*/
	virtual shared_ptr<void> getComputedCommitment()=0;
};

/**
* Concrete implementation of CommitValue where the committed value is a biginteger.
*/
class CmtBigIntegerCommitValue : public CmtCommitValue {
private:
	shared_ptr<biginteger> x; // the committed value

public:
	/**
	* Constructor that sets the commit value.
	* @param x BigInteger to commit on.
	*/
	CmtBigIntegerCommitValue(const shared_ptr<biginteger> & x) { this->x = x; };

	/**
	* Returns the committed BigInteger. Client should cast to biginteger.
	*/
	shared_ptr<void> getX() override { return x; };

	/**
	* Converts the committed value to a BigIntegerPlaintaxt.
	*/
	shared_ptr<Plaintext> convertToPlaintext() override {
		auto res = make_shared<BigIntegerPlainText>(*x);
		return res;
	};

	bool operator==(const CmtCommitValue & other) override {
		auto temp = dynamic_cast<const CmtBigIntegerCommitValue*>(&other);
		if (temp == NULL) {
			throw invalid_argument("the given argument should be an instance of CmtBigIntegerCommitValue");
		}
		return *x == *temp->x;
	}

	string toString() override { return  (*x).str(); }
};

/**
* Concrete implementation of CommitValue where the committed value is a vector<byte>.
*/
class CmtByteArrayCommitValue : public CmtCommitValue {
private:
	shared_ptr<vector<byte>> x; // the committed value. 
public:
	/**
	* Constructor that sets the commit value.
	*/
	CmtByteArrayCommitValue(const shared_ptr<vector<byte>> & x) { this->x = x; }
	/**
	* Returns the committed byte vector. client need to cast to byte vector
	*/
	shared_ptr<void> getX() override{ return x; }
	shared_ptr<vector<byte>> getXVector() { return x; }
	/**
	* Converts the committed value to a ByteArrayPlaintext.
	*/
	shared_ptr<Plaintext> convertToPlaintext() override {
		auto res = make_shared<ByteArrayPlaintext>(*x);
		return res;
	};

	bool operator==(const CmtCommitValue & other) override {
		auto temp = dynamic_cast<const CmtByteArrayCommitValue*>(&other);
		if (temp == NULL) {
			throw invalid_argument("the given argument should be an instance of CmtByteArrayCommitValue");
		}
		return *x == *(temp->x);
	}

	string toString() override {
		const byte * uc = &((*x)[0]);
		return string(reinterpret_cast<char const*>(uc), x->size());
	}

};

/**
* This class represents the commitment message sent from the committer to the receiver
* during the commitment phase.
* Every commitment has an id needed to identify the specific commitment in the case that many
* commitments are performed by the committer without decommiting in between the commitments.
* Each commitment has an id attached to it used lated for decommitment.
*/
class CmtCCommitmentMsg : public NetworkSerialized {
public:
	virtual ~CmtCCommitmentMsg(){}

	/**
	* Returns the unique id of the commitment.
	*/
	virtual long getId()=0;
	/**
	* The commitment objects can vary, therefore returns an void pointer.
	* @return the commitment object.
	*/
	virtual shared_ptr<void> getCommitment()=0;

	template<class Archive>
	void serialize(Archive & ar, const unsigned int version){}
};	

/**
* Abstract class for the decommitment message the committer sends to the receiver.
*/
class CmtCDecommitmentMessage : public NetworkSerialized{
public:
	virtual ~CmtCDecommitmentMessage(){}
	/**
	* Returns the random value used to commit.
	*/
	virtual shared_ptr<RandomValue> getR() = 0;
	virtual shared_ptr<void> getX() = 0;


	template<class Archive>
	void serialize(Archive & ar, const unsigned int version) {}
};

/**
* This is the general class of the Committer side of a Commitment Scheme.
* A commitment scheme has a commitment phase in which the committer send the commitment to the
* Receiver; and a decommitment phase in which the the Committer sends the decommitment to the Receiver.
*/
class CmtCommitter {
protected:
	shared_ptr<CommParty> channel;
	// The key to the map is an ID and the value is a structure that has the Committer's
	// private input x in Zq,the random value used to commit x and the actual commitment.
	// Each committed value is sent together with an ID so that the receiver can keep it in
	// some data structure. This is necessary in the cases that the same instances of committer
	// and receiver can be used for performing various commitments utilizing the values calculated
	// during the pre-process stage for the sake of efficiency.
	map<long, unique_ptr<CmtCommitmentPhaseValues>> commitmentMap;

public:
	/**
	* Generates a commitment message using the given input and ID.
	* There are cases when the user wants to commit the input but remain non-interactive,
	* meaning not to send the generate message yet.
	* The reasons for doing that are vary, for example the user wants to prepare a lot
	* of commitments and send together.
	* In these cases the commit function is not useful since it sends the generates commit message
	* to the other party. 
	* This function generates the message without sending it and this allows the user to save it
	* and send it later if he wants.
	* In case the commit phase is interactive, the commit message cannot be generated and an
	* IllegalStateException will be thrown.
	* In this case one should use the commit function instead.
	*
	* Code example: giving a committer object and an input,
	*
	* // create three commitment messages.
	* auto msg1 = generateCommitmentMsg(input, 1);
	* auto msg2 = generateCommitmentMsg(input, 2);
	* auto msg3 = generateCommitmentMsg(input, 3);
	* ...
	*
	* // Send the messages by the channel.
	* channel.write(msg1);
	* channel.write(msg2);
	* channel.write(msg3);
	*
	* @param input The value that the committer commits about.
	* @param r	The randomness used for the commitment on input
	* @param id Unique value attached to the input to keep track of the commitments in the case
	* that many commitments are performed one after the other without decommiting them yet.
	* @return the generated commitment object.
	*/

	virtual shared_ptr<CmtCCommitmentMsg> generateCommitmentMsg(const shared_ptr<CmtCommitValue> & input, biginteger r, long id) = 0;

	/*
	* This function returns the previous function with the randomness r randomly generated
	* @return the generated commitment object
	*/
	virtual shared_ptr<CmtCCommitmentMsg> generateCommitmentMsg(const shared_ptr<CmtCommitValue> & input, long id) = 0;

	/**
	* This function is the heart of the commitment phase from the Committer's point of view.
	* @param input The value that the committer commits about.
	* @param id Unique value attached to the input to keep track of the commitments in
	* the case that many commitments are performed one after the other without decommiting them yet.
	*/
	virtual void commit(const shared_ptr<CmtCommitValue> & input, long id) {
		auto msg = generateCommitmentMsg(input, id);
		try {
			auto msgStr = msg->toString();
			channel->writeWithSize(msgStr);
		}
		catch (...) {
			commitmentMap.erase(id);
		}
	}

	/**
	* Generate a decommitment message using the given id.
	*
	* There are cases when the user wants to decommit but remain non-interactive, meaning not to
	* send the generate message yet.
	* The reasons for doing that are vary, for example the user wants to prepare a lot of 
	* decommitments and send together.
	* In these cases the decommit function is not useful since it sends the generates decommit
	* message to the other party. 
	* This function generates the message without sending it and this allows the user to save it
	* and send it later if he wants.
	* In case the decommit phase is interactive, the decommit message cannot be generated and an 
	* IllegalStateException will be thrown.
	* In this case one should use the decommit function instead.
	*
	* Code example: giving a committer object and an input,
	*
	* //Create three commitment messages.
	* auto msg1 = generateDecommitmentMsg(1);
	* auto msg2 = generateDecommitmentMsg(2);
	* auto msg3 = generateDecommitmentMsg(3);
	* ...
	*
	* // Send the messages by the channel.
	* channel.write(msg1);
	* channel.write(msg2);
	* channel.write(msg3);
	*	
	* @param id Unique value attached to the input to keep track of the commitments in the case
	* that many commitments are performed one after the other without decommiting them yet.
	* @return the generated decommitment object.
	*/
	virtual shared_ptr<CmtCDecommitmentMessage> generateDecommitmentMsg(long id)=0;

	/**
	* This function is the heart of the decommitment phase from the Committer's point of view.
	* @param id Unique value used to identify which previously committed value needs to be decommitted now.
	*/
	virtual void decommit(long id) {
		// fetch the commitment according to the requested ID
		auto msg = generateDecommitmentMsg(id);
		auto bMsg = msg->toString();
		channel->writeWithSize(bMsg);
	}

	/**
	* This function samples random commit value to commit on.
	* @return the sampled commit value.
	*/
	virtual shared_ptr<CmtCommitValue> sampleRandomCommitValue() =0;

	/**
	* This function wraps the raw data x with a suitable CommitValue instance according to the
	* actual implementaion.
	* @param x array to convert into a commitValue.
	* @return the created CommitValue.
	*/
	virtual shared_ptr<CmtCommitValue> generateCommitValue(const vector<byte> & x) =0;

	/**
	* This function converts the given commit value to a byte array.
	* @param value to get its bytes.
	* @return the generated bytes.
	*/
	virtual vector<byte> generateBytesFromCommitValue(CmtCommitValue* value)=0;

	/**
	* This function returns the values calculated during the preprocess phase.<p>
	* This function is used for protocols that need values of the commitment,
	* like ZK protocols during proofs on the commitment.
	* We recommended not to call this function from somewhere else.
	* @return values calculated during the preprocess phase
	*/
	virtual vector<shared_ptr<void>> getPreProcessValues() = 0;
	
	/**
	* This function returns the values calculated during the commit phase for a specific commitment.
	* This function is used for protocols that need values of the commitment,
	* like ZK protocols during proofs on the commitment.
	* We recommended not to call this function from somewhere else.
	* @param id of the specific commitment
	* @return values calculated during the commit phase
	*/
	CmtCommitmentPhaseValues* getCommitmentPhaseValues(long id) {
		return commitmentMap[id].get();
	}
};

/**
* This the general class of the Receiver side of a Commitment Scheme. 
* A commitment scheme has a commitment phase in which the Receiver waits for the commitment
* sent by the Committer; and a decommitment phase in which the Receiver waits for the decommitment
* sent by the Committer and checks whether to accept or reject the decommitment.
*/
class CmtReceiver {
protected:
	// The committer may commit many values one after the other without decommitting.
	// And only at a later time decommit some or all those values. In order to keep track
	// of the commitments and be able to relate them afterwards to the decommitments we keep 
	// them in the commitmentMap. The key is some unique id known to the application
	// running the committer. The exact same id has to be use later on to decommit the 
	// corresponding values, otherwise the receiver will reject the decommitment.
	map<long, shared_ptr<CmtCCommitmentMsg>> commitmentMap;
public:
	/**
	* This function is the heart of the commitment phase from the Receiver's point of view.
	* @return the id of the commitment and some other information if necessary according to the 
	* implementing class.
	*/
	virtual shared_ptr<CmtRCommitPhaseOutput> receiveCommitment() = 0;

	/**
	* This function is the heart of the decommitment phase from the Receiver's point of view.
	* @param id wait for a specific message according to this id
	* @return the commitment
	*/
	virtual shared_ptr<CmtCommitValue> receiveDecommitment(long id) = 0;

	/**
	* Verifies the given decommitment object according to the given commitment object.
	*
	* There are cases when the committer sends the commitment and decommitments in the application,
	* and the receiver does not use the receiveCommitment and receiveDecommitment function.
	* In these cases this function should be called for each pair of commitment and decommitment
	* messages.
	* The reasons for doing that are vary, for example a protocol that prepare a lot of
	* commitments and send together.
	* In these cases the receiveCommitment and receiveDecommitment functions are not useful
	* since it receives the generates messages separately to the other party. 
	* This function generates the message without sending it and this allows the user to save
	* it and send it later if he wants.
	* In case the decommit phase is interactive, the decommit message cannot be generated 
	* and an IllegalStateException will be thrown.
	* In this case one should use the decommit function instead.
	*
	* Code example: giving a committer object and an input,
	*
	* //Create three commitment messages.
	* auto msg1 = generateDecommitmentMsg(1);
	* auto msg2 = generateDecommitmentMsg(2);
	* auto msg3 = generateDecommitmentMsg(3);
	* ...
	*
	* //Send the messages by the channel.
	* channel->writeWithSize(msg1);
	* channel->writeWithSize(msg2);
	* channel->writeWithSize(msg3);
	*
	* @param commitmentMsg the commitment object.
	* @param decommitmentMsg the decommitment object
	* @return the committed value if the decommit succeeded; null, otherwise.
	*/
	virtual shared_ptr<CmtCommitValue> verifyDecommitment(CmtCCommitmentMsg* commitmentMsg,
		CmtCDecommitmentMessage* decommitmentMsg) = 0;

	/**
	* Returns the values used during the pre-process phase (usually upon construction). 
	* Since these values vary between the different implementations this function
	* returns a general array of void pointers.
	*/
	virtual vector<shared_ptr<void>> getPreProcessedValues() = 0;

	/**
	* Returns the intermediate values used during the commitment phase.
	* @param id get the commitment values according to this id.
	* @return a general void pointer.
	*/
	virtual shared_ptr<void> getCommitmentPhaseValues(long id) {
		return commitmentMap[id];
	}

	/**
	* This function converts the given commit value to a byte array.
	* @param value to get its bytes.
	* @return a shared pointer to the generated bytes + the array size
	*/
	virtual vector<byte> generateBytesFromCommitValue(CmtCommitValue* value)=0;
};

/**
* This class is used by the committer to prove that:
* 1. The committer knows the committed value.
* 2. The committed value was x.
*
* All commitment scheme that have proofs should implement this interface.
*/
class CmtWithProofsCommitter : public virtual CmtCommitter{
public:
	/**
	* Proves that the committer knows the committed value.
	* @param id of the commitment message.
	*/
	virtual void proveKnowledge(long id) = 0;

	/**
	* Proves that the committed value with the given id was x.
	* @param id of the committed value.
	*/
	virtual void proveCommittedValue(long id) = 0;
};

/**
* This class is used by the verifier to verify that:
* 1. The committer knows the committed value.
* 2. The committed value was x.
* All commitment scheme that have proofs should implement this interface.
*/
class CmtWithProofsReceiver : public virtual CmtReceiver {
public:
	/**
	* Verifies that the committer knows the committed value.
	* @param id of the commitment message.
	*/
	virtual bool verifyKnowledge(long id) = 0;

	/**
	* Verifies that the committed value with the given id was x.
	* @param id of the committed value.
	*/
	virtual shared_ptr<CmtCommitValue> verifyCommittedValue(long id) = 0;
};

/**
* Marker class.
* Each committer/receiver that implement this interface is marked as committer/receiver
* that commit on a BigInteger.
*/
class CmtOnBigInteger {};

/**
* Marker class.
* Each committer/receiver that implement this interface is marked as committer/receiver
* that commit on a byte array.
*/
class CmtOnByteArray {};

/**
* Marker class.
* Each committer/receiver that implement this interface is marked as committer/receiver
* that commit on a GroupElement.
*/
class CmtOnGroupElement {};
