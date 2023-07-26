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


#include "../../include/interactive_mid_protocols/CommitmentSchemeSimpleHash.hpp"


/****************************************/
/*********** Commitment message *********/
/****************************************/
void CmtSimpleHashCommitmentMessage::initFromString(const string & s) {

    std::stringstream is(s, std::ios::binary | ios::out | ios::in);
    //read file and set obj
    boost::archive::binary_iarchive ia(is);
    ia >> boost::serialization::base_object<CmtCCommitmentMsg>(*this);
    ia >> c;
    ia >> id;

}

string CmtSimpleHashCommitmentMessage::toString() {
    //new scop - serialize need to flush
    std::stringstream os(std::ios::binary | ios::out | ios::in);
    {
        boost::archive::binary_oarchive oa(os);
        oa << boost::serialization::base_object<CmtCCommitmentMsg>(*this);
        oa << c;
        oa << id;
    }
    return os.str();
};

/****************************************/
/*********** Decommitment message *********/
/****************************************/
void CmtSimpleHashDecommitmentMessage::initFromString(const string & s) {

    std::stringstream is(s, std::ios::binary | ios::out | ios::in);
    //read file and set obj
    boost::archive::binary_iarchive ia(is);
    ia >> boost::serialization::base_object<CmtCDecommitmentMessage>(*this);
    ia >> x;
    ia >> r;
}

string CmtSimpleHashDecommitmentMessage::toString() {

    //new scop - serialize need to flush
    std::stringstream os(std::ios::binary | ios::out | ios::in);
    {
        boost::archive::binary_oarchive oa(os);
        oa << boost::serialization::base_object<CmtCDecommitmentMessage>(*this);
        oa << x;
        oa << r;
    }

    return os.str();
};

/**
* Constructor that receives a connected channel (to the receiver) and chosses default
* values for the hash function, SecureRandom object and a security parameter n.
*  @param channel
*/
CmtSimpleHashCommitter::CmtSimpleHashCommitter(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & prg, const shared_ptr<CryptographicHash> & hash, int n) {
	this->channel = channel;
	this->hash = hash;
	this->n = n;
	this->prg = prg;

	//No pre-process in SimpleHash Commitment
}

/**
* Runs the following lines of the commitment scheme:
* "SAMPLE a random value r <- {0, 1}^n
*	COMPUTE c = H(r,x) (c concatenated with r)".
* @return the generated commitment.
*
*/
shared_ptr<CmtCCommitmentMsg> CmtSimpleHashCommitter::generateCommitmentMsg(const shared_ptr<CmtCommitValue> & input, long id) {
	auto in = dynamic_pointer_cast<CmtByteArrayCommitValue>(input);
	if (in == NULL)
		throw invalid_argument("The input has to be of type CmtByteArrayCommitValue");
	auto x = in->getXVector();
	//Sample random byte array r
	vector<byte> r(n);
	prg->getPRGBytes(r, 0, n);

	//Compute the hash function
	auto hashValArray = make_shared<vector<byte>>(hash->getHashedMsgSize());
	hash->update(r, 0, r.size());
	hash->update(*x, 0, x->size());
	hash->hashFinal(*hashValArray, 0);

	//After succeeding in sending the commitment, keep the committed value in the map together with its ID.
	CmtSimpleHashCommitmentValues* tmp = new CmtSimpleHashCommitmentValues(make_shared<ByteArrayRandomValue>(r), input, hashValArray);
	commitmentMap[id].reset(tmp);

	return make_shared<CmtSimpleHashCommitmentMessage>(hashValArray, id);
}

shared_ptr<CmtCDecommitmentMessage> CmtSimpleHashCommitter::generateDecommitmentMsg(long id)  {
	//fetch the commitment according to the requested ID
	auto x = static_pointer_cast<vector<byte>>(commitmentMap[id]->getX()->getX());
	auto r = static_pointer_cast<ByteArrayRandomValue>(commitmentMap[id]->getR());
	return make_shared<CmtSimpleHashDecommitmentMessage>(r, x);
}

/**
* This function samples random commit value and returns it.
* @return the sampled commit value
*/
shared_ptr<CmtCommitValue> CmtSimpleHashCommitter::sampleRandomCommitValue() {
	vector<byte> val;
	prg->getPRGBytes(val, 0, 32);

	return make_shared<CmtByteArrayCommitValue>(make_shared<vector<byte>>(val));
}

/**
* This function converts the given commit value to a byte array.
* @param value
* @return the generated bytes.
*/
vector<byte> CmtSimpleHashCommitter::generateBytesFromCommitValue(CmtCommitValue* value) {
	auto val = dynamic_cast<CmtByteArrayCommitValue*>(value);
	if (val == NULL)
		throw invalid_argument("The given value must be of type CmtByteArrayCommitValue");
	return *val->getXVector();
}

void CmtSimpleHashReceiver::doConstruct(const shared_ptr<CommParty> & channel, const shared_ptr<CryptographicHash> & hash, int n) {
	this->channel = channel;
	this->hash = hash;
	this->n = n;
	
	//No pre-process in SimpleHash Commitment
}

/**
* Run the commit phase of the protocol:
* "WAIT for a value c
*	STORE c".
*/
shared_ptr<CmtRCommitPhaseOutput> CmtSimpleHashReceiver::receiveCommitment() {

	// create an empty CmtPedersenCommitmentMessage 
	auto msg = make_shared<CmtSimpleHashCommitmentMessage>();

	// read encoded CmtPedersenCommitmentMessage from channel
	vector<byte> raw_msg; // by the end of the scope - no need to hold it anymore - already decoded and copied
	channel->readWithSizeIntoVector(raw_msg);
	// init the empy CmtPedersenCommitmentMessage using the encdoed data
	msg->initFromByteVector(raw_msg);

	commitmentMap[msg->getId()] = msg;
	return make_shared<CmtRBasicCommitPhaseOutput>(msg->getId());
}

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
shared_ptr<CmtCommitValue> CmtSimpleHashReceiver::receiveDecommitment(long id) {
	//Receive the message from the committer.
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);
	auto msg = make_shared<CmtSimpleHashDecommitmentMessage>();
    msg->initFromByteVector(raw_msg);

	auto receivedCommitment = commitmentMap[id];
	auto cmtCommitMsg = static_pointer_cast<CmtCCommitmentMsg>(receivedCommitment);

	return verifyDecommitment(cmtCommitMsg.get(), msg.get());
}

shared_ptr<CmtCommitValue> CmtSimpleHashReceiver::verifyDecommitment(CmtCCommitmentMsg* commitmentMsg, CmtCDecommitmentMessage* decommitmentMsg) {
	auto decomMsg = dynamic_cast<CmtSimpleHashDecommitmentMessage*>(decommitmentMsg);
	if (decomMsg == NULL) {
		throw invalid_argument("the received message is not an instance of CmtSimpleHashDecommitmentMessage");
	}

	auto comMsg = dynamic_cast<CmtSimpleHashCommitmentMessage*>(commitmentMsg);
	if (comMsg == NULL) {
		throw invalid_argument("the received message is not an instance of CmtSimpleHashCommitmentMessage");
	}

	//Compute c = H(r,x)
	auto x = decomMsg->getXValue();
	auto r = decomMsg->getRArray();
	
	//create an array that will hold the concatenation of r with x
	hash->update(r, 0, r.size());
	hash->update(*x, 0, x->size());
	vector<byte> hashValArray(hash->getHashedMsgSize());
	hash->hashFinal(hashValArray, 0);

	//Checks that c = H(r,x)
    auto commitment = *comMsg->getCommitmentArray();
	if (commitment == hashValArray)
		return make_shared<CmtByteArrayCommitValue>(x);

    //In the pseudocode it says to return X and ACCEPT if valid commitment else, REJECT.
	//For now we return null as a mode of reject. If the returned value of this function is not null then it means ACCEPT
	return NULL;
}

/**
* This function converts the given commit value to a byte array.
* @param value
* @return the generated bytes.
*/
vector<byte> CmtSimpleHashReceiver::generateBytesFromCommitValue(CmtCommitValue* value)  {
	auto val = dynamic_cast<CmtByteArrayCommitValue*>(value);
	if (val == NULL)
		throw invalid_argument("The given value must be of type CmtByteArrayCommitValue");
	return *val->getXVector();
}