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


#include "../../include/interactive_mid_protocols/CommitmentSchemeElGamal.hpp"
#include "../../include/interactive_mid_protocols/SigmaProtocolElGamalCommittedValue.hpp"
#include "../../include/interactive_mid_protocols/SigmaProtocolElGamalCmtKnowledge.hpp"

/**
* Sets the given parameters and execute the preprocess phase of the scheme.
* @param channel
* @param dlog
* @param elGamal
* @param random
* @throws SecurityLevelException if the given dlog is not DDH secure
* @throws InvalidDlogGroupException if the given dlog is not valid.
* @throws IOException if there was a problem in the communication
*/
CmtElGamalCommitterCore::CmtElGamalCommitterCore(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, const shared_ptr<ElGamalEnc> & elGamal, const shared_ptr<PrgFromOpenSSLAES> & random) {
	//The underlying dlog group must be DDH secure.
	auto ddh = dynamic_pointer_cast<DDH>(dlog);
	if (ddh == NULL) {
		throw SecurityLevelException("DlogGroup should have DDH security level");
	}
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("");

	this->channel = channel;
	this->dlog = dlog;
	this->random = random;
	qMinusOne = dlog->getOrder() - 1;
	this->elGamal = elGamal;
	preProcess();
}

/**
* The pre-process is performed once within the construction of this object.
* If the user needs to generate new pre-process values then it needs to disregard
* this instance and create a new one.
* Runs the following lines from the pseudo code:
* "SAMPLE random values  a<- Zq
*	COMPUTE h = g^a"
* @throws IOException
*/
void CmtElGamalCommitterCore::preProcess() {
	//Instead of sample a and compute h, generate public and private keys directly.

	auto pair = elGamal->generateKey();
	//We keep both keys, the private key is used to prove knowledge of this commitment
	//but is not used by the encryption object.

	publicKey = dynamic_pointer_cast<ElGamalPublicKey>(pair.first);
	privateKey = dynamic_pointer_cast<ElGamalPrivateKey>(pair.second);
	elGamal->setKey(publicKey);

	//Send the public key to the receiver since throughout this connection the same key will be used used for all the commitments.
	channel->writeWithSize(publicKey->generateSendableData()->toString());
}

/**
* Computes the commitment object of the commitment scheme. <p>
* Pseudo code:<p>
* "SAMPLE random values  r <- Zq <p>
*	COMPUTE u = g^r and v = h^r * x". <p>
* @return the created commitment.
*/
shared_ptr<CmtCCommitmentMsg> CmtElGamalCommitterCore::generateCommitmentMsg(const shared_ptr<CmtCommitValue> & input, long id) {
	//Sample random r <-Zq.
	biginteger r = getRandomInRange(0, qMinusOne, random.get());
	//Compute u = g^r and v = h^r * x.
	//This is actually the encryption of x.
	auto c = elGamal->encrypt(input->convertToPlaintext(), r);
	//keep the committed value in the map together with its ID.
	CmtElGamalCommitmentPhaseValues* tmp = new CmtElGamalCommitmentPhaseValues(make_shared<BigIntegerRandomValue>(r), input, c);
	commitmentMap[id].reset(tmp);
	return make_shared<CmtElGamalCommitmentMessage>(dynamic_pointer_cast<AsymmetricCiphertextSendableData>(c->generateSendableData()), id);
}

shared_ptr<CmtCDecommitmentMessage> CmtElGamalCommitterCore::generateDecommitmentMsg(long id)  {

	//fetch the commitment according to the requested ID
	return make_shared<CmtElGamalDecommitmentMessage>(make_shared<string>(commitmentMap[id]->getX()->toString()), dynamic_pointer_cast<BigIntegerRandomValue>(commitmentMap[id]->getR()));
}

vector<shared_ptr<void>> CmtElGamalCommitterCore::getPreProcessValues() {
	vector<shared_ptr<void>> values;
	values.push_back(publicKey);
	values.push_back(privateKey);
	return values;
}

shared_ptr<CmtCCommitmentMsg> CmtElGamalOnGroupElementCommitter::generateCommitmentMsg(const shared_ptr<CmtCommitValue> & input, long id)  {
	auto in = dynamic_pointer_cast<CmtGroupElementCommitValue>(input);
	if (in == NULL)
		throw invalid_argument("The input must be of type CmtGroupElementCommitValue");
	return CmtElGamalCommitterCore::generateCommitmentMsg(input, id);
}

/**
* This function converts the given commit value to a byte array.
* @param value
* @return the generated bytes.
*/
vector<byte> CmtElGamalOnGroupElementCommitter::generateBytesFromCommitValue(CmtCommitValue* value) {
	auto val = dynamic_cast<CmtGroupElementCommitValue*>(value);
	if (val == NULL)
		throw invalid_argument("The given value must be of type CmtGroupElementCommitValue");
	return dlog->mapAnyGroupElementToByteArray(static_pointer_cast<GroupElement>(val->getX()).get());
}

/**
* Sets the given parameters and execute the preprocess phase of the scheme.
* @param channel
* @param dlog
* @param elGamal
*/
void CmtElGamalReceiverCore::doConstruct(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, const shared_ptr<ElGamalEnc> & elGamal) {
	//The underlying dlog group must be DDH secure.
	auto ddh = dynamic_pointer_cast<DDH>(dlog);
	if (ddh == NULL) {
		throw SecurityLevelException("DlogGroup should have DDH security level");
	}
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("");

	this->channel = channel;
	this->dlog = dlog;
	this->elGamal = elGamal;
	preProcess();
	elGamal->setKey(publicKey);
}

/**
* The pre-process is performed once within the construction of this object.
* If the user needs to generate new pre-process values then it needs to disregard
* this instance and create a new one.
*/
void CmtElGamalReceiverCore::preProcess() {
	ElGamalPublicKeySendableData publicKeySendableData(dlog->getGenerator()->generateSendableData());
	// read encoded CmtPedersenCommitmentMessage from channel
	vector<byte> raw_msg; // by the end of the scope - no need to hold it anymore - already decoded and copied
	channel->readWithSizeIntoVector(raw_msg);
	publicKeySendableData.initFromByteVector(raw_msg);
	publicKey = dynamic_pointer_cast<ElGamalPublicKey>(elGamal->reconstructPublicKey(&publicKeySendableData));
	//Set the public key from now on until the end of usage of this instance.
	auto h = publicKey->getH();
	if (!dlog->isMember(h.get()))
		throw CheatAttemptException("h element is not a member of the current DlogGroup");
}

/**
* Runs the commit phase of the commitment scheme.<p>
* Pseudo code:<p>
* "WAIT for a value c<p>
*	STORE c".
* @return the output of the commit phase.
*/
shared_ptr<CmtRCommitPhaseOutput> CmtElGamalReceiverCore::receiveCommitment()  {
	// create an empty CmtPedersenCommitmentMessage 
	auto msg = getCommitmentMsg();
	// read encoded CmtPedersenCommitmentMessage from channel
	vector<byte> raw_msg; // by the end of the scope - no need to hold it anymore - already decoded and copied
	channel->readWithSizeIntoVector(raw_msg);
	// init the empy CmtPedersenCommitmentMessage using the encdoed data
	msg->initFromByteVector(raw_msg);
	
	commitmentMap[msg->getId()] = msg;
	return make_shared<CmtRBasicCommitPhaseOutput>(msg->getId());
}

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
shared_ptr<CmtCommitValue> CmtElGamalReceiverCore::receiveDecommitment(long id) {
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);
	auto msg = make_shared<CmtElGamalDecommitmentMessage>();
	msg->initFromByteVector(raw_msg); 
	auto receivedCommitment = commitmentMap[id];
	return verifyDecommitment(receivedCommitment.get(), msg.get());
}

vector<shared_ptr<void>> CmtElGamalReceiverCore::getPreProcessedValues() {
	vector<shared_ptr<void>> keys;
	keys.push_back(publicKey);
	return keys;
}

shared_ptr<CmtElGamalCommitmentMessage> CmtElGamalOnGroupElementReceiver::getCommitmentMsg() {

	auto elementSendable1 = dlog->getGenerator()->generateSendableData();
	auto elementSendable2 = dlog->getGenerator()->generateSendableData();
	return make_shared<CmtElGamalCommitmentMessage>(make_shared<ElGamalOnGrElSendableData>(elementSendable1, elementSendable2));
}

/**
* Proccesses the decommitment phase.<p>
* "IF NOT<p>
*		u=g^r <p>
*		v = h^r * x<p>
*		x in G<p>
*		OUTPUT REJ<p>
*	ELSE<p>
*	    OUTPUT ACC and value x"<p>
* @param id the id of the commitment.
* @param msg the receiver message from the committer
* @return the committed value if the decommit succeeded; null, otherwise.
*/
shared_ptr<CmtCommitValue> CmtElGamalOnGroupElementReceiver::verifyDecommitment(CmtCCommitmentMsg* commitmentMsg,
	CmtCDecommitmentMessage* decommitmentMsg) {
	auto decom = dynamic_cast<CmtElGamalDecommitmentMessage*>(decommitmentMsg);
	auto com = dynamic_cast<CmtElGamalCommitmentMessage*>(commitmentMsg);
	if (decom == NULL) {
		throw invalid_argument("decommitmentMsg should be an instance of CmtElGamalDecommitmentMessage");
	}
	if (com == NULL) {
		throw invalid_argument("commitmentMsg should be an instance of CmtElGamalCommitmentMessage");
	}
	auto sendable = dlog->getGenerator()->generateSendableData();
	sendable->initFromString(decom->getXValue());
	auto xEl = dlog->reconstructElement(true, sendable.get());
	
	//First check if x is a group element in the current Dlog Group, if not return null meaning rejection:
	if (!dlog->isMember(xEl.get()))
		return NULL;

	auto commitment = static_pointer_cast<ElGamalOnGrElSendableData>(com->getCommitment());
	auto r = dynamic_pointer_cast<BigIntegerRandomValue>(decom->getR())->getR();
	//Fetch received commitment according to ID
	if (commitment == NULL)
		throw invalid_argument("commitment value is not an instance of ElGamalOnGrElSendableData");

	auto u = dlog->reconstructElement(true, commitment->getCipher1().get());
	auto v = dlog->reconstructElement(true, commitment->getCipher2().get());
	auto gToR = dlog->exponentiate(dlog->getGenerator().get(), r);
	auto hToR = dlog->exponentiate(publicKey->getH().get(), r);

	if ((*u == *gToR) && (*v == *dlog->multiplyGroupElements(hToR.get(), xEl.get())))
		return make_shared<CmtGroupElementCommitValue>(xEl);
	return NULL;
}

/**
* This function converts the given commit value to a byte array.
* @param value
* @return the generated bytes.
*/
vector<byte> CmtElGamalOnGroupElementReceiver::generateBytesFromCommitValue(CmtCommitValue* value) {
	auto tmp = dynamic_cast<CmtGroupElementCommitValue*>(value);
	if (tmp == NULL)
		throw invalid_argument("The given value must be of type CmtGroupElementCommitValue");
	return dlog->mapAnyGroupElementToByteArray(static_cast<GroupElement*>(tmp->getX().get()));
}

shared_ptr<CmtCCommitmentMsg> CmtElGamalOnByteArrayCommitter::generateCommitmentMsg(const shared_ptr<CmtCommitValue> & input, long id)  {
	auto in = dynamic_pointer_cast<CmtByteArrayCommitValue>(input);
	if (in == NULL)
		throw invalid_argument("The input must be of type CmtByteArrayCommitValue");
	return CmtElGamalCommitterCore::generateCommitmentMsg(input, id);
}

/**
* This function samples random commit value and returns it.
* @return the sampled commit value
*/
shared_ptr<CmtCommitValue> CmtElGamalOnByteArrayCommitter::sampleRandomCommitValue() {
	vector<byte> val(32);
	random->getPRGBytes(val, 0, 32);
	
	return make_shared<CmtByteArrayCommitValue>(make_shared<vector<byte>>(val));
}

/**
* This function converts the given commit value to a byte array.
* @param value
* @return the generated bytes.
*/
vector<byte> CmtElGamalOnByteArrayCommitter::generateBytesFromCommitValue(CmtCommitValue* value) {
	auto val = dynamic_cast<CmtByteArrayCommitValue*>(value);
	if (val == NULL)
		throw invalid_argument("The given value must be of type CmtByteArrayCommitValue");
	return *static_pointer_cast<vector<byte>>(val->getX());
}

shared_ptr<CmtElGamalCommitmentMessage> CmtElGamalOnByteArrayReceiver::getCommitmentMsg() {

	auto elementSendable1 = dlog->getGenerator()->generateSendableData();
	vector<byte> empty;
	return make_shared<CmtElGamalCommitmentMessage>(make_shared<ElGamalOnByteArraySendableData>(elementSendable1, empty));
}

/**
* Proccesses the decommitment phase.<p>
* "IF NOT<p>
*		u=g^r <p>
*		v = h^r * x<p>
*		x in G<p>
*		OUTPUT REJ<p>
*	ELSE<p>
*	    OUTPUT ACC and value x"<p>
* @param id the id of the commitment.
* @param msg the receiver message from the committer
* @return the committed value if the decommit succeeded; null, otherwise.
*/
shared_ptr<CmtCommitValue> CmtElGamalOnByteArrayReceiver::verifyDecommitment(CmtCCommitmentMsg* commitmentMsg,
	CmtCDecommitmentMessage* decommitmentMsg) {
	auto decommitment = dynamic_cast<CmtElGamalDecommitmentMessage*>(decommitmentMsg);
	auto com = dynamic_cast<CmtElGamalCommitmentMessage*>(commitmentMsg);
	if (decommitment == NULL) {
		throw invalid_argument("decommitmentMsg should be an instance of CmtElGamalDecommitmentMessage");
	}
	if (com == NULL) {
		throw invalid_argument("commitmentMsg should be an instance of CmtElGamalCommitmentMessage");
	}

	auto commitment = static_pointer_cast<ElGamalOnByteArraySendableData>(com->getCommitment());
	//Fetch received commitment according to ID
	if (commitment == NULL)
		throw invalid_argument("commitment value is not an instance of ElGamalOnByteArraySendableData");
	
	vector<byte> x;
	const string tmp = decommitment->getXValue();
	x.assign(tmp.begin(), tmp.end());
	
	size_t len = x.size();
	auto u = dlog->reconstructElement(true, commitment->getCipher1().get());
	auto v = commitment->getCipher2();
	
	if (len != v.size()) {
		return NULL;
	}
	
	auto r = dynamic_pointer_cast<BigIntegerRandomValue>(decommitment->getR())->getR();
	auto gToR = dlog->exponentiate(dlog->getGenerator().get(), r);
	auto hToR = dlog->exponentiate(publicKey->getH().get(), r);
	
	auto hToRBytes = dlog->mapAnyGroupElementToByteArray(hToR.get());
	auto c2 = kdf->deriveKey(hToRBytes, 0, hToRBytes.size(), len).getEncoded();
	
	//Xores the result from the kdf with the plaintext.
	for (size_t i = 0; i<len; i++) {
		c2[i] = (byte)(c2[i] ^ x[i]);
	}
	
	bool valid = *u == *gToR;
	
	for (size_t i = 0; i<len; i++) {
		valid = valid && (v[i] == c2[i]);
	}
	
	if (valid)
		return make_shared<CmtByteArrayCommitValue>(make_shared<vector<byte>>(x));
	return NULL;
}

/**
* This function converts the given commit value to a byte array.
* @param value
* @return the generated bytes.
*/
vector<byte> CmtElGamalOnByteArrayReceiver::generateBytesFromCommitValue(CmtCommitValue* value) {
	auto val = dynamic_cast<CmtByteArrayCommitValue*>(value);
	if (val == NULL)
		throw invalid_argument ("The given value must be of type CmtByteArrayCommitValue");
	return *static_pointer_cast<vector<byte>>(value->getX());
}

/**
* Creates the ZK provers using sigma protocols that prove Pedersen's proofs.
* @param t statistical parameter
* @throws IOException if there was a problem in the communication
*/
CmtElGamalWithProofsCommitter::CmtElGamalWithProofsCommitter(const shared_ptr<CommParty> & channel, int t, const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & prg) : CmtElGamalOnGroupElementCommitter(channel, dlog, prg) {
	auto elGamalCommittedValProver = make_shared<SigmaElGamalCommittedValueProverComputation>(dlog, t, prg);
	auto elGamalCTKnowledgeProver = make_shared<SigmaElGamalCmtKnowledgeProverComputation>(dlog, t, prg);
	knowledgeProver = make_shared<ZKPOKFromSigmaCmtPedersenProver>(channel, elGamalCTKnowledgeProver, dlog, prg);
	auto receiver = make_shared<CmtPedersenReceiver>(channel, dlog, prg);
	committedValProver = make_shared<ZKFromSigmaProver>(channel, elGamalCommittedValProver, receiver);

}

void CmtElGamalWithProofsCommitter::proveKnowledge(long id)  {
	auto keys = getPreProcessValues();
	auto publicKey = static_pointer_cast<ElGamalPublicKey>(keys[0]);
	auto privateKey = static_pointer_cast<ElGamalPrivateKey>(keys[1]);
	SigmaElGamalCmtKnowledgeProverInput input(*publicKey, privateKey->getX());
	knowledgeProver->prove(make_shared<SigmaElGamalCmtKnowledgeProverInput>(input));
}

void CmtElGamalWithProofsCommitter::proveCommittedValue(long id)  {
	//Send s1 to P2
	auto val = getCommitmentPhaseValues(id);
	//Send s1 to P2
	channel->writeWithSize(val->getX()->toString());

	auto keys = getPreProcessValues();
	auto publicKey = static_pointer_cast<ElGamalPublicKey>(keys[0]);
	auto commitment = static_pointer_cast<AsymmetricCiphertext>(val->getComputedCommitment())->generateSendableData();
	auto x = static_pointer_cast<GroupElement>(val->getX()->getX());
	auto r = static_pointer_cast<BigIntegerRandomValue>(val->getR())->getR();
	SigmaElGamalCommittedValueProverInput input(publicKey, static_pointer_cast<ElGamalOnGrElSendableData>(commitment), x, r);
	committedValProver->prove(make_shared<SigmaElGamalCommittedValueProverInput>(input));
}

/**
* Creates the ZK verifiers using sigma protocols that verifies ElGamal's proofs.
* @param t
* @throws IOException Creates the ZK provers using sigma protocols that prove Pedersen's proofs.
* @throws InvalidDlogGroupException if the given dlog is not valid.
* @throws CheatAttemptException if the receiver h is not in the DlogGroup.
* @throws ClassNotFoundException if there was a problem in the serialization
*/
CmtElGamalWithProofsReceiver::CmtElGamalWithProofsReceiver(const shared_ptr<CommParty> & channel, int t, const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & prg) : CmtElGamalOnGroupElementReceiver(channel, dlog) {
	auto elGamalCommittedValVerifier = make_shared<SigmaElGamalCommittedValueVerifierComputation>(dlog, t, prg);
	auto elGamalCTKnowledgeVerifier = make_shared<SigmaElGamalCmtKnowledgeVerifierComputation>(dlog, t, prg);
	auto output = make_shared<CmtRTrapdoorCommitPhaseOutput>();
	knowledgeVerifier = make_shared<ZKPOKFromSigmaCmtPedersenVerifier>(channel, elGamalCTKnowledgeVerifier, output, dlog, prg);
	auto committer = make_shared<CmtPedersenCommitter>(channel, dlog, prg);
	committedValVerifier = make_shared<ZKFromSigmaVerifier>(channel, elGamalCommittedValVerifier, committer, prg);

}

bool CmtElGamalWithProofsReceiver::verifyKnowledge(long id) {
	auto key = static_pointer_cast<ElGamalPublicKey>(getPreProcessedValues()[0]);
	SigmaElGamalCmtKnowledgeCommonInput input(*key);
	auto emptyA = make_shared<SigmaGroupElementMsg>(dlog->getGenerator()->generateSendableData());
	auto emptyZ = make_shared<SigmaBIMsg>();
	return knowledgeVerifier->verify(&input, emptyA, emptyZ);
}

shared_ptr<CmtCommitValue> CmtElGamalWithProofsReceiver::verifyCommittedValue(long id) {
	//Receive the committed value from the committer.
	// read biginteger from channel
	vector<byte> raw_msg; // by the end of the scope - no need to hold it anymore - already decoded and copied
	channel->readWithSizeIntoVector(raw_msg);
	auto sendable = dlog->getGenerator()->generateSendableData();
	sendable->initFromByteVector(raw_msg);
	auto committedVal = dlog->reconstructElement(true, sendable.get());
	
	//Creates input for the ZK verifier
	auto key = static_pointer_cast<ElGamalPublicKey>(getPreProcessedValues()[0]);
	auto commitmentVal = static_pointer_cast<CmtCCommitmentMsg>(getCommitmentPhaseValues(id));
	auto commitment = static_pointer_cast<ElGamalOnGrElSendableData>(commitmentVal->getCommitment());
	SigmaElGamalCommittedValueCommonInput input(key, commitment, committedVal);
	//Computes the verification.

	auto emptyA = make_shared<SigmaDHMsg>(dlog->getGenerator()->generateSendableData(), dlog->getGenerator()->generateSendableData());
	auto emptyZ = make_shared<SigmaBIMsg>();
	bool verified = committedValVerifier->verify(&input, emptyA, emptyZ);
	if (verified) 
		return make_shared<CmtGroupElementCommitValue>(committedVal);
	return NULL;
}