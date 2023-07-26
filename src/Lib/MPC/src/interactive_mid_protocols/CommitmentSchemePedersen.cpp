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


#include "../../include/interactive_mid_protocols/CommitmentSchemePedersen.hpp"
#include "../../include/interactive_mid_protocols/ZeroKnowledge.hpp"
#include "../../include/interactive_mid_protocols/SigmaProtocolPedersenCommittedValue.hpp"
#include "../../include/interactive_mid_protocols/SigmaProtocolPedersenCmtKnowledge.hpp"

/*********************************/
/*   CmtPedersenReceiverCore     */
/*********************************/
CmtPedersenReceiverCore::CmtPedersenReceiverCore(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random, const shared_ptr<DlogGroup> & dlog) {
	// the underlying dlog group must be DDH secure.
	auto ddh = dynamic_pointer_cast<DDH>(dlog);
	if (!ddh)
		throw SecurityLevelException("DlogGroup should have DDH security level");

	// validate the params of the group.
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("Group is not valid");

	this->channel = channel;
	this->dlog = dlog;
	this->random = random;
	qMinusOne = dlog->getOrder()-1;
	// the pre-process phase is actually performed at construction
	preProcess();
}

void CmtPedersenReceiverCore::preProcess() {
	if (channel == NULL) {
		throw runtime_error("In order to pre-compute the channel must be given");
	}
	trapdoor = getRandomInRange(0, qMinusOne, random.get());
	h = dlog->exponentiate(dlog->getGenerator().get(), trapdoor);
	auto sendableData = h->generateSendableData();	
	auto raw_msg = sendableData->toString();
	channel->writeWithSize(raw_msg);
}

shared_ptr<CmtRCommitPhaseOutput> CmtPedersenReceiverCore::receiveCommitment() {
	// create an empty CmtPedersenCommitmentMessage 
	auto msg = make_shared<CmtPedersenCommitmentMessage>(dlog->getGenerator()->generateSendableData());
	
	// read encoded CmtPedersenCommitmentMessage from channel
	vector<byte> raw_msg; // by the end of the scope - no need to hold it anymore - already decoded and copied
	channel->readWithSizeIntoVector(raw_msg);
	// init the empy CmtPedersenCommitmentMessage using the encdoed data
	msg->initFromByteVector(raw_msg);
	
	commitmentMap[msg->getId()] = msg;
	return make_shared<CmtRBasicCommitPhaseOutput>(msg->getId());
}

shared_ptr<CmtCommitValue> CmtPedersenReceiverCore::receiveDecommitment(long id) {
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);
	shared_ptr<CmtPedersenDecommitmentMessage> msg = make_shared<CmtPedersenDecommitmentMessage>();
	msg->initFromByteVector(raw_msg);
	auto receivedCommitment = commitmentMap[id];
	auto cmtCommitMsg = static_pointer_cast<CmtCCommitmentMsg>(receivedCommitment);
	return verifyDecommitment(cmtCommitMsg.get(), msg.get());
}

shared_ptr<CmtCommitValue> CmtPedersenReceiverCore::verifyDecommitment(CmtCCommitmentMsg* commitmentMsg,
	CmtCDecommitmentMessage* decommitmentMsg) {
	auto decommitmentMsgPedersen = dynamic_cast<CmtPedersenDecommitmentMessage*>(decommitmentMsg);
	if (decommitmentMsgPedersen == NULL) {
		throw invalid_argument("The received message should be an instance of CmtPedersenDecommitmentMessage");
	}
	auto commitmentMsgPedersen = dynamic_cast<CmtPedersenCommitmentMessage*>(commitmentMsg);
	if (commitmentMsgPedersen == NULL) {
		throw invalid_argument("The received message should be an instance of CmtPedersenCommitmentMessage");
	}
	biginteger x = decommitmentMsgPedersen->getXValue();
	biginteger r = decommitmentMsgPedersen->getRValue();

	// if x is not in Zq return null
	if (x<0 || x>dlog->getOrder()) 
		return NULL;
	// calculate c = g^r * h^x
	auto gTor = dlog->exponentiate(dlog->getGenerator().get(), r);
	auto hTox = dlog->exponentiate(h.get(), x);

	auto cmt = commitmentMsgPedersen->getCommitment();
	auto ge = static_pointer_cast<GroupElementSendableData>(cmt);
	auto commitmentElement = dlog->reconstructElement(true, ge.get());
	if (*commitmentElement == *(dlog->multiplyGroupElements(gTor.get(), hTox.get())))
		return make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(x));
	// in the pseudocode it says to return X and ACCEPT if valid commitment else, REJECT.
	// for now we return null as a mode of reject. If the returned value of this function is not
	// null then it means ACCEPT
	return NULL;
}

vector<shared_ptr<void>> CmtPedersenReceiverCore::getPreProcessedValues() {
	vector<shared_ptr<void>> values;
	values.push_back(h);
	return values;
}

shared_ptr<void> CmtPedersenReceiverCore::getCommitmentPhaseValues(long id) {
	auto voidPtr = commitmentMap[id]->getCommitment();
	auto ge = static_pointer_cast<GroupElementSendableData>(voidPtr);
	return dlog->reconstructElement(true, ge.get());
}

/*********************************/
/*   CmtPedersenCommitterCore    */
/*********************************/
CmtPedersenCommitterCore::CmtPedersenCommitterCore(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random,
	const shared_ptr<DlogGroup> & dlog) {
	// the underlying dlog group must be DDH secure.
	auto ddh = std::dynamic_pointer_cast<DDH>(dlog);
	if (!ddh)
		throw SecurityLevelException("DlogGroup should have DDH security level");
	// validate the params of the group.
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("");

	this->channel = channel;
	this->dlog = dlog;
	this->random = random;
	qMinusOne = dlog->getOrder()-1;
	// the pre-process phase is actually performed at construction
	preProcess();
}

void CmtPedersenCommitterCore::preProcess() {
	auto msg = waitForMessageFromReceiver();
	h = dlog->reconstructElement(true, msg.get());
	if (!dlog->isMember(h.get()))
		throw CheatAttemptException("h element is not a member of the current DlogGroup");
}

shared_ptr<GroupElementSendableData> CmtPedersenCommitterCore::waitForMessageFromReceiver() {
	if (channel == NULL) {
		throw runtime_error("In order to pre-compute the channel must be given");
	}
	vector<byte> rawMsg;
	channel->readWithSizeIntoVector(rawMsg);
	auto dummySendableData = dlog->getGenerator()->generateSendableData();
	dummySendableData->initFromByteVector(rawMsg);
	return dummySendableData;
}

shared_ptr<CmtCCommitmentMsg> CmtPedersenCommitterCore::generateCommitmentMsg(const shared_ptr<CmtCommitValue> & input, biginteger r, long id) {
	auto biCmt = dynamic_pointer_cast<CmtBigIntegerCommitValue>(input);
	if (!biCmt)
		throw invalid_argument("The input must be of type CmtBigIntegerCommitValue");

	shared_ptr<biginteger> x = static_pointer_cast<biginteger>(biCmt->getX());
	// check that the input is in Zq.
	if (*x < 0 || *x > dlog->getOrder())
		throw invalid_argument("The input must be in Zq");

	// check that the randomness r is in Zq
	if (r < 0 || r > dlog->getOrder())
		throw invalid_argument("The randomness must be in Zq");

	// compute  c = g^r * h^x
	auto gToR = dlog->exponentiate(dlog->getGenerator().get(), r);
	auto hToX = dlog->exponentiate(h.get(), *x);
	auto c = dlog->multiplyGroupElements(gToR.get(), hToX.get());

	// keep the committed value in the map together with its ID.
	auto sharedR = make_shared<BigIntegerRandomValue>(r);
	CmtPedersenCommitmentPhaseValues* tmp = new CmtPedersenCommitmentPhaseValues(sharedR, input, c);
	commitmentMap[id].reset(tmp);

	// send c
	return make_shared<CmtPedersenCommitmentMessage>(c->generateSendableData(), id);
}

shared_ptr<CmtCCommitmentMsg> CmtPedersenCommitterCore::generateCommitmentMsg(const shared_ptr<CmtCommitValue> & input, long id) {
	// sample a random value r <- Zq
	biginteger r = getRandomInRange(0, qMinusOne, random.get());

	return generateCommitmentMsg(input, r, id);
}

shared_ptr<CmtCDecommitmentMessage> CmtPedersenCommitterCore::generateDecommitmentMsg(long id) {
	auto cmtValue = commitmentMap[id]->getX();
	auto biCmt = dynamic_pointer_cast<CmtBigIntegerCommitValue>(cmtValue);
	auto x = static_pointer_cast<biginteger>(biCmt->getX());
	auto randomValuePtr = commitmentMap[id]->getR();
	auto biRVPtr = dynamic_pointer_cast<BigIntegerRandomValue>(randomValuePtr);
	return make_shared<CmtPedersenDecommitmentMessage>(x, biRVPtr);
}

vector<shared_ptr<void>> CmtPedersenCommitterCore::getPreProcessValues() {
	vector<shared_ptr<void>> values;
	values.push_back(h);
	return values;
}

/**********/
/* Helper */
/**********/
vector<byte> fromCmtToByteArray(CmtCommitValue* value) {
	biginteger x = *((biginteger *)value->getX().get());
	int size = bytesCount(x);
	vector<byte> byteRes(size);
	encodeBigInteger(x, byteRes.data(), size);
	return byteRes;
}

/*********************************/
/*   CmtPedersenCommitter        */
/*********************************/
vector<byte> CmtPedersenCommitter::generateBytesFromCommitValue(CmtCommitValue* value) {
	return fromCmtToByteArray(value);
}

/*********************************/
/*   CmtPedersenReceiver         */
/*********************************/
vector<byte> CmtPedersenReceiver::generateBytesFromCommitValue(CmtCommitValue* value) {
	return fromCmtToByteArray(value);
}

/********************************************/
/*   CmtPedersenWithProofsCommitter         */
/********************************************/
void CmtPedersenWithProofsCommitter::doConstruct(int t, const shared_ptr<PrgFromOpenSSLAES> & random) {
	auto pedersenCommittedValProver = make_shared<SigmaPedersenCommittedValueProverComputation>(dlog, t, random);
	auto pedersenCTKnowledgeProver = make_shared<SigmaPedersenCmtKnowledgeProverComputation>(dlog, t, random);
	knowledgeProver = make_shared<ZKPOKFromSigmaCmtPedersenProver>(channel, pedersenCTKnowledgeProver, dlog, random);
	committedValProver = make_shared<ZKPOKFromSigmaCmtPedersenProver>(channel, pedersenCommittedValProver, dlog, random);
}

void CmtPedersenWithProofsCommitter::proveKnowledge(long id)  {
	auto val = getCommitmentPhaseValues(id);
	auto h = static_pointer_cast<GroupElement>(getPreProcessValues()[0]);
	auto commitment = static_pointer_cast<GroupElement>(val->getComputedCommitment());
	biginteger x = *static_pointer_cast<biginteger>(val->getX()->getX());
	biginteger r = static_pointer_cast<BigIntegerRandomValue>(val->getR())->getR();
	SigmaPedersenCmtKnowledgeProverInput input(h, commitment, x, r);
	knowledgeProver->prove(make_shared<SigmaPedersenCmtKnowledgeProverInput>(input));
}

void CmtPedersenWithProofsCommitter::proveCommittedValue(long id) {
	auto val = getCommitmentPhaseValues(id);
	//Send s1 to P2
	channel->writeWithSize(val->getX()->toString());

	auto h = static_pointer_cast<GroupElement>(getPreProcessValues()[0]);
	auto commitment = static_pointer_cast<GroupElement>(val->getComputedCommitment());
	biginteger x = *static_pointer_cast<biginteger>(val->getX()->getX());
	biginteger r = static_pointer_cast<BigIntegerRandomValue>(val->getR())->getR();
	SigmaPedersenCommittedValueProverInput input(h, commitment, x, r);
	committedValProver->prove(make_shared<SigmaPedersenCommittedValueProverInput>(input));
}

/********************************************/
/*   CmtPedersenWithProofsReceiver         */
/********************************************/
void CmtPedersenWithProofsReceiver::doConstruct(int t, const shared_ptr<PrgFromOpenSSLAES> & prg) {
	auto pedersenCommittedValVerifier = make_shared<SigmaPedersenCommittedValueVerifierComputation>(dlog, t, prg);
	auto pedersenCTKnowledgeVerifier = make_shared<SigmaPedersenCmtKnowledgeVerifierComputation>(dlog, t, prg);
	auto output = make_shared<CmtRTrapdoorCommitPhaseOutput>();
	knowledgeVerifier = make_shared<ZKPOKFromSigmaCmtPedersenVerifier>(channel, pedersenCTKnowledgeVerifier, output, dlog, prg);
	committedValVerifier = make_shared<ZKPOKFromSigmaCmtPedersenVerifier>(channel, pedersenCommittedValVerifier, output, dlog, prg);
}

bool CmtPedersenWithProofsReceiver::verifyKnowledge(long id) {
	auto commitmentVal = getCommitmentPhaseValues(id);

	auto h = static_pointer_cast<GroupElement>(getPreProcessedValues()[0]);
	auto commitment = static_pointer_cast<GroupElement>(commitmentVal);
	SigmaPedersenCmtKnowledgeCommonInput input(h, commitment);

	auto emptyA = make_shared<SigmaGroupElementMsg>(dlog->getGenerator()->generateSendableData());
	auto emptyZ = make_shared<SigmaPedersenCmtKnowledgeMsg>(0,0);
	return knowledgeVerifier->verify(&input, emptyA, emptyZ);
}

shared_ptr<CmtCommitValue> CmtPedersenWithProofsReceiver::verifyCommittedValue(long id) {
	// read biginteger from channel
	vector<byte> raw_msg; // by the end of the scope - no need to hold it anymore - already decoded and copied
	channel->readWithSizeIntoVector(raw_msg);

	// init the empy CmtPedersenCommitmentMessage using the encdoed data
	const byte * uc = &(raw_msg[0]);
	string s(reinterpret_cast<char const*>(uc), raw_msg.size());
	biginteger x = biginteger(s);

	auto commitmentVal = getCommitmentPhaseValues(id);
	auto h = static_pointer_cast<GroupElement>(getPreProcessedValues()[0]);
	auto commitment = static_pointer_cast<GroupElement>(commitmentVal);
	SigmaPedersenCommittedValueCommonInput input(h, commitment, x);
	
	auto emptyA = make_shared<SigmaGroupElementMsg>(dlog->getGenerator()->generateSendableData());
	auto emptyZ = make_shared<SigmaBIMsg>();
	bool verified = committedValVerifier->verify(&input, emptyA, emptyZ);
	if (verified)
		return make_shared<CmtBigIntegerCommitValue>(make_shared<biginteger>(x));
	return NULL;
	
}

