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


#include "../../include/interactive_mid_protocols/ZeroKnowledge.hpp"
#include <boost/algorithm/string/replace.hpp>


/************************************************/
/*   ZKFromSigmaProver                          */
/************************************************/

ZKFromSigmaProver::ZKFromSigmaProver(const shared_ptr<CommParty> & channel,
	const shared_ptr<SigmaProverComputation> & sProver, const shared_ptr<CmtReceiver> & receiver) {
	// receiver must be an instance of PerfectlyHidingCT
	auto perfectHidingReceiver = dynamic_pointer_cast<PerfectlyHidingCmt>(receiver);
	if (!perfectHidingReceiver) 
		throw SecurityLevelException("the given CTReceiver must be an instance of PerfectlyHidingCmt");
	// receiver must be a commitment scheme on ByteArray or on BigInteger
	auto onBigIntegerReceiver = dynamic_pointer_cast<CmtOnBigInteger>(receiver);
	auto onByteArrayReceiver = dynamic_pointer_cast<CmtOnByteArray>(receiver);
	if (!onBigIntegerReceiver && !onByteArrayReceiver) 
		throw invalid_argument("the given receiver must be a commitment scheme on ByteArray or on BigInteger");

	this->sProver = sProver;
	this->receiver = receiver;
	this->channel = channel;
}

void ZKFromSigmaProver::prove(const shared_ptr<ZKProverInput> & input) {
	// the given input must be an instance of SigmaProtocolInput.
	auto sigmaProverInput = std::dynamic_pointer_cast<SigmaProverInput>(input);
	if (!sigmaProverInput) 
		throw invalid_argument("the given input must be an instance of SigmaProverInput");

	// run the receiver in COMMIT.commit 
	auto output = receiveCommit();
	// compute the first message a in sigma, using (x,w) as input and 
	// send a to V
	processFirstMsg(sigmaProverInput);
	// run the receiver in COMMIT.decommit 
	// if decommit returns INVALID output ERROR (CHEAT_ATTEMPT_BY_V)
	auto e = receiveDecommit(output->getCommitmentId());
	// IF decommit returns some e, compute the response z to (a,e) according to sigma, 
	// Send z to V and output nothing
	processSecondMsg(e.data(), e.size());
}

/************************************************/
/*   ZKFromSigmaVerifier                        */
/************************************************/

ZKFromSigmaVerifier::ZKFromSigmaVerifier(const shared_ptr<CommParty> & channel,
    const shared_ptr<SigmaVerifierComputation> & sVerifier, const shared_ptr<CmtCommitter> & committer,
	const shared_ptr<PrgFromOpenSSLAES> & random) {
	// committer must be an instance of PerfectlyHidingCT
	auto perfectHidingCommiter = std::dynamic_pointer_cast<PerfectlyHidingCmt>(committer);
	if (!perfectHidingCommiter) 
		throw SecurityLevelException("the given CTCommitter must be an instance of PerfectlyHidingCmt");
	
	// receiver must be a commitment scheme on ByteArray or on BigInteger
	auto onBigIntegerCommitter = std::dynamic_pointer_cast<CmtOnBigInteger>(committer);
	auto onByteArrayCommitter = std::dynamic_pointer_cast<CmtOnByteArray>(committer);
	if (!onBigIntegerCommitter && !onByteArrayCommitter) 
		throw invalid_argument("the given committer must be a commitment scheme on ByteArray or on BigInteger");

	this->sVerifier = sVerifier;
	this->committer = committer;
	this->channel = channel;
	this->random = random;
}

bool ZKFromSigmaVerifier::verify(ZKCommonInput* input, const shared_ptr<SigmaProtocolMsg> & emptyA, const shared_ptr<SigmaProtocolMsg> & emptyZ) {
	// the given input must be an instance of SigmaProtocolInput.
	auto sigmaCommonInput = dynamic_cast<SigmaCommonInput*>(input);
	if (!sigmaCommonInput)
		throw invalid_argument("the given input must be an instance of SigmaCommonInput");

	// sample a random challenge  e <- {0, 1}^t 
	sVerifier->sampleChallenge();
	auto e = sVerifier->getChallenge();
	// run COMMIT.commit as the committer with input e
	long id = commit(e);
	// wait for a message a from P
	receiveMsgFromProver(emptyA.get());
	// run COMMIT.decommit as the decommitter
	decommit(id);
	// wait for a message z from P, 
	// if transcript (a, e, z) is accepting in sigma on input x, output ACC
	// else outupt REJ
	return proccessVerify(sigmaCommonInput, emptyA.get(), emptyZ.get());
}

void ZKFromSigmaVerifier::receiveMsgFromProver(SigmaProtocolMsg* concreteMsg) {
	vector<byte> rawMsg;
	channel->readWithSizeIntoVector(rawMsg);
	concreteMsg->initFromByteVector(rawMsg);
}

/************************************************/
/*   ZKPOKFromSigmaCmtPedersenProver            */
/************************************************/

void ZKPOKFromSigmaCmtPedersenProver::prove(const shared_ptr<ZKProverInput> & input) {
	// the given input must be an instance of SigmaProverInput.
	auto sigmaProverInput = dynamic_pointer_cast<SigmaProverInput>(input);
	if (!sigmaProverInput)
		throw invalid_argument("the given input must be an instance of SigmaProverInput");

	// run the receiver in TRAP_COMMIT.commit 
	auto trap = receiveCommit();
	auto trapR = dynamic_pointer_cast<CmtRTrapdoorCommitPhaseOutput>(trap);
	// compute the first message a in sigma, using (x,w) as input and 
	// send a to V
	processFirstMsg(sigmaProverInput);
	// run the receiver in TRAP_COMMIT.decommit 
	// if decommit returns INVALID output ERROR (CHEAT_ATTEMPT_BY_V)
	auto e = receiveDecommit(trap->getCommitmentId());
	// if decommit returns some e, compute the response z to (a,e) according to sigma, 
	// send z to V and output nothing
	processSecondMsg(e, trap);

}

void ZKPOKFromSigmaCmtPedersenProver::processSecondMsg(const vector<byte> & e, const shared_ptr<CmtRCommitPhaseOutput> & trap) {
	// compute the second message by the underlying proverComputation.
	auto z = sProver->computeSecondMsg(e);

	// send the second message.
	auto raw_z = z->toString();
	sendMsgToVerifier(raw_z);

	// send the trap.
	auto raw_trap = trap->toString();
	sendMsgToVerifier(raw_trap);
}



/************************************************/
/*   ZKPOKFromSigmaCmtPedersenVerifier          */
/************************************************/
bool ZKPOKFromSigmaCmtPedersenVerifier::verify(ZKCommonInput* input, 
	const shared_ptr<SigmaProtocolMsg> & emptyA, const shared_ptr<SigmaProtocolMsg> & emptyZ) {
	// the given input must be an instance of SigmaProtocolInput.
	auto sigmaCommonInput = dynamic_cast<SigmaCommonInput*>(input);
	if (!sigmaCommonInput) 
		throw invalid_argument("the given input must be an instance of SigmaCommonInput");
	
	// sample a random challenge  e <- {0, 1}^t 
	sVerifier->sampleChallenge();
	auto e = sVerifier->getChallenge();
	//the challenge should be a positive number.
	if (decodeBigInteger(e.data(), e.size()) < 0) {
		encodeBigInteger(abs(decodeBigInteger(e.data(), e.size())), e.data(), e.size());
		sVerifier->setChallenge(e);
	}
		
	// run TRAP_COMMIT.commit as the committer with input e,
	long id = commit(e);
	
	// wait for a message a from P
	receiveMsgFromProver(emptyA.get());
	
	// run COMMIT.decommit as the decommitter
	committer->decommit(id);
	
	bool valid = true;

	// wait for a message z from P
	receiveMsgFromProver(emptyZ.get());
	// wait for trap from P
	receiveTrapFromProver(trap.get());
	
	// run TRAP_COMMIT.valid(T,trap), where T is the transcript from the commit phase
	valid = valid && committer->validate(trap);
	
	// run transcript (a, e, z) is accepting in sigma on input x
	valid = valid && sVerifier->verify(sigmaCommonInput, emptyA.get(), emptyZ.get());
	

	// if decommit and sigma verify returned true, return ACCEPT. Else, return REJECT.
	return valid;
}

/**
* Runs COMMIT.commit as the committer with input e.
*/
long ZKPOKFromSigmaCmtPedersenVerifier::commit(const vector<byte> & e) {
	auto val = committer->generateCommitValue(e);
	auto id = random->getRandom64();
	committer->commit(val, id);
	return id;
};
/**
* Waits for a message a from the prover.
* @return the received message
*/
void ZKPOKFromSigmaCmtPedersenVerifier::receiveMsgFromProver(SigmaProtocolMsg* emptyMsg) {
	vector<byte> rawMsg;
	channel->readWithSizeIntoVector(rawMsg);
	emptyMsg->initFromByteVector(rawMsg);
};

/**
* Waits for a trapdoor a from the prover.
*/
void ZKPOKFromSigmaCmtPedersenVerifier::receiveTrapFromProver(CmtRCommitPhaseOutput* emptyOutput) {
	vector<byte> rawMsg;
	channel->readWithSizeIntoVector(rawMsg);
	emptyOutput->initFromByteVector(rawMsg);
}

void ZKPOKFiatShamirProof::initFromString(const string & row) {

	auto str_vec = explode(row, ':');
	//recover a
	int xSize = atoi(str_vec[0].c_str());
	int i = 2;
	for (; (int) str_vec[1].size() != xSize; i++) {
		str_vec[1] += ":";
		str_vec[1] += str_vec[i];
	}
	a->initFromString(str_vec[1]);
	
	//recover e
	e = vector<byte>(str_vec[i].size());
	e.assign(str_vec[i].begin(), str_vec[i].end());
	
	i++;
	//recover z
	int zSize = atoi(str_vec[i++].c_str());
	for (int k = i + 1; (int) str_vec[i].size() != zSize; k++) {
		str_vec[i] += ":";
		str_vec[i] += str_vec[k];
	}
	z->initFromString(str_vec[i]);
}

string ZKPOKFiatShamirProof::toString() {
	string output = "";
	//print a
	auto aString = a->toString();
	output += to_string(aString.size());
	output += ":";
	output += aString;
	output += ":";

	//print e
    string eString = string(reinterpret_cast<char const*>(e.data()), e.size());
    boost::replace_all(eString, ":", "+");
	output += eString;
	output += ":";

	//print z
	auto zString = z->toString();
	output += to_string(zString.size());
	output += ":";
	output += zString;

	return output;
}

/**
* Run the following line from the protocol:
* "COMPUTE e=H(x,a,cont)".
* @param input
* @param a first message of the sigma protocol.
* @return the computed challenge
* @throws IOException
*/
vector<byte> ZKPOKFiatShamirFromSigmaProver::computeChallenge(ZKPOKFiatShamirProverInput* input, SigmaProtocolMsg* a) {
	//The input to the random oracle should include the common data of the prover 
	//and verifier, and not the prover's private input.
	auto inputString = input->getSigmaInput()->getCommonInput()->toString();
	vector<byte> inputArray(inputString.begin(), inputString.end());

	auto msgString = a->toString();
	vector<byte> messageArray(msgString.begin(), msgString.end());

	auto cont = input->getContext();
    string str1(cont.begin(), cont.end());

    vector<byte> inputToRO;

	if (cont.size() != 0) {
		inputToRO.resize(inputArray.size() + messageArray.size() + cont.size());
		memcpy(inputToRO.data() + inputArray.size() + messageArray.size(), cont.data(), cont.size());
	}
	else {
		inputToRO.resize(inputArray.size() + messageArray.size());
	}
	memcpy(inputToRO.data(), inputArray.data(), inputArray.size());
	memcpy(inputToRO.data() + inputArray.size(), messageArray.data(), messageArray.size());

	int outLen = sProver->getSoundnessParam() / 8;
	vector<byte> output(outLen);
	ro->compute(inputToRO, 0, inputToRO.size(), output, outLen);

    string str(output.begin(), output.end());

	return output;
}

/**
* Sends the given message to the verifier.
* @param message to send to the verifier.
* @throws IOException if failed to send the message.
*/
void ZKPOKFiatShamirFromSigmaProver::sendMsgToVerifier(ZKPOKFiatShamirProof & msg) {
	auto msgStr = msg.toString();
	channel->writeWithSize(msgStr);
}

/**
* Runs the prover side of the Zero Knowledge proof.
* @param input can be an instance of ZKPOKFiatShamirInput that holds
* 				input for the underlying sigma protocol and possible context information cont;
* 				Or input for the underlying Sigma prover.
* @throws IllegalArgumentException if the given input is not an instance of ZKPOKFiatShamirProverInput or SigmaProverInput.
* @throws IOException if failed to send the message.
* @throws CheatAttemptException if the prover suspects the verifier is trying to cheat.
*/
void ZKPOKFiatShamirFromSigmaProver::prove(const shared_ptr<ZKProverInput> & input) {
	ZKPOKFiatShamirProof msg = generateFiatShamirProof(input);
	
	//Send (a,e,z) to V and output nothing.
	sendMsgToVerifier(msg);
}

/**
* Let (a,e,z) denote the prover1, verifier challenge and prover2 messages of the sigma protocol.<p>
* This function computes the following calculations:<p>
*
*		 COMPUTE the first message a in sigma, using (x,w) as input<p>
*		 COMPUTE e=H(x,a,cont)<p>
*		 COMPUTE the response z to (a,e) according to sigma<p>
*		 RETURN (a,e,z)<p>
* @param input can be an instance of ZKPOKFiatShamirInput that holds
* 				input for the underlying sigma protocol and possible context information cont;
* 				Or input for the underlying Sigma prover.
* @return ZKPOKFiatShamirMessage holds (a, e, z).
* @throws CheatAttemptException if the prover suspects the verifier is trying to cheat.
* @throws IOException if failed to send the message.
*/
ZKPOKFiatShamirProof ZKPOKFiatShamirFromSigmaProver::generateFiatShamirProof(const shared_ptr<ZKProverInput> & input) {
	//The given input must be an instance of ZKPOKFiatShamirProverInput that holds input for the underlying sigma protocol 
	//and possible context information cont.
	auto sigmaInput = dynamic_pointer_cast<SigmaProverInput>(input);
	auto fsInput = dynamic_pointer_cast<ZKPOKFiatShamirProverInput>(input);
	if (fsInput == nullptr && sigmaInput == nullptr) {
		throw invalid_argument("the given input must be an instance of ZKPOKFiatShamirProverInput or SigmaProverInput");
	}


	vector<byte> vec;

	if (sigmaInput != nullptr) {
		fsInput = make_shared<ZKPOKFiatShamirProverInput>(sigmaInput, vec);
	}

	//Compute the first message a in sigma, using (x,w) as input and 
	auto a = sProver->computeFirstMsg(fsInput->getSigmaInput());

	//Compute e=H(x,a,cont)
	auto e = computeChallenge(fsInput.get(), a.get());
	
	//Compute the response z to (a,e) according to sigma
	auto z = sProver->computeSecondMsg(e);
	
	//return (a,e,z).
	return ZKPOKFiatShamirProof(a, e, z);
}

/**
* Waits for a message a from the prover.
* @return the received message
* @throws ClassNotFoundException
* @throws IOException if failed to send the message.
*/
shared_ptr<ZKPOKFiatShamirProof> ZKPOKFiatShamirFromSigmaVerifier::receiveMsgFromProver(const shared_ptr<SigmaProtocolMsg> & emptyA, const shared_ptr<SigmaProtocolMsg> & emptyZ) {
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);


	vector<byte> vec;
	// create an empty OTRGroupElementPairMsg and initialize it with the received data. 
	auto msg = make_shared<ZKPOKFiatShamirProof>(emptyA, vec, emptyZ);
	msg->initFromByteVector(raw_msg);

	return msg;
}

/**
* Run the following line from the protocol:
* "COMPUTE e=H(x,a,cont)".
* @param input
* @param a first message of the sigma protocol.
* @return the computed challenge
* @throws IOException
*/
vector<byte> ZKPOKFiatShamirFromSigmaVerifier::computeChallenge(ZKPOKFiatShamirCommonInput* input, SigmaProtocolMsg* a) {
	//The input to the random oracle should include the common data of the prover 
	//and verifier, and not the prover's private input.
	auto inputString = input->getSigmaInput()->toString();
	vector<byte> inputArray(inputString.begin(), inputString.end());
	
	auto msgString = a->toString();

	vector<byte> messageArray(msgString.begin(), msgString.end());
	
	auto cont = input->getContext();
    string str1(cont.begin(), cont.end());



	vector<byte> inputToRO;

	if (cont.size() != 0) {
		inputToRO.resize(inputArray.size() + messageArray.size() + cont.size());
		memcpy(inputToRO.data() + inputArray.size() + messageArray.size(), cont.data(), cont.size());
	}
	else {
		inputToRO.resize(inputArray.size() + messageArray.size());
	}
	memcpy(inputToRO.data(), inputArray.data(), inputArray.size());
	memcpy(inputToRO.data() + inputArray.size(), messageArray.data(), messageArray.size());
	
	int outLen = sVerifier->getSoundnessParam() / 8;
	vector<byte> output(outLen);
	ro->compute(inputToRO, 0, inputToRO.size(), output, outLen);

    string str(output.begin(), output.end());

	return output;
}

/**
* Verifies the proof.
* @param input2
* @param a first message from prover.
* @throws IOException if failed to send the message.
* @throws ClassNotFoundException
*/
bool ZKPOKFiatShamirFromSigmaVerifier::proccessVerify(SigmaCommonInput* input, SigmaProtocolMsg* a, const vector<byte> & challenge, SigmaProtocolMsg* z) {
	//If transcript (a, e, z) is accepting in sigma on input x, output ACC
	//Else outupt REJ

	sVerifier->setChallenge(challenge);

	return sVerifier->verify(input, a, z);
}

/**
* Runs the verifier side of the Zero Knowledge proof.
* @param input can be an instance of ZKPOKFiatShamirInput that holds
* 				input for the underlying sigma protocol and possible context information cont;
* 				Or input for the underlying sigma protocol.
* @throws IOException if failed to send the message.
* @throws ClassNotFoundException if there was a problem with the serialization mechanism.
*/
bool ZKPOKFiatShamirFromSigmaVerifier::verify(ZKCommonInput* input, const shared_ptr<SigmaProtocolMsg> & emptyA, const shared_ptr<SigmaProtocolMsg> & emptyZ) {
	//Wait for a message a from P
	auto msg = receiveMsgFromProver(emptyA, emptyZ);
	
	//verify the proof.
	return verifyFiatShamirProof(input, msg.get());
}

/**
* Verifies Fiat Shamir proof.<p>
* Let (a,e,z) denote the prover1, verifier challenge and prover2 messages of the sigma protocol.<p>
* This function computes the following calculations:<p>
*
*		IF<p>
*				e=H(x,a,cont), AND<p>
*				Transcript (a, e, z) is accepting in sigma on input x<p>
*     		OUTPUT ACC<p>
*     ELSE<p>
*          OUTPUT REJ<p>
* @param input can be an instance of ZKPOKFiatShamirInput that holds
* 				input for the underlying sigma protocol and possible context information cont;
* 				Or input for the underlying sigma protocol.
* @param msg Fiat Shamir proof received from the prover.
* @return true if the proof is valid; false, otherwise.
* @throws IOException if there was problem with the serialization of the data on order to achieve a challenge.
* @throws IllegalArgumentException if the given input is not an instance of ZKPOKFiatShamirInput or SigmaCommonInput.
*/
bool ZKPOKFiatShamirFromSigmaVerifier::verifyFiatShamirProof(ZKCommonInput* input, ZKPOKFiatShamirProof* msg) {	
	//The given input must be an instance of ZKPOKFiatShamirCommonInput that holds input for the underlying sigma protocol 
	//and possible context information cont.
	auto sigmaInput = dynamic_cast<SigmaCommonInput*>(input);
	auto fsInput = dynamic_cast<ZKPOKFiatShamirCommonInput*>(input);
	if (fsInput == nullptr && sigmaInput == nullptr) {
		throw invalid_argument("the given input must be an instance of ZKPOKFiatShamirCommonInput or SigmaCommonInput");
	}
	if (sigmaInput != nullptr) {
		vector<byte> vec;
		fsInput = new ZKPOKFiatShamirCommonInput(sigmaInput,vec);
	}

	//get the given a
	auto a = msg->getA();

	//Compute e=H(x,a,cont)
	auto computedE = computeChallenge(fsInput, a.get());
    auto fixedComputedE = computedE;

    string eString = string(reinterpret_cast<char const*>(computedE.data()), computedE.size());
    boost::replace_all(eString, ":", "+");


    fixedComputedE.assign(eString.begin(), eString.end());


    //get the given challenge.
	auto receivedE = msg->getE();

	//check that e=H(x,a,cont):
	bool valid = true;
	//In case that lengths of computed e and received e are not the same, set valid to false.
	if (fixedComputedE.size() != receivedE.size()) {
		valid = false;
	}
	
	//In case that  computed e and received e are not the same, set valid to false.
	for (int i = 0; i< (int) fixedComputedE.size(); i++) {
		if (fixedComputedE[i] != receivedE[i]) {
			valid = false;
		}
	}

	//get the received z
	auto z = msg->getZ();
	
	//If transcript (a, e, z) is accepting in sigma on input x, output ACC
	//Else outupt REJ
	valid = valid && proccessVerify(fsInput->getSigmaInput(), a.get(), computedE, z.get());
	
	if (sigmaInput != nullptr) {
		delete fsInput;
	}

	return valid;
}





