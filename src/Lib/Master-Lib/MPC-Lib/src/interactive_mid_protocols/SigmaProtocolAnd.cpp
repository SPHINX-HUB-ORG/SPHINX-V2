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


#include "../../include/interactive_mid_protocols/SigmaProtocolAnd.hpp"


/***************************************/
/*   SigmaANDProverComputation         */
/***************************************/

SigmaANDProverComputation::SigmaANDProverComputation(const vector<shared_ptr<SigmaProverComputation>> & provers, int t, const shared_ptr<PrgFromOpenSSLAES> & prg) {
	// if the given t is different from one of the underlying object's t values, throw exception.
	for (auto prover : provers)
		if(t != prover->getSoundnessParam())
			throw invalid_argument("the given t does not equal to one of the t values in the underlying provers objects.");

	this->provers = provers;
	this->prg = prg;
	len = provers.size();
	this->t = t;
}

shared_ptr<SigmaProtocolMsg> SigmaANDProverComputation::computeFirstMsg(const shared_ptr<SigmaProverInput> & in) {
	// checks that the input is as expected.
	auto input = checkInput(in.get());
	auto proversInput = input->getInputs();

	// create an array to hold all messages.
	vector<shared_ptr<SigmaProtocolMsg>> firstMessages;

	// compute all first messages and add them to the array list.
	for (int i = 0; i < len; i++) 
		firstMessages.push_back(provers[i]->computeFirstMsg(proversInput[i]));

	// create a SigmaMultipleMsg with the messages array.
	return make_shared<SigmaMultipleMsg>(firstMessages);
}

shared_ptr<SigmaProtocolMsg> SigmaANDProverComputation::computeSecondMsg(const vector<byte> & challenge) {
	// create an array to hold all messages.
	vector<shared_ptr<SigmaProtocolMsg>> secondMessages;
	// compute all second messages and add them to the array list.
	for (auto prover : provers) {
		secondMessages.push_back(prover->computeSecondMsg(challenge));
	}

	// Create a SigmaMultipleMsg with the messages array.
	return make_shared<SigmaMultipleMsg>(secondMessages);
}

shared_ptr<SigmaSimulator> SigmaANDProverComputation::getSimulator() {
	vector<shared_ptr<SigmaSimulator>> simulators;
	for(auto prover:provers)
		simulators.push_back(prover->getSimulator());
	return make_shared<SigmaANDSimulator>(simulators, t, prg);
}

SigmaMultipleProverInput* SigmaANDProverComputation::checkInput(SigmaProverInput* in) {
	auto input = dynamic_cast<SigmaMultipleProverInput*>(in);
	if (!input)
		throw invalid_argument("the given input must be an instance of SigmaMultipleProverInput");

	int inputLen = input->getInputs().size();

	// if number of inputs is not equal to number of provers, throw exception.
	if (inputLen != len)
		throw invalid_argument("number of inputs is different from number of underlying provers.");
	return input;
}

/***************************************/
/*   SigmaANDSimulator                 */
/***************************************/

SigmaANDSimulator::SigmaANDSimulator(const vector<shared_ptr<SigmaSimulator>> & simulators, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {
	// if the given t is different from one of the underlying object's t values, throw exception.
	for(auto sigmaSimulator : simulators)
		if(t!=sigmaSimulator->getSoundnessParam())
			throw invalid_argument("the given t does not equal to one of the t values in the underlying simulators objects.");

	this->simulators = simulators;
	len = simulators.size();
	this->t = t;
	this->random = random;
}

shared_ptr<SigmaSimulatorOutput> SigmaANDSimulator::simulate(SigmaCommonInput* input,
	const vector<byte> & challenge) {
	if (!checkChallengeLength(challenge.size())) 
		throw CheatAttemptException("the length of the given challenge is different from the soundness parameter");
	
	auto andInput = dynamic_cast<SigmaMultipleCommonInput*>(input);
	if (andInput == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaANDCommonInput");
	}
	
	vector<shared_ptr<SigmaCommonInput>> simulatorsInput = andInput->getInputs();
	int inputLen = simulatorsInput.size();

	// if number of inputs is not equal to number of provers, throw exception.
	if (inputLen != len) 
		throw invalid_argument("number of inputs is different from number of underlying simulators.");

	vector<shared_ptr<SigmaProtocolMsg>> aOutputs;
	vector<shared_ptr<SigmaProtocolMsg>> zOutputs;
	shared_ptr<SigmaSimulatorOutput> output = NULL;
	// run each Sigma protocol simulator with the given challenge.
	for (int i = 0; i < len; i++) {
		output = simulators[i]->simulate(simulatorsInput[i].get(), challenge);
		aOutputs.push_back(output->getA());
		zOutputs.push_back(output->getZ());
	}

	// create a SigmaMultipleMsg from the simulates function's outputs to create a and z.
	auto a = make_shared<SigmaMultipleMsg>(aOutputs);
	auto z = make_shared<SigmaMultipleMsg>(zOutputs);

	// output (a,e,eSize,z).
	return make_shared<SigmaSimulatorOutput>(a, challenge, z);
}

shared_ptr<SigmaSimulatorOutput> SigmaANDSimulator::simulate(SigmaCommonInput* input) {
	//Create a new byte array of size t/8, to get the required byte size and fill it with random values.
	vector<byte> e(t / 8);
	random->getPRGBytes(e, 0, t / 8);
	//modify the challenge to be positive.
	e.data()[e.size() - 1] = e.data()[e.size() - 1] & 127;
	// call the other simulate function with the given input and the samples e.
	return simulate(input, e);
}


/***************************************/
/*   SigmaANDVerifierComputation       */
/***************************************/
SigmaANDVerifierComputation::SigmaANDVerifierComputation(const vector<shared_ptr<SigmaVerifierComputation>> & verifiers, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {
	// if the given t is different from one of the underlying object's t values, throw exception.
	for(auto verifier : verifiers)
		if(t != verifier->getSoundnessParam())
			throw new invalid_argument("the given t does not equal to one of the t values in the underlying verifiers objects.");

	this->verifiers = verifiers;
	len = verifiers.size();
	this->t = t;
	this->random = random;
}

void SigmaANDVerifierComputation::sampleChallenge() {
	//make space for t/8 bytes and fill it with random values.
	e.resize(t / 8);
	random->getPRGBytes(e, 0, t / 8);
	//modify the challenge to be positive.
	e.data()[e.size() - 1] = e.data()[e.size() - 1] & 127;
	
	// set all the other verifiers with the sampled challenge.
	for (auto verifier : verifiers)
		verifier->setChallenge(e);
}

void SigmaANDVerifierComputation::setChallenge(const vector<byte> & challenge) {
	e = challenge;
	for (auto verifier : verifiers)
		verifier->setChallenge(challenge);
}

bool SigmaANDVerifierComputation::verify(SigmaCommonInput* input, 
	SigmaProtocolMsg* a, SigmaProtocolMsg* z) {
	// checks that the input is as expected.
	auto in = dynamic_cast<SigmaMultipleCommonInput*>(input);
	int inputLen = in->getInputs().size();

	// if number of inputs is not equal to number of verifiers, throw exception.
	if (inputLen != len) {
		throw invalid_argument("number of inputs is different from number of underlying verifiers.");
	}
	auto verifiersInput = in->getInputs();

	bool verified = true;

	// if one of the messages is illegal, throw exception.
	SigmaMultipleMsg *first = dynamic_cast<SigmaMultipleMsg*>(a);
	SigmaMultipleMsg *second = dynamic_cast<SigmaMultipleMsg*>(z);
	if (first == NULL)
		throw invalid_argument("first message must be an instance of SigmaMultipleMsg");
	if (second == NULL)
		throw invalid_argument("second message must be an instance of SigmaMultipleMsg");

	auto firstMessages  = first ->getMessages();
	auto secondMessages = second->getMessages();

	//Compute all verifier checks.
	for (int i = 0; i < len; i++) 
		verified = verified && verifiers[i]->verify(verifiersInput[i].get(), firstMessages[i].get(), secondMessages[i].get());

	// return true if all verifiers returned true; false, otherwise.
	return verified;
}

