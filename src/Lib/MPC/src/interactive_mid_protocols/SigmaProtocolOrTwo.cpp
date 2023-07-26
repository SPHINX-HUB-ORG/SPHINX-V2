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


#include "../../include/interactive_mid_protocols/SigmaProtocolOrTwo.hpp"

void SigmaOrTwoSecondMsg::initFromString(const string & s) {
	auto str_vec = explode(s, ':');
	assert(str_vec.size() == 4);
	z0->initFromString(str_vec[0]);
	e0.assign(str_vec[1].begin(), str_vec[1].end());
	z1->initFromString(str_vec[2]);
	e1.assign(str_vec[3].begin(), str_vec[3].end());
}

string SigmaOrTwoSecondMsg::toString() {
	string output = z0->toString();
	output += ":";
	const byte * uc0 = &(e0[0]);
	output += string(reinterpret_cast<char const*>(uc0), e0.size());
	output += ":";
	output += z1->toString();
	output += ":";
	const byte * uc1 = &(e1[0]);
	output += string(reinterpret_cast<char const*>(uc1), e1.size());
	return output;
}

shared_ptr<SigmaCommonInput> SigmaOrTwoProverInput::getCommonInput() {
	/*
	*
	* There are two options to implement this function:
	* 1. Create a new instance of SigmaANDCommonInput every time the function is called.
	* 2. Create the object in the construction time and return it every time this function is called.
	* This class holds an array of SigmaProverInput, where each instance in the array holds
	* an instance of SigmaCommonParams inside it.
	* In the second option above, this class will have in addition an array of SigmaCommonInput.
	* This way, the SigmaCommonInput instances will appear twice -
	* once in the array and once in the corresponding SigmaProverInput.
	* This is an undesired duplication and redundancy, So we decided to implement using the
	* first way, although this is less efficient.
	* In case the efficiency is important, a user can derive this class and override this implementation.
	*/

	vector<shared_ptr<SigmaCommonInput>> inputArr;
	if (b) {
		inputArr.push_back(proverInput->getCommonInput());
		inputArr.push_back(simulatorInput);
	}
	else {
		inputArr.push_back(simulatorInput);
		inputArr.push_back(proverInput->getCommonInput());
	}
	return make_shared<SigmaMultipleCommonInput>(inputArr);
}


/**
* Constructor that gets the underlying simulators.
* @param simulators array of SigmaSimulator that contains TWO underlying simulators.
* @param t soundness parameter. t MUST be equal to both t values of the underlying simulators object.
* @throws IllegalArgumentException if the given t is not equal to both t values of the underlying simulators.
* @throws IllegalArgumentException if the given simulators array does not contains two objects.
*/
SigmaOrTwoSimulator::SigmaOrTwoSimulator(const vector<shared_ptr<SigmaSimulator>> & simulators, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {
	if (simulators.size() != 2) {
		throw invalid_argument("The given simulators array must contains two objects.");
	}

	//If the given t is different from one of the underlying object's t values, throw exception.
	if ((t != simulators[0]->getSoundnessParam()) || (t != simulators[1]->getSoundnessParam())) {
		throw invalid_argument("The given t does not equal to one of the t values in the underlying simulators objects.");
	}

	this->simulators = simulators;
	this->t = t;
	this->random = random;
}

/**
* Computes the simulator computation with the given challenge.
* @param input MUST be an instance of SigmaORTwoCommonInput.
* @param challenge
* @return the output of the computation - (a, e, z).
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
* @throws IllegalArgumentException if the given input is not an instance of SigmaORTwoCommonInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaOrTwoSimulator::simulate(SigmaCommonInput* input, const vector<byte> & challenge) {
	/*
	* SAMPLE a random e0,
	* 	COMPUTE e1 = e XOR e0
	* 	RUN the Sigma protocol simulator for each protocol with the resulting e0,e1 values.
	*/

	//check the challenge validity.
	int len = challenge.size();
	if (!checkChallengeLength(len)) {
		throw CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
	}

	auto in = dynamic_cast<SigmaMultipleCommonInput*>(input);
	if (in == NULL) {
		throw invalid_argument("The given input must be an instance of SigmaORTwoCommonInput");
	}
	
	//Sample a random e0.
	vector<byte> e0(len);
	random->getPRGBytes(e0, 0, t / 8);

	
	//Set e1 = challenge XOR e0.
	vector<byte> e1;
	for (int i = 0; i < len; i++) {
		e1.push_back(challenge[i] ^ e0[i]);
	}
	
	auto output0 = simulators[0]->simulate(in->getInputs()[0].get(), e0);
	auto output1 = simulators[1]->simulate(in->getInputs()[1].get(), e1);

	//Create a SigmaORTwo messages from the simulates function's outputs.
	vector<shared_ptr<SigmaProtocolMsg>> firstMessages;
	firstMessages.push_back(output0->getA());
	firstMessages.push_back(output1->getA());
	auto a = make_shared<SigmaMultipleMsg>(firstMessages);
	auto z = make_shared<SigmaOrTwoSecondMsg>(output0->getZ(), e0, output1->getZ(), e1);

	//Output (a,e,z).
	return make_shared<SigmaSimulatorOutput>(a, challenge, z);

}

/**
* Computes the simulator computation with a randomly chosen challenge.
* @param input MUST be an instance of SigmaORTwoCommonInput.
* @return the output of the computation - (a, e, z).
* @throws IllegalArgumentException if the given input is not an instance of SigmaORTwoCommonInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaOrTwoSimulator::simulate(SigmaCommonInput* input) {
	//Create a new byte array of size t/8, to get the required byte size.
	vector<byte> e(t / 8);
	random->getPRGBytes(e, 0, t / 8);
	
	return simulate(input, e);
}

/**
* Checks if the given challenge length is equal to the soundness parameter.
* @return true if the challenge length is t; false, otherwise.
*/
bool SigmaOrTwoSimulator::checkChallengeLength(int size) {
	//If the challenge's length is equal to t, return true. else, return false.
	return (size == (t / 8) ? true : false);
}

/**
* Constructor that gets the underlying provers.
* @param provers array of SigmaProverComputation that contains TWO underlying provers.
* @param t soundness parameter. t MUST be equal to both t values of the underlying provers object.
* @throws IllegalArgumentException if the given t is not equal to both t values of the underlying provers.
* @throws IllegalArgumentException if the given provers array does not contains two objects.
*/
SigmaOrTwoProverComputation::SigmaOrTwoProverComputation(const shared_ptr<SigmaProverComputation> & prover, const shared_ptr<SigmaSimulator> & simulator, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {

	//If the given t is different from one of the underlying object's t values, throw exception.
	if ((t != prover->getSoundnessParam()) || (t != simulator->getSoundnessParam())) {
		throw invalid_argument("The given t does not equal to one of the t values in the underlying provers objects.");
	}

	this->prover = prover;
	this->simulator = simulator;
	this->t = t;
	this->random = random;
}

/**
* Computes the frist message of the protocol.<p>
* "SAMPLE a random challenge  e1-b <- {0, 1}^t" for the simulator.<p>
*  COMPUTE the first message ab in SigmaB, using (xb,w) as input.<p>
*	RUN the simulator M for SigmaI on input (x1-b, e1-b) to obtain (a1-b, e1-b, z1-b).<p>
*	The message is (a0,a1); e1-b,z1-b are stored for later".
* @param input MUST be an instance of SigmaORTwoProverInput.
* @return SigmaORFirstMsg contains a0, a1.
* @throws IllegalArgumentException if input is not an instance of SigmaORTwoProverInput.
*/
shared_ptr<SigmaProtocolMsg> SigmaOrTwoProverComputation::computeFirstMsg(const shared_ptr<SigmaProverInput> & input) {
	
	auto in = dynamic_pointer_cast<SigmaOrTwoProverInput>(input);
	if (in == NULL) {
		throw invalid_argument("The given input must be an instance of SigmaORTwoProverInput");
	}
	
	//Get b such that (xb,w) is in R.
	b = in->getB();

	//Create the challenge for the Simulator.
	eOneMinusB.resize(t / 8);
	random->getPRGBytes(eOneMinusB, 0, t / 8);

	//Call the sigma WITH THE WITNESS to compute first message ab.
	//The second prover will not be in use so it does not need to compute messages.
	auto aB = prover->computeFirstMsg(in->getProverInput());

	//Simulate Sigma 1-b on input (x1-b, e1-b) to obtain (a1-b, e1-b, z1-b), save the output.
	auto output = simulator->simulate(in->getSimulatorInput().get(), eOneMinusB);
	
	auto aOneMinusB = output->getA();
	//Save the z1-b to the future.
	zOneMinusB = output->getZ();

	//Create and return SigmaORTwoFirstMsg with a0, a1.
	vector<shared_ptr<SigmaProtocolMsg>> msg;
	if (b == 0) {
		msg.push_back(aB);
		msg.push_back(aOneMinusB);
	} else {
		msg.push_back(aOneMinusB);
		msg.push_back(aB);
	}
	return make_shared<SigmaMultipleMsg>(msg);
}

/**
* Computes the second message of the protocol.<p>
* "SET eb = e XOR e1-b<p>
*	COMPUTE the response zb to (ab, eb) in SigmaB using input (xb,w)<p>
*	The message is e0,z0,e1,z1".
* @param challenge
* @return SigmaORTwoSecondMsg contains e0,z0,e1,z1.
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
*/
shared_ptr<SigmaProtocolMsg> SigmaOrTwoProverComputation::computeSecondMsg(const vector<byte> & challenge) {
	//check the challenge validity.
	int len = challenge.size();
	if (!checkChallengeLength(len)) {
		throw CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
	}

	//Set eb = e XOR e1-b.
	vector<byte> eb;
	for (int i = 0; i < len; i++) {
		eb.push_back(challenge[i] ^ eOneMinusB[i]);
	}
	
	//Compute the response zb in SigmaB using input (xb,w).
	auto zb = prover->computeSecondMsg(eb);

	//Create and return SigmaORTwoSecondMsg with z0, e0, z1, e1.
	shared_ptr<SigmaOrTwoSecondMsg> msg;
	if (b == 0) {
		msg = make_shared<SigmaOrTwoSecondMsg>(zb, eb, zOneMinusB, eOneMinusB);
	} else {
		msg = make_shared<SigmaOrTwoSecondMsg>(zOneMinusB, eOneMinusB, zb, eb);
	}
	return msg;
}

/**
* Checks if the given challenge length is equal to the soundness parameter.
* @return true if the challenge length is t; false, otherwise.
*/
bool SigmaOrTwoProverComputation::checkChallengeLength(int size) {
	//If the challenge's length is equal to t, return true. else, return false.
	return (size == (t / 8) ? true : false);
}

/**
* Returns the simulator that matches this sigma protocol prover.
* @return SigmaProtocolANDSimulator
*/
shared_ptr<SigmaSimulator> SigmaOrTwoProverComputation::getSimulator() {
	//Create a simulators array with simulators that matches the underlying provers.
	vector<shared_ptr<SigmaSimulator>> simulators;
	if (b == 0) {
		simulators.push_back(prover->getSimulator());
		simulators.push_back(simulator);
	} else {
		simulators.push_back(simulator);
		simulators.push_back(prover->getSimulator());
	}
	return make_shared<SigmaOrTwoSimulator>(simulators, t, random);
}

/**
* Constructor that gets the underlying verifiers.
* @param verifiers array of SigmaVerifierComputation that contains TWO underlying verifiers.
* @param t soundness parameter. t MUST be equal to both t values of the underlying verifiers objects.
* @throws IllegalArgumentException if the given t is not equal to both t values of the underlying verifiers.
* @throws IllegalArgumentException if the given verifiers array does not contains two objects.
*/
SigmaOrTwoVerifierComputation::SigmaOrTwoVerifierComputation(const vector<shared_ptr<SigmaVerifierComputation>> & verifiers, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {
	if (verifiers.size() != 2) {
		throw invalid_argument("The given verifiers array must contains two objects.");
	}
	//If the given t is different from one of the underlying object's t values, throw exception.
	if ((t != verifiers[0]->getSoundnessParam()) || (t != verifiers[1]->getSoundnessParam())) {
		throw invalid_argument("The given t does not equal to one of the t values in the underlying verifiers objects.");
	}

	this->verifiers = verifiers;
	this->t = t;
	this->random = random;
}

/**
* Computes the following line from the protocol:
* 	"ACC IFF all verifier checks are ACC".
* @param input MUST be an instance of SigmaORTwoCommonInput.
* @param a first message from prover
* @param z second message from prover
* @return true if the proof has been verified; false, otherwise.
* @throws IllegalArgumentException if input is not an instance of SigmaORTwoCommonInput.
* @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaORTwoFirstMsg
* @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaORTwoSecondMsg
*/
bool SigmaOrTwoVerifierComputation::verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) {
	auto in = dynamic_cast<SigmaMultipleCommonInput*>(input);
	if (in == NULL) {
		throw invalid_argument("The given input must be an instance of SigmaMultipleCommonInput");
	}

	bool verified = true;

	//If one of the messages is illegal, throw exception.
	auto first = dynamic_cast<SigmaMultipleMsg*>(a);
	auto second = dynamic_cast<SigmaOrTwoSecondMsg*>(z);
	if (first == NULL) {
		throw invalid_argument("first message must be an instance of SigmaMultipleMsg");
	}
	if (second == NULL) {
		throw invalid_argument("second message must be an instance of SigmaORTwoSecondMsg");
	}
	
	//Sets the challenges to the underlying verifiers.
	verifiers[0]->setChallenge(second->getE0());
	verifiers[1]->setChallenge(second->getE1());

	//Compute the first verify check
	verified = verified && verifiers[0]->verify(in->getInputs()[0].get(), first->getMessages()[0].get(), second->getZ0().get());

	//Compute the second verify check
	verified = verified && verifiers[1]->verify(in->getInputs()[1].get(), first->getMessages()[1].get(), second->getZ1().get());

	//Return true if all verifiers returned true; false, otherwise.
	return verified;
}