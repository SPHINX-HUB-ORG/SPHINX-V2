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


#include "../../include/interactive_mid_protocols/SigmaProtocolElGamalCommittedValue.hpp"

string SigmaElGamalCommittedValueCommonInput::toString() {
	string output = publicKey->generateSendableData()->toString();
	output += ":";
	output += commitment->toString();
	output += ":";
	output += x->generateSendableData()->toString();
	return output;
}
/**
* Converts the input to an input object for the underlying simulator.
* @param in
* @return
*/
shared_ptr<SigmaDHCommonInput> SigmaElGamalCommittedValueSimulator::convertInput(SigmaCommonInput* in) {
	auto input = dynamic_cast<SigmaElGamalCommittedValueCommonInput*>(in);

	if (input == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalCommittedValueCommonInput");
	}
	
	auto commitment = input->getCommitment();

	//Convert input to the underlying DH prover:
	//(g,h,u,v) = (g,h,c1,c2/x).
	auto h = input->getPublicKey()->getH();
	//u = c1
	auto u = dlog->reconstructElement(true, commitment->getCipher1().get());
	//Calculate v = c2/x = c2*x^(-1)
	auto c2 = dlog->reconstructElement(true, commitment->getCipher2().get());
	auto xInv = dlog->getInverse(input->getX().get());
	auto v = dlog->multiplyGroupElements(c2.get(), xInv.get());
	
	return make_shared<SigmaDHCommonInput>(h, u, v);
}

/**
* Computes the simulator computation with the given challenge.
* @param input MUST be an instance of SigmaElGamalCommittedValueCommonInput.
* @param challenge
* @return the output of the computation - (a, e, z).
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCommittedValueCommonInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaElGamalCommittedValueSimulator::simulate(SigmaCommonInput* input, const vector<byte> & challenge)  {
	//Convert the input to an input object for the underlying simulator.
	//Delegates the computation to the underlying Sigma DH prover.
	return dhSim.simulate(convertInput(input).get(), challenge);

}

/**
* Computes the simulator computation with a randomly chosen challenge.
* @param in MUST be an instance of SigmaElGamalCommittedValueCommonInput.
* @return the output of the computation - (a, e, z).
* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCommittedValueCommonInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaElGamalCommittedValueSimulator::simulate(SigmaCommonInput* input) {
	//Convert the input to an input object for the underlying simulator.
	//Delegates the computation to the underlying Sigma DH simulator.
	return dhSim.simulate(convertInput(input).get());
}

/**
* Converts the input to an input object for the underlying simulator.
* @param in
* @return
*/
shared_ptr<SigmaDHProverInput> SigmaElGamalCommittedValueProverComputation::convertInput(SigmaProverInput* in) {
	auto input = dynamic_cast<SigmaElGamalCommittedValueProverInput*>(in);
	if (input == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalCommittedValueProverInput");
	}

	auto commonInput = dynamic_cast<SigmaElGamalCommittedValueCommonInput*>(input->getCommonInput().get());
	if (commonInput == NULL) {
		throw invalid_argument("the common input must be an instance of SigmaElGamalCommittedValueCommonInput");
	}
	auto commitment = commonInput->getCommitment();

	//Convert input to the underlying DH prover:
	//(g,h,u,v) = (g,h,c1,c2/x).
	auto h = commonInput->getPublicKey()->getH();
	//u = c1
	auto u = dlog->reconstructElement(true, commitment->getCipher1().get());
	//Calculate v = c2/x = c2*x^(-1)
	auto c2 = dlog->reconstructElement(true, commitment->getCipher2().get());
	auto xInv = dlog->getInverse(commonInput->getX().get());
	auto v = dlog->multiplyGroupElements(c2.get(), xInv.get());

	return make_shared<SigmaDHProverInput>(h, u, v, input->getR());
}

/**
* Computes the first message of the protocol.
* @param input MUST be an instance of SigmaElGamalCommittedValueProverInput.
* @return the computed message
* @throws IllegalArgumentException if input is not an instance of SigmaElGamalCommittedValueProverInput.
*/
shared_ptr<SigmaProtocolMsg> SigmaElGamalCommittedValueProverComputation::computeFirstMsg(const shared_ptr<SigmaProverInput> & input) {
	//Delegates the computation to the underlying Sigma DH prover.
	return sigmaDH.computeFirstMsg(convertInput(input.get()));
}

/**
* Computes the second message of the protocol.
* @param challenge
* @return the computed message.
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
*/
shared_ptr<SigmaProtocolMsg> SigmaElGamalCommittedValueProverComputation::computeSecondMsg(const vector<byte> & challenge) {
	//Delegates the computation to the underlying Sigma DH prover.
	return sigmaDH.computeSecondMsg(challenge);

}

/**
* Converts the input to an input object for the underlying simulator.
* @param in
* @return
*/
shared_ptr<SigmaDHCommonInput> SigmaElGamalCommittedValueVerifierComputation::convertInput(SigmaCommonInput* in) {
	auto input = dynamic_cast<SigmaElGamalCommittedValueCommonInput*>(in);

	if (input == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalCommittedValueCommonInput");
	}
	auto commitment = input->getCommitment();
	
	//Convert input to the underlying DH prover:
	//(g,h,u,v) = (g,h,c1,c2/x).
	auto h = input->getPublicKey()->getH();
	//u = c1
	auto u = dlog->reconstructElement(true, commitment->getCipher1().get()); 
	//Calculate v = c2/x = c2*x^(-1)
	auto c2 = dlog->reconstructElement(true, commitment->getCipher2().get());
	auto xInv = dlog->getInverse(input->getX().get());
	auto v = dlog->multiplyGroupElements(c2.get(), xInv.get());
	return make_shared<SigmaDHCommonInput>(h, u, v);
}