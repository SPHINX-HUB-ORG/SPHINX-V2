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


#include "../../include/interactive_mid_protocols/SigmaProtocolPedersenCommittedValue.hpp"

string SigmaPedersenCommittedValueCommonInput::toString() {
	string output = x.str();
	output += ":";
	output += h->generateSendableData()->toString();
	output += ":";
	output += commitment->generateSendableData()->toString();
	return output;

}

/**
* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
* @param dlog
* @param t Soundness parameter in BITS.
* @param random
*/
SigmaPedersenCommittedValueSimulator::SigmaPedersenCommittedValueSimulator(const shared_ptr<DlogGroup> & dlog,
        int t, const shared_ptr<PrgFromOpenSSLAES> & prg)
	: dlogSim(dlog, t, prg) {

	//Creates the underlying SigmaDlogSimulator object with the given parameters.
	this->dlog = dlog.get();
}

shared_ptr<SigmaSimulatorOutput> SigmaPedersenCommittedValueSimulator::simulate(SigmaCommonInput* input,
        const vector<byte> & challenge) {
	
	//Delegate the computation to the underlying Sigma Dlog simulator.
	return dlogSim.simulate(convertInput(input).get(), challenge);

}

shared_ptr<SigmaSimulatorOutput> SigmaPedersenCommittedValueSimulator::simulate(SigmaCommonInput* input) {
	//Delegate the computation to the underlying Sigma Dlog simulator.
	return dlogSim.simulate(convertInput(input).get());
}

shared_ptr<SigmaDlogCommonInput> SigmaPedersenCommittedValueSimulator::convertInput(SigmaCommonInput* in) {
	auto params = dynamic_cast<SigmaPedersenCommittedValueCommonInput*>(in);

	//If the given input is not an instance of SigmaPedersenCommittedValueCommonInput throw exception
	if (params == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaPedersenCommittedValueCommonInput");
	}
	
	//Convert the input to the underlying Dlog prover. h' = c*h^(-x).
	biginteger minusX = dlog->getOrder() - params->getX();
	auto hToX = dlog->exponentiate(params->getH().get(), minusX);
	auto c = params->getCommitment();
	auto hTag = dlog->multiplyGroupElements(c.get(), hToX.get());

	//Create and return the input instance with the computes h'.
	return make_shared<SigmaDlogCommonInput>(hTag);
}

/**
* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
* @param dlog
* @param t Soundness parameter in BITS.
* @param random
*/
SigmaPedersenCommittedValueProverComputation::SigmaPedersenCommittedValueProverComputation(const shared_ptr<DlogGroup> & dlog, int t,
	const shared_ptr<PrgFromOpenSSLAES> & prg) : sigmaDlog(dlog, t, prg) {
	this->prg = prg;
	this->dlog = dlog;
	this->t = t;
}

/**
* Returns the soundness parameter for this Sigma protocol.
* @return t soundness parameter
*/
int SigmaPedersenCommittedValueProverComputation::getSoundnessParam() {
	//Delegates the computation to the underlying Sigma Dlog prover.
	return sigmaDlog.getSoundnessParam();
}

/**
* Computes the first message of the protocol.
* @param input MUST be an instance of SigmaPedersenCommittedValueProverInput.
* @return the computed message
* @throws IllegalArgumentException if input is not an instance of SigmaPedersenCommittedValueProverInput.
*/
shared_ptr<SigmaProtocolMsg> SigmaPedersenCommittedValueProverComputation::computeFirstMsg(const shared_ptr<SigmaProverInput> & input)  {
	//Converts the input to the underlying prover.
	//Delegates the computation to the underlying Sigma Dlog prover.
	return sigmaDlog.computeFirstMsg(convertInput(input.get()));
}

/**
* Computes the second message of the protocol.
* @param challenge
* @return the computed message.
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
*/
shared_ptr<SigmaProtocolMsg> SigmaPedersenCommittedValueProverComputation::computeSecondMsg(const vector<byte> & challenge) {
	//Delegates the computation to the underlying Sigma Dlog prover.
	return sigmaDlog.computeSecondMsg(challenge);

}

/**
* Converts the input for the underlying prover computation.
* @param input MUST be an instance of SigmaPedersenCommittedValueProverInput.
* @throws IllegalArgumentException if input is not an instance of SigmaPedersenCommittedValueProverInput.
*/
shared_ptr<SigmaDlogProverInput> SigmaPedersenCommittedValueProverComputation::convertInput(SigmaProverInput* in) {
	auto params = dynamic_cast<SigmaPedersenCommittedValueProverInput*>(in);

	//If the given input is not an instance of SigmaPedersenCommittedValueCommonInput throw exception
	if (params == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaPedersenCommittedValueProverInput");
	}

	auto commonParams = dynamic_pointer_cast<SigmaPedersenCommittedValueCommonInput>(params->getCommonInput());
	//If the given input is not an instance of SigmaPedersenCommittedValueCommonInput throw exception
	if (commonParams == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaPedersenCommittedValueCommonInput");
	}

	//Convert the input to the underlying Dlog prover. h' = c*h^(-x).
	biginteger minusX = dlog->getOrder() - commonParams->getX();
	auto hToX = dlog->exponentiate(commonParams->getH().get(), minusX);
	auto c = commonParams->getCommitment();
	auto hTag = dlog->multiplyGroupElements(c.get(), hToX.get());

	//Create and return the input instance with the computes h'.
	return make_shared<SigmaDlogProverInput>(hTag, params->getR());
}

/**
* Sets the input for this Sigma protocol.
* @param input MUST be an instance of SigmaPedersenCommittedValueCommonInput.
* @throws IllegalArgumentException if input is not an instance of SigmaPedersenCommittedValueCommonInput.
*/
shared_ptr<SigmaDlogCommonInput> SigmaPedersenCommittedValueVerifierComputation::convertInput(SigmaCommonInput* in) {
	auto input = dynamic_cast<SigmaPedersenCommittedValueCommonInput*>(in);
	if (input == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaPedersenCommittedValueCommonInput");
	}
	
	//Convert the input to the underlying Dlog prover. h' = c*h^(-x).
	biginteger minusX = dlog->getOrder() - input->getX();
	auto hToX = dlog->exponentiate(input->getH().get(), minusX);
	auto c = input->getCommitment();
	auto hTag = dlog->multiplyGroupElements(c.get(), hToX.get());

	return make_shared<SigmaDlogCommonInput>(hTag);

}