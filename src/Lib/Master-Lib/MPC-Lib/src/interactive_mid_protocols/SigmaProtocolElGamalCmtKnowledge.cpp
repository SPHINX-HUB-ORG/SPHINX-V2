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


#include "../../include/interactive_mid_protocols/SigmaProtocolElGamalCmtKnowledge.hpp"

shared_ptr<SigmaDlogCommonInput> SigmaElGamalCmtKnowledgeSimulator::convertInput(SigmaCommonInput* input) {
	auto params = dynamic_cast<SigmaElGamalCmtKnowledgeCommonInput*>(input);

	//If the given input is not an instance of SigmaPedersenCommittedValueCommonInput throw exception
	if (params == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalCTKnowledgeCommonInput");
	}

	//Convert the input to match the required SigmaDlogSimulator's input.
	auto h = params->getPublicKey().getH();
	return make_shared<SigmaDlogCommonInput>(h);
}

/**
* Computes the simulator computation.
* @param input MUST be an instance of SigmaElGamalCTKnowledgeCommonInput.
* @param challenge
* @return the output of the computation - (a, e, z).
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCTKnowledgeCommonInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaElGamalCmtKnowledgeSimulator::simulate(SigmaCommonInput* input, const vector<byte> & challenge) {
	//Converts the input to an input object of the underlying simulator.
	//Delegates the computation to the underlying Sigma Dlog prover.
	return dlogSim.simulate(convertInput(input).get(), challenge);

}

/**
* Computes the simulator computation.
* @param input MUST be an instance of SigmaElGamalCTKnowledgeCommonInput.
* @return the output of the computation - (a, e, z).
* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCTKnowledgeCommonInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaElGamalCmtKnowledgeSimulator::simulate(SigmaCommonInput* input){
	//Converts the input to an input object of the underlying simulator.
	//Delegates the computation to the underlying Sigma Dlog simulator.
	return dlogSim.simulate(convertInput(input).get());
}

/**
* Converts the input for this Sigma protocol to the underlying protocol.
* @param input MUST be an instance of SigmaElGamalCTKnowledgeProverInput.
* @throws IllegalArgumentException if input is not an instance of SigmaElGamalCTKnowledgeProverInput.
*/
shared_ptr<SigmaDlogProverInput> SigmaElGamalCmtKnowledgeProverComputation::convertInput(SigmaProverInput* in) {
	auto input = dynamic_cast<SigmaElGamalCmtKnowledgeProverInput*>(in);

	if (input == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalCTKnowledgeProverInput");
	}
	
	//Create an input object to the underlying sigma dlog prover.
	auto h = (dynamic_pointer_cast<SigmaElGamalCmtKnowledgeCommonInput>(input->getCommonInput()))->getPublicKey().getH();
	return make_shared<SigmaDlogProverInput>(h, input->getW());

}

/**
* Constructor that gets the underlying DlogGroup, soundness parameter.
* @param dlog
* @param t Soundness parameter in BITS.
*/
SigmaElGamalCmtKnowledgeProverComputation::SigmaElGamalCmtKnowledgeProverComputation(const shared_ptr<DlogGroup> & dlog,
								 int t, const shared_ptr<PrgFromOpenSSLAES> & prg) : sigmaDlog(dlog, t, prg) {
	this->dlog = dlog;
	this->t = t;
	this->prg = prg;
}

/**
* Computes the first message of the protocol.
* @param input MUST be an instance of SigmaElGamalCTKnowledgeProverInput.
* @return the computed message
* @throws IllegalArgumentException if input is not an instance of SigmaElGamalCTKnowledgeProverInput.
*/
shared_ptr<SigmaProtocolMsg> SigmaElGamalCmtKnowledgeProverComputation::computeFirstMsg(const shared_ptr<SigmaProverInput> & input) {
	//Delegates the computation to the underlying Sigma Dlog prover.
	return sigmaDlog.computeFirstMsg(convertInput(input.get()));
}

/**
* Computes the second message of the protocol.
* @param challenge
* @return the computed message.
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
*/
shared_ptr<SigmaProtocolMsg> SigmaElGamalCmtKnowledgeProverComputation::computeSecondMsg(const vector<byte> & challenge) {
	//Delegates the computation to the underlying Sigma Dlog prover.
	return sigmaDlog.computeSecondMsg(challenge);
}

/**
* Convert the input for this Sigma protocol to the underlying protocol.
* @param input MUST be an instance of SigmaElGamalCTKnowledgeCommonInput.
* @throws IllegalArgumentException if input is not an instance of SigmaElGamalCTKnowledgeCommonInput.
*/
shared_ptr<SigmaDlogCommonInput> SigmaElGamalCmtKnowledgeVerifierComputation::convertInput(SigmaCommonInput* in) {
	auto input = dynamic_cast<SigmaElGamalCmtKnowledgeCommonInput*>(in);

	if (input == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalCTKnowledgeCommonInput");
	}
	

	//Create an input object to the underlying sigma dlog prover.
	auto h = input->getPublicKey().getH();

	return make_shared<SigmaDlogCommonInput>(h);

}