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


#include "../../include/interactive_mid_protocols/SigmaProtocolElGamalPrivateKey.hpp"

/**
* Computes the simulator computation with the given challenge.
* @param input MUST be an instance of SigmaElGamalPrivateKeyCommonInput.
* @param challenge
* @return the output of the computation - (a, e, z).
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalPrivateKeyCommonInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaElGamalPrivateKeySimulator::simulate(SigmaCommonInput* input, const vector<byte> & challenge) {
	auto elGamalInput = dynamic_cast<SigmaElGamalPrivateKeyCommonInput*>(input);
	if (elGamalInput == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalPrivateKeyCommonInput");
	}
	//Convert the input to match the required SigmaDlogSimulator's input.
	SigmaDlogCommonInput * dlogInput = new SigmaDlogCommonInput(elGamalInput->getPublicKey().getH());
	unique_ptr<SigmaDlogCommonInput> dlogInputP(dlogInput);

	//Delegates the computation to the underlying Sigma Dlog simulator.
	return dlogSim.simulate(dlogInputP.get(), challenge);

}

/**
* Computes the simulator computation with a randomly chosen challenge.
* @param input MUST be an instance of SigmaElGamalPrivateKeyCommonInput.
* @return the output of the computation - (a, e, z).
* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalPrivateKeyCommonInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaElGamalPrivateKeySimulator::simulate(SigmaCommonInput* input) {
	auto elGamalInput = dynamic_cast<SigmaElGamalPrivateKeyCommonInput*>(input);
	if (elGamalInput == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalPrivateKeyCommonInput");
	}
	//Convert the input to match the required SigmaDlogSimulator's input.
	SigmaDlogCommonInput * dlogInput = new SigmaDlogCommonInput(elGamalInput->getPublicKey().getH());
	unique_ptr<SigmaDlogCommonInput> dlogInputP(dlogInput);

	//Delegates the computation to the underlying Sigma Dlog simulator.
	return dlogSim.simulate(dlogInputP.get());
}

/**
* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
* @param dlog
* @param t Soundness parameter in BITS.
* @param random
*/
SigmaElGamalPrivateKeyProverComputation::SigmaElGamalPrivateKeyProverComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & prg)
	: sigmaDlog(dlog, t, prg) {
	this->prg = prg;
	this->dlog = dlog;
	this->t = t;
}

/**
* Computes the first message of the protocol.
* @param input MUST be an instance of SigmaElGamalPrivateKeyProverInput.
* @return the computed message
* @throws IllegalArgumentException if input is not an instance of SigmaElGamalPrivateKeyProverInput.
*/
shared_ptr<SigmaProtocolMsg> SigmaElGamalPrivateKeyProverComputation::computeFirstMsg(const shared_ptr<SigmaProverInput> & input){
	auto in = dynamic_pointer_cast<SigmaElGamalPrivateKeyProverInput>(input);
	
	if (in == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalPrivateKeyProverInput");
	}
	
	//Create an input object to the underlying sigma dlog prover.
	//Delegates the computation to the underlying Sigma Dlog prover.
	return sigmaDlog.computeFirstMsg(make_shared<SigmaDlogProverInput>(dynamic_pointer_cast<SigmaElGamalPrivateKeyCommonInput>(in->getCommonInput())->getPublicKey().getH(), in->getPrivateKey().getX()));

}

/**
* Computes the second message of the protocol.
* @param challenge
* @return the computed message.
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
*/
shared_ptr<SigmaProtocolMsg> SigmaElGamalPrivateKeyProverComputation::computeSecondMsg(const vector<byte> & challenge) {
	//Delegates the computation to the underlying Sigma Dlog prover.
	return sigmaDlog.computeSecondMsg(challenge);

}

/**
* Verifies the proof.
* @param z second message from prover
* @param input MUST be an instance of SigmaElGamalPrivateKeyCommonInput.
* @return true if the proof has been verified; false, otherwise.
* @throws IllegalArgumentException if input is not an instance of SigmaElGamalPrivateKeyCommonInput.
* @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaGroupElementMsg
* @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
*/
bool SigmaElGamalPrivateKeyVerifierComputation::verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) {
	auto in = dynamic_cast<SigmaElGamalPrivateKeyCommonInput*>(input);
	if (in == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalPrivateKeyCommonInput");
	}
	
	//Create an input object to the underlying sigma dlog verifier.
	SigmaDlogCommonInput* underlyingInput = new SigmaDlogCommonInput(in->getPublicKey().getH());
	unique_ptr<SigmaDlogCommonInput> inputP(underlyingInput);

	return sigmaDlog.verify(inputP.get(), a, z);
}