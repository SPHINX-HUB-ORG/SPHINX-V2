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


#include "../../include/interactive_mid_protocols/SigmaProtocolElGamalEncryptedValue.hpp"

/**
* Sets the given ciphertext, public key and encrypted value.<p>
* There is also an argument represents if the encryption was done by private key knowledge or by a randomness knowledge.
* @param isRandomness represents if the encryption was done by private key knowledge or by a randomness knowledge.
* @param cipher ciphertext outputed by the encryption scheme on the given x
* @param publicKey used to encrypt.
* @param x encrypted value
*/
SigmaElGamalEncryptedValueCommonInput::SigmaElGamalEncryptedValueCommonInput(bool isRandom,
		ElGamalOnGroupElementCiphertext cipher, ElGamalPublicKey publicKey, const shared_ptr<GroupElement> & x)
		: publicKey(publicKey), cipher(cipher) {
	this->isRandom = isRandom;
	this->x = x;
}

string SigmaElGamalEncryptedValueCommonInput::toString() {
	string output = isRandom? "1" : "0";
	output += ":";
	output += x->generateSendableData()->toString();
	output += ":";
	output += publicKey.generateSendableData()->toString();
	output += ":";
	output += cipher.generateSendableData()->toString();
	return output;
}

/**
* Sets the given ciphertext, public key, encrypted value and private key.
* @param isRandomness represents if the encryption was done by private key knowledge or by a randomness knowledge.
* @param cipher ciphertext outputed by the encryption scheme on the given x
* @param publicKey used to encrypt.
* @param x encrypted value
* @param privateKey used to decrypt.
*/
SigmaElGamalEncryptedValuePrivKeyProverInput::SigmaElGamalEncryptedValuePrivKeyProverInput(ElGamalOnGroupElementCiphertext cipher,
			ElGamalPublicKey pubKey, const shared_ptr<GroupElement> & x, ElGamalPrivateKey privateKey)
			: privateKey(privateKey){
	input = make_shared<SigmaElGamalEncryptedValueCommonInput>(false, cipher, pubKey, x);
}

/**
* Sets the given ciphertext, public key, encrypted value and random value used to encrypt.<p>
* @param isRandomness represents if the encryption was done by private key knowledge or by a randomness knowledge.
* @param cipher ciphertext outputed by the encryption scheme on the given x
* @param publicKey used to encrypt.
* @param x encrypted value
* @param r random value used to encrypt.
*/
SigmaElGamalEncryptedValueRandomnessProverInput::SigmaElGamalEncryptedValueRandomnessProverInput(ElGamalOnGroupElementCiphertext cipher,
					 ElGamalPublicKey pubKey, const shared_ptr<GroupElement> & x, const biginteger & r) {
	input = make_shared<SigmaElGamalEncryptedValueCommonInput>(true, cipher, pubKey, x);
	this->r = r;
}

/**
* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
* @param dlog
* @param t Soundness parameter in BITS.
* @param random
*/
SigmaElGamalEncryptedValueSimulator::SigmaElGamalEncryptedValueSimulator(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & prg)
	: dhSim(dlog, t, prg) {
	//Creates the underlying SigmaDHSimulator object with the given parameters.
	this->dlog = dlog;
}

/**
* Computes the simulator computation with the given challenge.
* @param input MUST be an instance of SigmaElGamalEncryptedValueCommonInput.
* @param challenge
* @return the output of the computation - (a, e, z).
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
* @throws IllegalArgumentException if input is not the expected.
*/
shared_ptr<SigmaSimulatorOutput> SigmaElGamalEncryptedValueSimulator::simulate(SigmaCommonInput* input, const vector<byte> & challenge) {
	auto underlyingInput = checkAndCreateUnderlyingInput(input);

	//Delegates the computation to the underlying Sigma DH simulator.
	return dhSim.simulate(underlyingInput.get(), challenge);

}

/**
* Computes the simulator computation with a randomly chosen challenge.
* @param input MUST be an instance of SigmaElGamalEncryptedValueInput.
* @return the output of the computation - (a, e, z).
* @throws IllegalArgumentException if input is not the expected.
*/
shared_ptr<SigmaSimulatorOutput> SigmaElGamalEncryptedValueSimulator::simulate(SigmaCommonInput* input) {
	auto underlyingInput = checkAndCreateUnderlyingInput(input);

	//Delegates the computation to the underlying Sigma DH simulator.
	return dhSim.simulate(underlyingInput.get());

}

/**
* Checks the given input and creates the input for the underlying DH simulator according to it.
* @param in MUST be an instance of SigmaElGamalEncryptedValueCommonInput.
* @return SigmaDHInput the input for the underlying simulator.
* @throws IllegalArgumentException if input is not the expected.
*/
shared_ptr<SigmaDHCommonInput> SigmaElGamalEncryptedValueSimulator::checkAndCreateUnderlyingInput(SigmaCommonInput* in) {
	auto params = dynamic_cast<SigmaElGamalEncryptedValueCommonInput*>(in);

	if (in == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalEncryptedValueCommonInput");
	}

	bool isRandomness = params->isRandomness();
	//Converts the given input to the necessary input to the underlying SigmaDHVerifier.
	shared_ptr<GroupElement> h, u, v;

	//In case we use knowledge of the private key, the input should be:
	// (h, u, v) = (c1, h, c2/x) 
	if (!isRandomness) {

		//h = c1;
		h = params->getCipher().getC1();
		//u = h;
		u = params->getPublicKey().getH();	
	}
	//In case we use knowledge of the randomness used to encrypt:
	// (h,u,v, w) = (h,c1,c2/x, r)
	if (isRandomness) {
		//h = h;
		h = params->getPublicKey().getH();
		//u = c1;
		u = params->getCipher().getC1();
	}

	//v = c2/x = c2*x^(-1)
	auto c2 = params->getCipher().getC2();
	auto xInverse = dlog->getInverse(params->getX().get());
	v = dlog->multiplyGroupElements(c2.get(), xInverse.get());

	//Create an input object to the underlying sigma DH verifier.
	return make_shared<SigmaDHCommonInput>(h, u, v);
}

/**
* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
* @param dlog
* @param t Soundness parameter in BITS.
* @param random
*/
SigmaElGamalEncryptedValueProverComputation::SigmaElGamalEncryptedValueProverComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & prg)
	: sigmaDH(dlog, t, prg) {
	this->dlog = dlog;
	this->prg = prg;
	this->t = t;
}

shared_ptr<SigmaDHProverInput> SigmaElGamalEncryptedValueProverComputation::convertInput(SigmaProverInput* in) {

	//Converts the given input to the necessary input to the underlying SigmaDHProver.
	shared_ptr<GroupElement> h, u, v;
	shared_ptr<SigmaElGamalEncryptedValueCommonInput> params;
	biginteger w;

	//In case we use knowledge of the private key, the input should be:
	// (h, u, v, w) = (c1, h, c2/x, w) 
	auto keyInput = dynamic_cast<SigmaElGamalEncryptedValuePrivKeyProverInput*>(in);
	auto randomInput = dynamic_cast<SigmaElGamalEncryptedValueRandomnessProverInput*>(in);
	if (keyInput != NULL) {
		params = dynamic_pointer_cast<SigmaElGamalEncryptedValueCommonInput>(keyInput->getCommonInput());
		//h = c1;
		h = params->getCipher().getC1();
		//u = h;
		u = params->getPublicKey().getH();
		
		//get the private key.
		w = keyInput->getPrivateKey().getX();
	}
	//In case we use knowledge of the randomness used to encrypt:
	// (h,u,v, w) = (h,c1,c2/x, r)
	else if (randomInput != NULL) {
		params = dynamic_pointer_cast<SigmaElGamalEncryptedValueCommonInput>(randomInput->getCommonInput());
		//h = h;
		h = params->getPublicKey().getH();
		//u = c1;
		u = params->getCipher().getC1();
		//get the randomness.
		w = randomInput->getR();
	}
	else {
		throw invalid_argument("the given input must be an instance of SigmaElGamalEncryptedValuePrivKeyProverInput or SigmaElGamalEncryptedValueRandomnessProverInput");
	}

	//v = c2/x = c2*x^(-1)
	auto c2 = params->getCipher().getC2();
	auto xInverse = dlog->getInverse(params->getX().get());
	v = dlog->multiplyGroupElements(c2.get(), xInverse.get());
	//Create an input object to the underlying sigma DH prover.
	return make_shared<SigmaDHProverInput>(h, u, v, w);

}

/**
* Computes the first message of the protocol.
* @return the computed message
*/
shared_ptr<SigmaProtocolMsg> SigmaElGamalEncryptedValueProverComputation::computeFirstMsg(const shared_ptr<SigmaProverInput> & input) {
		//Converts the input to the underlying prover.
		//Delegates the computation to the underlying Sigma DH prover.
		return sigmaDH.computeFirstMsg(convertInput(input.get()));
	}

/**
* Computes the second message of the protocol.
* @param challenge
* @return the computed message.
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
*/
shared_ptr<SigmaProtocolMsg> SigmaElGamalEncryptedValueProverComputation::computeSecondMsg(const vector<byte> & challenge) {
	//Delegates the computation to the underlying Sigma DH prover.
	return sigmaDH.computeSecondMsg(challenge);

}

/**
* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
* @param dlog
* @param t Soundness parameter in BITS.
* @param random
* @throws InvalidDlogGroupException if the given dlog is invalid.
*/
SigmaElGamalEncryptedValueVerifierComputation::SigmaElGamalEncryptedValueVerifierComputation(const shared_ptr<DlogGroup> & dlog,
	int t) : sigmaDH(dlog, t) {
	this->dlog = dlog;
}

shared_ptr<SigmaDHCommonInput> SigmaElGamalEncryptedValueVerifierComputation::convertInput(SigmaCommonInput* in) {
	auto params = dynamic_cast<SigmaElGamalEncryptedValueCommonInput*>(in);

	if (in == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalEncryptedValueCommonInput");
	}

	bool isRandomness = params->isRandomness();
	//Converts the given input to the necessary input to the underlying SigmaDHVerifier.
	shared_ptr<GroupElement> h, u, v;

	//In case we use knowledge of the private key, the input should be:
	// (h, u, v) = (c1, h, c2/x) 
	if (!isRandomness) {

		//h = c1;
		h = params->getCipher().getC1();
		//u = h;
		u = params->getPublicKey().getH();
	}
	//In case we use knowledge of the randomness used to encrypt:
	// (h,u,v, w) = (h,c1,c2/x, r)
	if (isRandomness) {
		//h = h;
		h = params->getPublicKey().getH();
		//u = c1;
		u = params->getCipher().getC1();
	}

	//v = c2/x = c2*x^(-1)
	auto c2 = params->getCipher().getC2();
	auto xInverse = dlog->getInverse(params->getX().get());
	v = dlog->multiplyGroupElements(c2.get(), xInverse.get());

	//Create an input object to the underlying sigma DH verifier.
	return make_shared<SigmaDHCommonInput>(h, u, v);
}

/**
* Verifies the proof.
* @param z second message from prover
* @return true if the proof has been verified; false, otherwise.
* @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaDHMsg
* @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
*/
bool SigmaElGamalEncryptedValueVerifierComputation::verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) {
	//converts the input to the underlying verifier.
	//Delegates to the underlying Sigma DH verifier.
	return sigmaDH.verify(convertInput(input).get(), a, z);
}