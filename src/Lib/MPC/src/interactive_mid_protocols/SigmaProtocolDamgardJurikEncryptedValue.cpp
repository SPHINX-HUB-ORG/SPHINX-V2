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


#include "../../include/interactive_mid_protocols/SigmaProtocolDamgardJurikEncryptedValue.hpp"

string SigmaDJEncryptedValueCommonInput::toString() {
	string output = publicKey.generateSendableData()->toString();
	output += ":";
	output += cipher.generateSendableData()->toString();
	output += ":";
	output += plaintext.generateSendableData()->toString();
	return output;
}
/**
* Sets the given public key, ciphertext, plaintext and random value used to encrypt.
* @param publicKey used to encrypt.
* @param cipher encryption on the given plaintext.
* @param plaintext that has been encrypted.
* @param r random value used to encrypt.
*/
SigmaDJEncryptedValueProverInput::SigmaDJEncryptedValueProverInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext cipher, BigIntegerPlainText plaintext, const biginteger & r) {
	input = make_shared<SigmaDJEncryptedValueCommonInput>(publicKey, cipher, plaintext);
	this->r = r;
}

/**
* This protocol assumes that the prover knows the randomness used to encrypt. <p>
* If the prover knows the secret key, then it can compute (once) the value m=n^(-1) mod phi(n)=n^(-1) mod (p-1)(q-1).<p>
* Then, it can recover the randomness r from c by computing c^m mod n (this equals r^(n/n) mod n = r). <p>
* Once given r, the prover can proceed with the protocol.<p>
* @param publicKey used to encrypt.
* @param cipher encryption on the given plaintext.
* @param plaintext that has been encrypted.
* @param privateKey used for decrypt.
*/
SigmaDJEncryptedValueProverInput::SigmaDJEncryptedValueProverInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext cipher, BigIntegerPlainText plaintext, DamgardJurikPrivateKey privateKey) {
	input = make_shared<SigmaDJEncryptedValueCommonInput>(publicKey, cipher, plaintext);
	//Calculate r from the given private key.
	biginteger p = privateKey.getP();
	biginteger q = privateKey.getQ();
	biginteger pMinusOne = p - 1;
	biginteger qMinusOne = q - 1;
	biginteger n = p * q;
	//(p-1)*(q-1)
	biginteger phiN = pMinusOne * qMinusOne;
	//m = n^(-1) mod (p-1)(q-1).
	biginteger m = MathAlgorithms::modInverse(n, phiN);
	//r = c^m mod n
	r = mp::powm(cipher.getCipher(), m, n);
}

/**
* Computes the simulator computation with the given challenge.
* @param input MUST be an instance of SigmaDJEncryptedValueCommonInput.
* @param challenge
* @return the output of the computation - (a, e, z).
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
* @throws IllegalArgumentException if input is not the expected.
*/
shared_ptr<SigmaSimulatorOutput> SigmaDJEncryptedValueSimulator::simulate(SigmaCommonInput* input, const vector<byte> & challenge) {
	
	//Delegates the computation to the underlying SigmaDJEncryptedZeroSimulator.
	return djSim.simulate(checkAndCreateUnderlyingInput(input).get(), challenge);

}

/**
* Computes the simulator computation with a randomly chosen challenge.
* @param input MUST be an instance of SigmaDJEncryptedValueInput.
* @return the output of the computation - (a, e, z).
* @throws IllegalArgumentException if input is not the expected.
*/
shared_ptr<SigmaSimulatorOutput> SigmaDJEncryptedValueSimulator::simulate(SigmaCommonInput* input) {
	
	//Delegates the computation to the underlying SigmaDJEncryptedZeroSimulator.
	return djSim.simulate(checkAndCreateUnderlyingInput(input).get());

}

/**
* Converts the given input to an input object for the underlying simulator.
* @param in MUST be an instance of SigmaDJEncryptedValueCommonInput.
* @return SigmaDJEncryptedZeroInput the converted input.
*/
shared_ptr<SigmaDJEncryptedZeroCommonInput> SigmaDJEncryptedValueSimulator::checkAndCreateUnderlyingInput(SigmaCommonInput* in) {

	auto input = dynamic_cast<SigmaDJEncryptedValueCommonInput*>(in);
	if (input == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaDJEncryptedValueCommonInput");
	}

	//Get public key, cipher and plaintext.
	DamgardJurikPublicKey pubKey = input->getPublicKey();
	BigIntegerPlainText plaintext = input->getPlaintext();
	BigIntegerCiphertext cipher = input->getCiphertext();

	//Convert the cipher c to c' = c*(1+n)^(-x)
	biginteger n = pubKey.getModulus();
	biginteger nPlusOne = n + 1;

	//calculate N' = n^(s+1).
	biginteger NTag = mp::pow(n, lengthParameter + 1);

	//Calculate (n+1)^(-x)
	biginteger minusX = plaintext.getX() * (-1);
	biginteger multVal = mp::powm(nPlusOne, minusX, NTag);

	//Calculate the ciphertext for DamgardJurikEncryptedZero - c*(n+1)^(-x).
	biginteger newCipher = (cipher.getCipher() * multVal) % (NTag);
	BigIntegerCiphertext cipherTag(newCipher);

	//Create an input object to the underlying sigmaDamgardJurik simulator.
	return make_shared<SigmaDJEncryptedZeroCommonInput>(pubKey, cipherTag);
}

/**
* Computes the first message of the protocol.
* @param input MUST be an instance of SigmaDJEncryptedValueProverInput.
* @return the computed message
* @throws IllegalArgumentException if input is not an instance of SigmaDJEncryptedValueProverInput.
*/
shared_ptr<SigmaProtocolMsg> SigmaDJEncryptedValueProverComputation::computeFirstMsg(const shared_ptr<SigmaProverInput> & input) {
	/*
	* Converts the input (n, c, x, r) to (n, c', r) where c' = c*(1+n)^(-x) mod N'.
	*/
	auto in = dynamic_pointer_cast<SigmaDJEncryptedValueProverInput>(input);
	if (in == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaDJEncryptedValueProverInput");
	}
	
	//Get public key, cipher and plaintext.
	auto params = dynamic_pointer_cast<SigmaDJEncryptedValueCommonInput>(in->getCommonInput());
	DamgardJurikPublicKey pubKey = params->getPublicKey();
	BigIntegerPlainText plaintext = params->getPlaintext();
	BigIntegerCiphertext cipher = params->getCiphertext();

	//Convert the cipher c to c' = c*(1+n)^(-x)
	biginteger n = pubKey.getModulus();
	biginteger nPlusOne = n = 1;

	//calculate N' = n^(s+1).
	biginteger NTag = mp::pow(n, lengthParameter + 1);

	//Calculate (n+1)^(-x)
	biginteger minusX = plaintext.getX() * (-1);
	biginteger multVal = mp::powm(nPlusOne, minusX, NTag);

	//Calculate the ciphertext for DamgardJurikEncryptedZero - c*(n+1)^(-x).
	biginteger newCipher = (cipher.getCipher() * multVal) % (NTag);
	BigIntegerCiphertext cipherTag(newCipher);

	//Create an input object to the underlying sigmaDamgardJurik prover.
	auto underlyingInput = make_shared<SigmaDJEncryptedZeroProverInput>(pubKey, cipherTag, in->getR());

	//Delegates the computation to the underlying sigmaDamgardJurik prover.
	return sigmaDamgardJurik.computeFirstMsg(underlyingInput);
}

/**
* Computes the second message of the protocol.
* @param challenge
* @return the computed message.
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
*/
shared_ptr<SigmaProtocolMsg> SigmaDJEncryptedValueProverComputation::computeSecondMsg(const vector<byte> & challenge) {
	//Delegates the computation to the underlying sigmaDamgardJurik prover.
	return sigmaDamgardJurik.computeSecondMsg(challenge);
}

/**
* Returns the soundness parameter for this Sigma protocol.
* @return t soundness parameter
*/
int SigmaDJEncryptedValueVerifierComputation::getSoundnessParam() { 
	return sigmaDamgardJurik.getSoundnessParam(); 
}

/**
* Samples the challenge e <- {0,1}^t.
*/
void SigmaDJEncryptedValueVerifierComputation::sampleChallenge() {
	//Delegates to the underlying sigmaDamgardJurik verifier.
	sigmaDamgardJurik.sampleChallenge();
}

/**
* Sets the given challenge.
* @param challenge
*/
void SigmaDJEncryptedValueVerifierComputation::setChallenge(const vector<byte> & challenge) {

	//Delegates to the underlying sigmaDamgardJurik verifier.
	sigmaDamgardJurik.setChallenge(challenge);

}

/**
* Returns the sampled challenge.
* @return the challenge.
*/
vector<byte> SigmaDJEncryptedValueVerifierComputation::getChallenge() {
	//Delegates to the underlying sigmaDamgardJurik verifier.
	return sigmaDamgardJurik.getChallenge();
}

/**
* Verifies the proof.
* @param z second message from prover
* @param input MUST be an instance of SigmaDJEncryptedValueCommonInput.
* @return true if the proof has been verified; false, otherwise.
* @throws IllegalArgumentException if input is not an instance of SigmaDJEncryptedValueCommonInput.
* @throws IllegalArgumentException if the messages of the prover are not an instance of SigmaBIMsg
*/
bool SigmaDJEncryptedValueVerifierComputation::verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) {
	/*
	* Converts the input (n, c, x) to (n, c') where c' = c*(1+n)^(-x) mod N'.
	*/
	auto in = dynamic_cast<SigmaDJEncryptedValueCommonInput*>(input);
	if (in == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaDJEncryptedValueCommonInput");
	}
	
	//Get public key, cipher and plaintext.
	DamgardJurikPublicKey pubKey = in->getPublicKey();
	BigIntegerPlainText plaintext = in->getPlaintext();
	BigIntegerCiphertext cipher = in->getCiphertext();

	//Convert the cipher c to c' = c*(1+n)^(-x)
	biginteger n = pubKey.getModulus();
	biginteger nPlusOne = n + 1;

	//calculate N' = n^(s+1).
	biginteger NTag = mp::pow(n, lengthParameter + 1);

	//Calculate (n+1)^(-x)
	biginteger minusX = plaintext.getX() * (-1);
	biginteger multVal = mp::powm(nPlusOne, minusX, NTag);

	//Calculate the ciphertext for DamgardJurikEncryptedZero - c*(n+1)^(-x).
	biginteger newCipher = (cipher.getCipher() * multVal) % (NTag);
	BigIntegerCiphertext cipherTag(newCipher);

	//Create an input object to the underlying sigmaDamgardJurik verifier.
	auto underlyingInput = new SigmaDJEncryptedZeroCommonInput(pubKey, cipherTag);
	auto temp = unique_ptr<SigmaDJEncryptedZeroCommonInput>(underlyingInput);

	//Delegates to the underlying sigmaDamgardJurik verifier.
	return sigmaDamgardJurik.verify(temp.get(), a, z);
}