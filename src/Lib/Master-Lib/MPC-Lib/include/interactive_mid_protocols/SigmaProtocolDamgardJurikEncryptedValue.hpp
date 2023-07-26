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


#pragma once
#include "SigmaProtocol.hpp"
#include "../mid_layer/DamgardJurikEnc.hpp"
#include "../../include/interactive_mid_protocols/SigmaProtocolDamgardJurikEncryptedZero.hpp"

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaDamgardJurikEncryptedValue verifier and simulator.<p>
* In SigmaProtocolDamgardJurikEncryptedValue, the common input contains DamgardJurikPublicKey, BigIntegerCiphertext and BigIntegerPlaintext.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJEncryptedValueCommonInput : public SigmaCommonInput {

private:
	DamgardJurikPublicKey publicKey;
	BigIntegerCiphertext cipher;
	BigIntegerPlainText plaintext;

public:
	/**
	* Sets the given public key, ciphertext and plaintext.
	* @param publicKey used to encrypt.
	* @param cipher encryption on the given plaintext.
	* @param plaintext that has been encrypted.
	*/
	SigmaDJEncryptedValueCommonInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext cipher, BigIntegerPlainText plaintext) 
		: publicKey(publicKey), cipher(cipher), plaintext(plaintext) {}

	/**
	* Returns the public key used to encrypt.
	* @return public key used to encrypt.
	*/
	DamgardJurikPublicKey getPublicKey() { return publicKey; }

	/**
	* Returns the ciphertext which is an encryption on the plaintext.
	* @return  ciphertext which is an encryption on the plaintext.
	*/
	BigIntegerCiphertext getCiphertext() { return cipher; }

	/**
	* Returns the plaintext that has been encrypted.
	* @return the plaintext that has been encrypted.
	*/
	BigIntegerPlainText getPlaintext() { return plaintext;	}

	string toString() override;
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaDamgardJurikEncryptedValueProver.<p>
* In SigmaProtocolDamgardJurikEncryptedValue, the prover gets DamgardJurikPublicKey, BigIntegerCiphertext, BigIntegerPlaintext and the random BigInteger used to encrypt.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJEncryptedValueProverInput :public SigmaProverInput {

private:
	shared_ptr<SigmaDJEncryptedValueCommonInput> input;
	biginteger r;

public:
	/**
	* Sets the given public key, ciphertext, plaintext and random value used to encrypt.
	* @param publicKey used to encrypt.
	* @param cipher encryption on the given plaintext.
	* @param plaintext that has been encrypted.
	* @param r random value used to encrypt.
	*/
	SigmaDJEncryptedValueProverInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext cipher, BigIntegerPlainText plaintext, const biginteger & r);

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
	SigmaDJEncryptedValueProverInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext cipher, BigIntegerPlainText plaintext, DamgardJurikPrivateKey privateKey);

	/**
	* Returns the random value used to encrypt.
	* @return random value used to encrypt.
	*/
	biginteger getR() {	return r; }

	shared_ptr<SigmaCommonInput> getCommonInput() override { return input; };
};

/**
* Concrete implementation of Sigma Simulator.<p>
*
* This implementation simulates the case that party who encrypted a value x proves that it indeed encrypted x.<P>
*
* The pseudo code of this protocol can be found in Protocol 1.12 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJEncryptedValueSimulator :public SigmaSimulator {

	/*
	This class uses an instance of SigmaDamgardJurikEncryptedZeroSimulator with:
	Common input: (n,c') where c'=c*(1+n)^(-x) mod N'
	*/

private:
	SigmaDJEncryptedZeroSimulator djSim; // Underlying SigmaDamgardJurikEncryptedZeroSimulator to use.
	int lengthParameter; 						   // Used in converting the input to the underlying input.

	/**
	 * Converts the given input to an input object for the underlying simulator.
	 * @param in MUST be an instance of SigmaDJEncryptedValueCommonInput.
	 * @return SigmaDJEncryptedZeroInput the converted input.
	*/
	shared_ptr<SigmaDJEncryptedZeroCommonInput> checkAndCreateUnderlyingInput(SigmaCommonInput* in);
														  
public:
	/**
	* Constructor that gets the soundness parameter, length parameter and SecureRandom.
	* @param t Soundness parameter in BITS.
	* @param lengthParameter length parameter in BITS.
	* @param random
	*/
	SigmaDJEncryptedValueSimulator(int t = 40, int lengthParameter = 1, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg()) : djSim(t, lengthParameter, prg) {
		this->lengthParameter = lengthParameter;
	}

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return djSim.getSoundnessParam(); }

	/**
	* Computes the simulator computation with the given challenge.
	* @param input MUST be an instance of SigmaDJEncryptedValueCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	* @throws IllegalArgumentException if input is not the expected.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input, const vector<byte> & challenge)  override;
		

	/**
	* Computes the simulator computation with a randomly chosen challenge.
	* @param input MUST be an instance of SigmaDJEncryptedValueInput.
	* @return the output of the computation - (a, e, z).
	* @throws IllegalArgumentException if input is not the expected.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input) override;

};

/**
* Concrete implementation of Sigma Protocol prover computation.<p>
*
* This protocol is used for a party who encrypted a value x to prove that it indeed encrypted x.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.12 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJEncryptedValueProverComputation : public SigmaProverComputation, DJBasedSigma {

	/*
	This class uses an instance of SigmaDamgardJurikEncryptedZeroProver with:
	Common input: (n,c') where c'=c*(1+n)^(-x) mod N'
	P's private input: a value r <- Zq such that c'=r^N mod N'.
	*/

private:
	SigmaDJEncryptedZeroProverComputation sigmaDamgardJurik;	//underlying SigmaDamgardJurikProver to use.
	shared_ptr<PrgFromOpenSSLAES> prg;
	int lengthParameter;									// length parameter in BITS.
	int t;

public:
	/**
	* Constructor that gets the soundness parameter, length parameter and SecureRandom.
	* @param t Soundness parameter in BITS.
	* @param lengthParameter length parameter in BITS.
	* @param random
	*/
	SigmaDJEncryptedValueProverComputation(int t = 40, int lengthParameter = 1, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg()) : sigmaDamgardJurik(t, lengthParameter, prg) {

		this->lengthParameter = lengthParameter;
		this->t = t;
		this->prg = prg;
	}

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return sigmaDamgardJurik.getSoundnessParam(); }

	/**
	* Computes the first message of the protocol.
	* @param input MUST be an instance of SigmaDJEncryptedValueProverInput.
	* @return the computed message
	* @throws IllegalArgumentException if input is not an instance of SigmaDJEncryptedValueProverInput.
	*/
	shared_ptr<SigmaProtocolMsg> computeFirstMsg(const shared_ptr<SigmaProverInput> & input) override;
		
	/**
	* Computes the second message of the protocol.
	* @param challenge
	* @return the computed message.
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	*/
	shared_ptr<SigmaProtocolMsg> computeSecondMsg(const vector<byte> & challenge) override;

	/**
	* Returns the simulator that matches this sigma protocol prover.
	* @return SigmaDamgardJurikEncryptedValueSimulator
	*/
	shared_ptr<SigmaSimulator> getSimulator() override {
		return make_shared<SigmaDJEncryptedValueSimulator>(t, lengthParameter, prg);
	}
};

/**
* Concrete implementation of Sigma Protocol verifier computation. <p>
*
* This protocol is used for a party who encrypted a value x to prove that it indeed encrypted x.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.12 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJEncryptedValueVerifierComputation : public SigmaVerifierComputation, DJBasedSigma {

	/*
	This class uses an instance of SigmaDamgardJurikEncryptedZeroVerifier with:
	Common input: (n,c') where c' =c*(1+n)^(-x) mod N'

	*/

private:
	SigmaDJEncryptedZeroVerifierComputation sigmaDamgardJurik;	//underlying SigmaDamgardJurikVerifier to use.
	int lengthParameter;										// length parameter in BITS

public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaDJEncryptedValueVerifierComputation(int t = 40, int lengthParameter = 1) : sigmaDamgardJurik(t, lengthParameter) {
		this->lengthParameter = lengthParameter;
	}

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override;

	/**
	* Samples the challenge e <- {0,1}^t.
	*/
	void sampleChallenge() override; 

	/**
	* Sets the given challenge.
	* @param challenge
	*/
	void setChallenge(const vector<byte> & challenge) override;

	/**
	* Returns the sampled challenge.
	* @return the challenge.
	*/
	vector<byte> getChallenge() override;

	/**
	* Verifies the proof.
	* @param z second message from prover
	* @param input MUST be an instance of SigmaDJEncryptedValueCommonInput.
	* @return true if the proof has been verified; false, otherwise.
	* @throws IllegalArgumentException if input is not an instance of SigmaDJEncryptedValueCommonInput.
	* @throws IllegalArgumentException if the messages of the prover are not an instance of SigmaBIMsg
	*/
	bool verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) override; 
};

