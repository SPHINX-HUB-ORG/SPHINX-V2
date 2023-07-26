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
#include "../primitives/Prg.hpp"

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaDamgardJurikEncryptedZero verifier and simulator.
* In SigmaProtocolDamgardJurikEncryptedZero, the common input contains DamgardJurikPublicKey and a BigIntegerCiphertext.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJEncryptedZeroCommonInput : public SigmaCommonInput {

private:
	DamgardJurikPublicKey publicKey;
	BigIntegerCiphertext cipher;

	/**
	* Sets the given public key and ciphertext.
	* @param publicKey used to encrypt.
	* @param cipher encryption on the given plaintext.
	*/
public:
	SigmaDJEncryptedZeroCommonInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext cipher) : publicKey(publicKey), cipher(cipher){}

	/**
	* Returns the public key used to encrypt.
	*/
	DamgardJurikPublicKey getPublicKey() { return publicKey; }

	/**
	* Returns the ciphertext which is an encryption on the plaintext.
	* @return ciphertext which is an encryption on the plaintext.
	*/
	BigIntegerCiphertext getCiphertext() { return cipher; }

	string toString() override;
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaDamgardJurikEncryptedZeroProver.
* In SigmaProtocolDamgardJurikEncryptedZero, the prover gets DamgardJurikPublicKey, BigIntegerCiphertext and the random BigInteger used to encrypt.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJEncryptedZeroProverInput : public SigmaProverInput {

private:
	shared_ptr<SigmaDJEncryptedZeroCommonInput> input;
	biginteger r; //randomness used to encrypt.

public:
	/**
	* Sets the given public key, ciphertext and random value used to encrypt.
	* @param publicKey used to encrypt.
	* @param cipher encryption on the given plaintext.
	* @param r random value used to encrypt.
	*/
	SigmaDJEncryptedZeroProverInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext cipher, const biginteger & r) {
		input = make_shared<SigmaDJEncryptedZeroCommonInput>(publicKey, cipher);
		this->r = r;
	}

	/**
	* This protocol assumes that the prover knows the randomness used to encrypt.
	* If the prover knows the secret key, then it can compute (once) the value m=n^(-1) mod phi(n)=n^(-1) mod (p-1)(q-1).
	* Then, it can recover the randomness r from c by computing c^m mod n (this equals r^(n/n) mod n = r).
	* Once given r, the prover can proceed with the protocol.
	* @param publicKey used to encrypt.
	* @param cipher encryption on the given plaintext.
	* @param privateKey used for decrypt.
	*/
	SigmaDJEncryptedZeroProverInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext cipher, DamgardJurikPrivateKey privateKey) {
		input = make_shared<SigmaDJEncryptedZeroCommonInput>(publicKey, cipher);

		//Calculate r from the given private key.
		biginteger p = privateKey.getP();
		biginteger q = privateKey.getQ();
		biginteger n = p * q;
		//(p-1)*(q-1)
		biginteger phiN = (p - 1) * (q - 1);
		//m = n^(-1) mod (p-1)(q-1).
		biginteger m = MathAlgorithms::modInverse(n, phiN);
		//r = c^m mod n
		r = mp::powm(cipher.getCipher(), m, n);
	}

	/**
	* Returns the random value used to encrypt.
	* @return random value used to encrypt.
	*/
	biginteger getR() {	return r; }

	shared_ptr<SigmaCommonInput> getCommonInput() override { return input; };
};

/**
* Concrete implementation of Sigma Simulator.<P>
* This implementation simulates the case that the prover convince a verifier that a ciphertext is an encryption of 0 (or an Nth power).<p>
*
* The pseudo code of this protocol can be found in Protocol 1.11 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJEncryptedZeroSimulator : public SigmaSimulator {

	/*
	This class computes the following calculations:
	SAMPLE a random value z <- Z*n
	COMPUTE a = z^N/c^e mod N'
	OUTPUT (a,e,z)
	*/

private:
	int t; 						// Soundness parameter in BITS.
	int lengthParameter;		// Length parameter in BITS.
	shared_ptr<PrgFromOpenSSLAES> random;

	/**
	* Checks the validity of the given soundness parameter.<p>
	* t must be less than a third of the length of the public key n.
	* @return true if the soundness parameter is valid; false, otherwise.
	*/
	bool checkSoundnessParam(const biginteger & modulus);

	/**
	* Checks if the given challenge length is equal to the soundness parameter.
	* @return true if the challenge length is t; false, otherwise.
	*/
	bool checkChallengeLength(const vector<byte> & challenge);

public:
	/**
	* Constructor that gets the soundness parameter, length parameter and SecureRandom.
	* @param t Soundness parameter in BITS.
	* @param lengthParameter length parameter in BITS.
	* @param random
	*/
	SigmaDJEncryptedZeroSimulator(int t = 40, int lengthParameter = 1, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return t; }

	/**
	* Computes the simulator computation with the given challenge.
	* @param input MUST be an instance of SigmaDJEncryptedZeroCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	* @throws IllegalArgumentException if the given input is not an instance of SigmaDJEncryptedZeroCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input, const vector<byte> & challenge)  override;

	/**
	* Computes the simulator computation with a randomly chosen challenge.
	* @param input MUST be an instance of SigmaDJEncryptedZeroInput.
	* @return the output of the computation - (a, e, z).
	* @throws IllegalArgumentException if the given input is not an instance of SigmaDJEncryptedZeroInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input) override; 
};

/**
* Concrete implementation of Sigma Protocol prover computation.<p>
*
* This protocol is used for a party to prove that a ciphertext is an encryption of 0 (or an Nth power).<p>
*
* The pseudo code of this protocol can be found in Protocol 1.11 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJEncryptedZeroProverComputation : public SigmaProverComputation, DJBasedSigma {

	/*
	This class computes the following calculations:
	SAMPLE random value s <- Z*n
	COMPUTE a = s^N mod N'
	COMPUTE z = s*r^e mod n.

	*/

private:
	int t; 									// Soundness parameter in BITS.
	int lengthParameter;					// Length parameter in BITS.
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<SigmaDJEncryptedZeroProverInput> input;	// Contains public key n, ciphertext c and the random value used to encrypt.
	biginteger n;							// Modulus.
	biginteger s;							// The random value chosen in the protocol.

	/**
	* Checks the validity of the given soundness parameter.<p>
	* t must be less than a third of the length of the public key n.
	* @return true if the soundness parameter is valid; false, otherwise.
	*/
	bool checkSoundnessParam(const biginteger & modulus);

	/**
	* Checks if the given challenge length is equal to the soundness parameter.
	* @return true if the challenge length is t; false, otherwise.
	*/
	bool checkChallengeLength(const vector<byte> & challenge) {
		//If the challenge's length is equal to t, return true. else, return false.
		return ((int)challenge.size() == (t / 8) ? true : false);
	}

public:
	/**
	* Constructor that gets the soundness parameter, length parameter and SecureRandom.
	* @param t Soundness parameter in BITS.
	* @param lengthParameter length parameter in BITS.
	* @param random
	*/
	SigmaDJEncryptedZeroProverComputation(int t = 40, int lengthParameter = 1, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return t; }

	/**
	* Computes the first message of the protocol.<p>
	* "SAMPLE random value s <- Z*n<p>
	* COMPUTE a = s^N mod N'".
	* @param input MUST be an instance of SigmaDJEncryptedZeroProverInput.
	* @return the computed message
	* @throws IllegalArgumentException if input is not an instance of SigmaDJEncryptedZeroProverInput.
	*/
	shared_ptr<SigmaProtocolMsg> computeFirstMsg(const shared_ptr<SigmaProverInput> & input) override;

	/**
	* Computes the second message of the protocol.<p>
	* "COMPUTE z = s*r^e mod n".
	* @param challenge
	* @return the computed message.
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	*/
	shared_ptr<SigmaProtocolMsg> computeSecondMsg(const vector<byte> & challenge) override;

	/**
	* Returns the simulator that matches this sigma protocol prover.
	* @return SigmaDamgardJurikEncryptedZeroSimulator
	*/
	shared_ptr<SigmaSimulator> getSimulator() override {
		return make_shared<SigmaDJEncryptedZeroSimulator>(t, lengthParameter, random);
	}

};

/**
* Concrete implementation of Sigma Protocol verifier computation. <p>
*
* This protocol is used for a party to prove that a ciphertext is an encryption of 0 (or an Nth power).<p>
*
* The pseudo code of this protocol can be found in Protocol 1.11 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJEncryptedZeroVerifierComputation : public SigmaVerifierComputation, DJBasedSigma {

	/*
	This class computes the following calculations:
	SAMPLE a random challenge  e -< {0, 1}^t
	ACC IFF c,a,z are relatively prime to n AND z^N = (a*c^e) mod N'

	*/

private:
	int t; 						// Soundness parameter in BITS.
	int lengthParameter;		// Length parameter in BITS.
	shared_ptr<PrgFromOpenSSLAES> random;
	vector<byte> e;				//The challenge.
	biginteger n;				//The modulus

	/**
	* Checks the validity of the given soundness parameter. <p>
	* t must be less than a third of the length of the public key n.
	* @return true if the soundness parameter is valid; false, otherwise.
	*/
	bool checkSoundnessParam(const biginteger & modulus);

public:
	/**
	* Constructor that gets the soundness parameter, length parameter and SecureRandom.
	* @param t Soundness parameter in BITS.
	* @param lengthParameter length parameter in BITS.
	* @param random
	*/
	SigmaDJEncryptedZeroVerifierComputation(int t = 40, int lengthParameter = 1, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());


	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return t; }

	/**
	* Samples the challenge of the protocol.<p>
	* 	"SAMPLE a random challenge e<-{0,1}^t".
	*/
	void sampleChallenge() override;

	/**
	* Sets the given challenge.
	* @param challenge
	*/
	void setChallenge(const vector<byte> & challenge) override {
		e = challenge;
	}

	/**
	* Returns the sampled challenge.
	* @return the challenge.
	*/
	vector<byte> getChallenge() override { return e; }

	/**
	* Computes the verification of the protocol.<p>
	* 	"ACC IFF c,a,z are relatively prime to n AND z^N = (a*c^e) mod N'".
	* @param input MUST be an instance of SigmaDJEncryptedZeroCommonInput.
	* @param z second message from prover
	* @return true if the proof has been verified; false, otherwise.
	* @throws IllegalArgumentException if input is not an instance of SigmaDJEncryptedZeroCommonInput.
	* @throws IllegalArgumentException if the one of the prover's messages are not an instance of SigmaBIMsg
	*/
	bool verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) override;
};

