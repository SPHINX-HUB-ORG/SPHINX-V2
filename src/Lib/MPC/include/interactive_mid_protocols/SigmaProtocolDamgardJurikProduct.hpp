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
* Concrete implementation of SigmaProtocol input, used by the SigmaDamgardJurikProduct verifier and simulator.<p>
* In SigmaProtocolDamgardJurikProduct, the common input contains DamgardJurikPublicKey and three BigIntegerCiphertexts.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJProductCommonInput : public SigmaCommonInput {

private:
	DamgardJurikPublicKey publicKey;
	BigIntegerCiphertext cipher1;
	BigIntegerCiphertext cipher2;
	BigIntegerCiphertext cipher3;

public:
	/**
	* Sets the given public key and three ciphertexts.
	* @param publicKey used to encrypt.
	* @param c1 first ciphertext
	* @param c2 second ciphertext
	* @param c3 third ciphertext
	*/
	SigmaDJProductCommonInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext c1, BigIntegerCiphertext c2, BigIntegerCiphertext c3) 
		: publicKey(publicKey), cipher1(c1), cipher2(c2), cipher3(c3){}

	/**
	* Returns the public key used to encrypt.
	*/
	DamgardJurikPublicKey getPublicKey() {	return publicKey; }

	/**
	* Returns the first ciphertext.
	*/
	BigIntegerCiphertext getC1() {return cipher1; }

	/**
	* Returns the second ciphertext.
	*/
	BigIntegerCiphertext getC2() { return cipher2; }

	/**
	* Returns the third ciphertext.
	* @return the third ciphertext.
	*/
	BigIntegerCiphertext getC3() { return cipher3;}

	string toString() override;
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaDamgardJurikProductProver.<p>
* In SigmaProtocolDamgardJurikProduct, the prover gets DamgardJurikPublicKey, three BigIntegerCiphertexts and three random BigIntegers used to encrypt.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJProductProverInput : public SigmaProverInput {

private:
	shared_ptr<SigmaDJProductCommonInput> input;
	biginteger r1;
	biginteger r2;
	biginteger r3;
	BigIntegerPlainText x1;
	BigIntegerPlainText x2;

public:
	/**
	* Sets the given public key, three ciphertexts, three random values, and two plaintexts.
	* @param publicKey used to encrypt.
	* @param c1 first ciphertext
	* @param c2 second ciphertext
	* @param c3 third ciphertext
	* @param r1 first random number used to encrypt x1
	* @param r2 first random number used to encrypt x2
	* @param r3 first random number used to encrypt x3
	* @param x1 first plaintext
	* @param x2 second plaintext
	*/
	SigmaDJProductProverInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext c1, BigIntegerCiphertext c2, BigIntegerCiphertext c3,
		const biginteger & r1, const biginteger & r2, const biginteger & r3, BigIntegerPlainText x1, BigIntegerPlainText x2);

	/**
	* This protocol assumes that the prover knows the randomness used to encrypt.
	* If the prover knows the secret key, then it can compute (once) the value m=n^(-1) mod phi(n)=n^(-1) mod (p-1)(q-1).
	* Then, it can recover the randomness ri from ci by computing ci^m mod n (this equals ri^(n/n) mod n = ri).
	* Once given r, the prover can proceed with the protocol.
	* @param c1 first ciphertext
	* @param c2 second ciphertext
	* @param c3 third ciphertext
	* @param privateKey used to recover r1, r2, r3
	* @param x1 first plaintext
	* @param x2 second plaintext
	*
	*/
	SigmaDJProductProverInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext c1, BigIntegerCiphertext c2, BigIntegerCiphertext c3,
		DamgardJurikPrivateKey privateKey, BigIntegerPlainText x1, BigIntegerPlainText x2);

	/**
	* Returns the random number used to encrypt r1.
	*/
	biginteger getR1() { return r1; }

	/**
	* Returns the random number used to encrypt r2.
	*/
	biginteger getR2() { return r2; }

	/**
	* Returns the random number used to encrypt r3.
	*/
	biginteger getR3() { return r3; }

	/**
	* Returns the first plaintext.
	*/
	BigIntegerPlainText getX1() { return x1; }

	/**
	* Returns the second plaintext.
	* @return the second plaintext.
	*/
	BigIntegerPlainText getX2() { return x2; }

	shared_ptr<SigmaCommonInput> getCommonInput() override { return input; };
};

/**
* Concrete implementation of SigmaProtocol message.
* This message contains two BigIntegers and used when the DamgardJurikProduct prover send the first message to the verifier.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJProductFirstMsg : public SigmaProtocolMsg {

private:
	biginteger a1;
	biginteger a2;

public:
	SigmaDJProductFirstMsg(const biginteger & a1, const biginteger & a2) {
		this->a1 = a1;
		this->a2 = a2;
	}

	biginteger getA1() { return a1; }

	biginteger getA2() { return a2; }

	string toString() override;

	void initFromString(const string & row) override;
};

/**
* Concrete implementation of SigmaProtocol message.
* This message contains three BigIntegers and used when the DamgardJurikProduct prover send the second message to the verifier.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJProductSecondMsg : public SigmaProtocolMsg {

private:
	biginteger z1;
	biginteger z2;
	biginteger z3;

public:
	SigmaDJProductSecondMsg(const biginteger & z1, const biginteger & z2, const biginteger & z3) {
		this->z1 = z1;
		this->z2 = z2;
		this->z3 = z3;
	}

	biginteger getZ1() { return z1; }

	biginteger getZ2() { return z2;	}

	biginteger getZ3() { return z3;	}

	string toString() override;

	void initFromString(const string & row) override;
};

/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that 3 ciphertexts c1,c2,c3
* are encryptions of values x1,x2,x3 s.t. x1*x2=x3 mod N.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.13 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJProductSimulator : public SigmaSimulator {

	/*
	This class computes the following calculations:
	SAMPLE random values z1 <- ZN, z2 <- Z*n, z3 <- Z*n
	COMPUTE a1 = (1+n)^z1*(z2^N/c1^e) mod N' AND a2 = c2^z1/(z3^N*c3^e) mod N'
	OUTPUT (a,e,z) where a = (a1,a2) AND z=(z1,z2,z3)

	*/

private:
	int t; 					// Soundness parameter in BITS.
	int lengthParameter;	// Length parameter in BITS.
	shared_ptr<PrgFromOpenSSLAES> random;

	/**
	* Checks the validity of the given soundness parameter.
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
	SigmaDJProductSimulator(int t = 40, int lengthParameter = 1, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return t; }

	/**
	* Computes the simulator computation with the given challenge.
	* @param input MUST be an instance of SigmaDJProductCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	* @throws IllegalArgumentException if the given input is not an instance of SigmaDJProductCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input, const vector<byte> & challenge)  override;

	/**
	* Computes the simulator computation with a randomly chosen challenge.
	* @param input MUST be an instance of SigmaDJProductInput.
	* @return the output of the computation - (a, e, z).
	* @throws IllegalArgumentException if the given input is not an instance of SigmaDJProductInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input) override;
};

/**
* Concrete implementation of Sigma Protocol prover computation.<p>
*
* This protocol is used for a party to prove that 3 ciphertexts c1,c2,c3 are encryptions of values x1,x2,x3 s.t. x1*x2=x3 mod N.<P>
*
* The pseudo code of this protocol can be found in Protocol 1.13 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJProductProverComputation : public SigmaProverComputation, DJBasedSigma {
	/*
	This class computes the following calculations:
	SAMPLE random values d <- ZN, rd <- Z*n, rdb <- Z*n
	COMPUTE a1=(1+n)^drd^N mod N' and a2=(1+n)^(d*x2)rdb^N mod N' and SET a = (a1,a2)
	COMPUTE z1=e*x1+d mod N, z2 = r1^e*rd mod n, z3=(r2^z1)/(rdb*r3^e) mod n, and SET z=(z1,z2,z3)
	*/

private:
	int t; 								// Soundness parameter in BITS.
	int lengthParameter;				// Length parameter in BITS.
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<SigmaDJProductProverInput> input;	// Contains n, 3 ciphertexts, 3 plaintexts and 3 random values used to encrypt.
	biginteger n;						// Modulus
	biginteger N, NTag;					// N = n^lengthParameter and N' = n^(lengthParameter+1).
	biginteger d, rd, rdb;				// The random value chosen in the protocol.

	/**
	* Checks the validity of the given soundness parameter.
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
	SigmaDJProductProverComputation(int t = 40, int lengthParameter = 1, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());


	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return t; }

	/**
	* Computes the first message of the protocol.<p>
	* "SAMPLE random values d <- ZN, rd <- Z*n, rdb <- Z*n<p>
	*  COMPUTE a1 = (1+n)^d*rd^N mod N' and a2 = ((1+n)^(d*x2))*(rdb^N) mod N' and SET a = (a1,a2)".
	* @param input MUST be an instance of SigmaDJProductProverInput.
	* @return the computed message
	* @throws IllegalArgumentException if input is not an instance of SigmaDJProductProverInput.
	*/
	shared_ptr<SigmaProtocolMsg> computeFirstMsg(const shared_ptr<SigmaProverInput> & input) override;

	/**
	* Computes the second message of the protocol.<p>
	* "COMPUTE z1=e^x1+d mod N, z2 = r1^e*rd mod n, z3=(r2^z1)/(rdb*r3^e) mod n, and SET z=(z1,z2,z3)".
	* @param challenge
	* @return the computed message.
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	*/
	shared_ptr<SigmaProtocolMsg> computeSecondMsg(const vector<byte> & challenge) override;

	/**
	* Returns the simulator that matches this sigma protocol prover.
	* @return SigmaDamgardJurikProductSimulator
	*/
	shared_ptr<SigmaSimulator> getSimulator() override {
		return make_shared<SigmaDJProductSimulator>(t, lengthParameter, random);
	}
};

/**
* Concrete implementation of Sigma Protocol verifier computation. <p>
*
* This protocol is used for a party to prove that 3 ciphertexts c1,c2,c3 are encryptions of values x1,x2,x3 s.t. x1*x2=x3 mod N.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.13 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDJProductVerifierComputation : public SigmaVerifierComputation, DJBasedSigma {

	/*
	This class computes the following calculations:
	SAMPLE a random challenge  e -< {0, 1}^t
	ACC IFF c1,c2,c3,a1,a2,z1,z2,z3 are relatively prime to n
	AND c1^e*a1 = (1+n)^z1*z2^N mod N'
	AND (c2^z1)/(a2*c3^e) = z3^N mod N'

	*/

private:
	int t; 						// Soundness parameter in BITS.
	int lengthParameter;		// Length parameter in BITS.
	shared_ptr<PrgFromOpenSSLAES> random;
	vector<byte> e;					// The challenge.

	/**
	* Checks the validity of the given soundness parameter.<p>
	* t must be less than a third of the length of the public key n.
	* @return true if the soundness parameter is valid; false, otherwise.
	*/
	bool checkSoundnessParam(const biginteger & modulus) {
		//If soundness parameter is not less than a third of the publicKey n, return false.
		int third = NumberOfBits(modulus) / 3;
		return (t < third);
	}

	bool areRelativelyPrime(const biginteger & n, const biginteger & c1, const biginteger & c2, const biginteger & a1, const biginteger & a2, const biginteger & z1,
		const biginteger & z2, const biginteger & z3);

	void checkInput(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z);

public:
	/**
	* Constructor that gets the soundness parameter, length parameter and SecureRandom.
	* @param t Soundness parameter in BITS.
	* @param lengthParameter length parameter in BITS.
	* @param random
	*/
	SigmaDJProductVerifierComputation(int t = 40, int lengthParameter = 1, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

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
	void setChallenge(const vector<byte> & challenge) override { e = challenge;	}

	/**
	* Returns the sampled challenge.
	* @return the challenge.
	*/
	vector<byte> getChallenge() override { return e; }

	/**
	* Computes the verification of the protocol.<p>
	* 	"ACC IFF c1,c2,c3,a1,a2,z1,z2,z3 are relatively prime to n <p>
	AND c1^e*a1 = (1+n)^z1*z2^N mod N'<p>
	AND (c2^z1)/(a2*c3^e) = z3^N mod N'".
	* @param z second message from prover
	* @return true if the proof has been verified; false, otherwise.
	* @throws IllegalArgumentException if the first prover message is not an instance of SigmaDJProductFirstMsg
	* @throws IllegalArgumentException if the second prover message is not an instance of SigmaDJProductSecondMsg
	*/
	bool verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) override; 
};





