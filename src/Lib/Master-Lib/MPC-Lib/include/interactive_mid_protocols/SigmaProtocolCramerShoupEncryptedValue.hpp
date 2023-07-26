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
#include "../mid_layer/CramerShoupEnc.hpp"
#include "SigmaProtocolDHExtended.hpp"


/**
* Concrete implementation of SigmaProtocol input, used by the SigmaCramerShoupEncryptedValue verifier and simulator.<p>
*
* In SigmaCramerShoupEncryptedValue protocol, the common input contains a GroupElement x, a CramerShoup public key
* and the ciphertext of x using the CramerShoup encryption scheme.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaCramerShoupEncryptedValueCommonInput : public SigmaCommonInput {

private:
	shared_ptr<GroupElement> x;
	CramerShoupPublicKey publicKey;
	CramerShoupOnGroupElementCiphertext cipher;

public:
	/**
	* Sets the ciphertext, public key and the encrypted element.
	* @param cipher ciphertext the output of the encryption scheme on the encrypted element.
	* @param publicKey used to encrypt.
	* @param x encrypted element.
	*/
	SigmaCramerShoupEncryptedValueCommonInput(CramerShoupOnGroupElementCiphertext cipher, CramerShoupPublicKey publicKey, const shared_ptr<GroupElement> & x);

	/**
	* Returns the encrypted element.
	*/
	shared_ptr<GroupElement> getX() { return x;	}

	/**
	* Returns the public key used to encrypt.
	*/
	CramerShoupPublicKey getPublicKey() { return publicKey;	}

	/**
	* Returns the ciphertext.
	*/
	CramerShoupOnGroupElementCiphertext getCipher() { return cipher; }

	string toString() override;
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaCramerShoupEncryptedValueProver.<p>
*
* In SigmaCramerShoupEncryptedValue protocol, the prover gets a GroupElement x, a CramerShoup public key,
* the ciphertext of x using the CramerShoup encryption scheme and the random value used to encrypt x.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaCramerShoupEncryptedValueProverInput : public SigmaProverInput {

private:
	shared_ptr<SigmaCramerShoupEncryptedValueCommonInput> input;
	biginteger r;

public:
	/**
	* Sets the ciphertext, public key, the encrypted element and the random value used to encrypt x.
	* @param cipher ciphertext the output of the encryption scheme on the encrypted element.
	* @param publicKey used to encrypt.
	* @param x encrypted element.
	* @param r random value used to encrypt x.
	*/
	SigmaCramerShoupEncryptedValueProverInput(CramerShoupOnGroupElementCiphertext cipher, CramerShoupPublicKey pubKey, const shared_ptr<GroupElement> & x, const biginteger & r);

	/**
	* Returns the random value used to encrypt x.
	*/
	biginteger getR() {	return r; }

	shared_ptr<SigmaCommonInput> getCommonInput() override { return input; }
};

/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that the value encrypted under Cramer-Shoup in the
* ciphertext (u1,u2,e,v) with public-key g1,g2,c,d,h is x. <p>
* The protocol is for the case that the prover knows the randomness used to encrypt.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.10 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaCramerShoupEncryptedValueSimulator : public SigmaSimulator {

	/*
	This class uses an instance of SigmaDHExtendedSimulator with:
	Common DlogGroup
	Common input: (g1,g2,g3,g4,h1,h2,h3,h4) = (g1,g2,h,cd^w,u1,u2,e/x,v)
	*/

private:
	SigmaDHExtendedSimulator dhSim; 	//underlying SigmaDHExtendedSimulator to use.
	shared_ptr<DlogGroup> dlog;						//We save the dlog because we need it to calculate the input for the underlying Sigma verifier.
	shared_ptr<CryptographicHash> hash;					//Underlying hash function that used in the CramerShoup cryptosystem.

														/**
														* Checks the given input and creates the input for the underlying DH simulator according to it.
														* @param in MUST be an instance of SigmaCramerShoupEncryptedValueCommonInput.
														* @return SigmaDHExtendedInput the input for the underlying simulator.
														* @throws IllegalArgumentException if input is not the expected.
														*/
	shared_ptr<SigmaDHExtendedCommonInput> checkAndCreateUnderlyingInput(SigmaCommonInput* in);

	/**
	* Receives three byte arrays and calculates the hash function on their concatenation.
	* @param u1ToByteArray
	* @param u2ToByteArray
	* @param eToByteArray
	* @return the result of hash(u1ToByteArray+u2ToByteArray+eToByteArray) as BigInteger.
	*/
	biginteger calcW(const shared_ptr<GroupElement> & u1, const shared_ptr<GroupElement> & u2, const shared_ptr<GroupElement> & e);

public:
	/**
	* Constructor that gets the underlying DlogGroup, CryptographicHash, soundness parameter and SecureRandom.
	* @param dlog DlogGroup used in CramerShoup encryption scheme.
	* @param hash CryptographicHash used in CramerShoup encryption scheme.
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaCramerShoupEncryptedValueSimulator(const shared_ptr<DlogGroup> & dlog, const shared_ptr<CryptographicHash> & hash, int t, const shared_ptr<PrgFromOpenSSLAES> & prg);

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return dhSim.getSoundnessParam(); }

	/**
	* Computes the simulator computation with the given challenge.
	* @param input MUST be an instance of SigmaCramerShoupEncryptedValueInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	* @throws IllegalArgumentException if input is not the expected.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input, const vector<byte> & challenge)  override;

	/**
	* Computes the simulator computation with a randomly chosen challenge.
	* @param input MUST be an instance of SigmaCramerShoupEncryptedValueInput.
	* @return the output of the computation - (a, e, z).
	* @throws IllegalArgumentException if input is not the expected.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input) override; 
};

/**
* Concrete implementation of Sigma Protocol prover computation. <p>
*
* This protocol is used to prove that the value encrypted under Cramer-Shoup in the ciphertext (u1,u2,e,v)
* with public-key g1,g2,c,d,h is x. <p>
* The protocol is for the case that the prover knows the randomness used to encrypt.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.10 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaCramerShoupEncryptedValueProverComputation : public SigmaProverComputation, DlogBasedSigma {

	/*
	This class uses an instance of SigmaDHExtendedProver with:

	Common DlogGroup
	Common input: (g1,g2,g3,g4,h1,h2,h3,h4) = (g1,g2,h,cd^w,u1,u2,e/x,v)
	P-s private input: r

	*/

private:
	SigmaDHExtendedProverComputation sigmaDH;	//underlying SigmaDHExtendedProver to use.
	shared_ptr<DlogGroup> dlog;					//We save the dlog because we need it to calculate the input for the underlying Sigma prover.
	int t; 
	shared_ptr<CryptographicHash> hash;			//Underlying hash function that used in the CramerShoup cryptosystem.
	shared_ptr<PrgFromOpenSSLAES> prg;

												/**
												* Receives three byte arrays and calculates the hash function on their concatenation.
												* @param u1ToByteArray
												* @param u2ToByteArray
												* @param eToByteArray
												* @return the result of hash(u1ToByteArray+u2ToByteArray+eToByteArray) as BigInteger.
												*/
	biginteger calcW(const shared_ptr<GroupElement> & u1, const shared_ptr<GroupElement> & u2, const shared_ptr<GroupElement> & e);

public:
	/**
	* Constructor that gets the underlying DlogGroup, CryptographicHash, soundness parameter and SecureRandom.
	* @param dlog DlogGroup used in CramerShoup encryption scheme.
	* @param hash CryptographicHash used in CramerShoup encryption scheme.
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaCramerShoupEncryptedValueProverComputation(const shared_ptr<DlogGroup> & dlog, const shared_ptr<CryptographicHash> & hash, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return sigmaDH.getSoundnessParam(); }


	/**
	* Computes the first message of the protocol.
	* @param input MUST be an instance of SigmaCramerShoupEncryptedValueProverInput.
	* @return the computed message
	* @throws IllegalArgumentException if input is not the expected.
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
	* @return SigmaCramerShoupEncryptedValueSimulator.
	*/
	shared_ptr<SigmaSimulator> getSimulator() override {
		return make_shared<SigmaCramerShoupEncryptedValueSimulator>(dlog, hash, t, prg);
	}
};

/**
* Concrete implementation of Sigma Protocol verifier computation. <p>
*
* This protocol is used to prove that the value encrypted under Cramer-Shoup in the ciphertext (u1,u2,e,v)
* with public-key g1,g2,c,d,h is x. <p>
* The protocol is for the case that the prover knows the randomness used to encrypt.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.10 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaCramerShoupEncryptedValueVerifierComputation : public SigmaVerifierComputation, DlogBasedSigma {

	/*
	This class uses an instance of SigmaDHExtendedVerifier with:

	Common DlogGroup
	Common input: (g1,g2,g3,g4,h1,h2,h3,h4) = (g1,g2,h,cd^w,u1,u2,e/x,v)
	*/

private:
	SigmaDHExtendedVerifierComputation sigmaDH;		//underlying SigmaDHExtendedVerifier to use.
	shared_ptr<DlogGroup> dlog;						//We save the dlog because we need it to calculate the input for the underlying Sigma verifier.
	shared_ptr<CryptographicHash> hash;				//Underlying hash function that used in the CramerShoup cryptosystem.

													/**
													* Receives three byte arrays and calculates the hash function on their concatenation.
													* @param u1ToByteArray
													* @param u2ToByteArray
													* @param eToByteArray
													* @return the result of hash(u1ToByteArray+u2ToByteArray+eToByteArray) as BigInteger.
													*/
	biginteger calcW(const shared_ptr<GroupElement> & u1, const shared_ptr<GroupElement> & u2, const shared_ptr<GroupElement> & e);

public:
	/**
	* Constructor that gets the underlying DlogGroup, CryptographicHash, soundness parameter and SecureRandom.
	* @param dlog DlogGroup used in CramerShoup encryption scheme.
	* @param hash CryptographicHash used in CramerShoup encryption scheme.
	* @param t Soundness parameter in BITS.
	* @param random
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	*/
	SigmaCramerShoupEncryptedValueVerifierComputation(const shared_ptr<DlogGroup> & dlog, const shared_ptr<CryptographicHash> & hash, int t);

	/**
	* Returns the soundness parameter for this Sigma protocol.
	*/
	int getSoundnessParam() override { return sigmaDH.getSoundnessParam(); }

	/**
	* Samples the challenge e <- {0,1}^t.
	*/
	void sampleChallenge() override { sigmaDH.sampleChallenge(); }

	/**
	* Sets the given challenge.
	* @param challenge
	*/
	void setChallenge(const vector<byte> & challenge) override { sigmaDH.setChallenge(challenge); }

	/**
	* Returns the sampled challenge.
	* @return the challenge.
	*/
	vector<byte> getChallenge() override { return sigmaDH.getChallenge(); }

	/**
	* Verifies the proof.
	* @param input MUST be an instance of SigmaCramerShoupEncryptedValueCommonInput.
	* @param z second message from prover
	* @return true if the proof has been verified; false, otherwise.
	* @throws IllegalArgumentException if input is not the expected.
	* @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaDHExtendedMsg
	* @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
	*/
	bool verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z);
};






