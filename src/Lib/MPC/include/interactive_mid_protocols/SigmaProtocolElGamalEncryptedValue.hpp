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
#include "../mid_layer/ElGamalEnc.hpp"
#include "SigmaProtocolDH.hpp"

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaElGamalEncryptedValue verifier and simulator.<p>
* There are two versions of SigmaElGamalEncryptedValue protocol, depending upon if the prover knows
* the secret key or it knows the randomness used to generate the ciphertext.<p>
* This common input contains an ElGamal public Key, the encrypted value x, the ciphertext and
* a boolean indicates is the prover knows the secret key or the random value.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalEncryptedValueCommonInput : public SigmaCommonInput {

private:
	bool isRandom;
	shared_ptr<GroupElement> x;
	ElGamalPublicKey publicKey;
	ElGamalOnGroupElementCiphertext cipher;

public:
	/**
	* Sets the given ciphertext, public key and encrypted value.<p>
	* There is also an argument represents if the encryption was done by private key knowledge or by a randomness knowledge.
	* @param isRandomness represents if the encryption was done by private key knowledge or by a randomness knowledge.
	* @param cipher ciphertext outputed by the encryption scheme on the given x
	* @param publicKey used to encrypt.
	* @param x encrypted value
	*/
	SigmaElGamalEncryptedValueCommonInput(bool isRandomness, ElGamalOnGroupElementCiphertext cipher, ElGamalPublicKey publicKey, const shared_ptr<GroupElement> & x);

	/**
	* Returns a boolean represents if the encryption was done by private key knowledge or by a randomness knowledge.
	*/
	bool isRandomness() { return isRandom; }

	/**
	* Returns the encrypted value.
	*/
	shared_ptr<GroupElement> getX() { return x;	}

	/**
	* Returns the publicKey used to encrypt.
	*/
	ElGamalPublicKey getPublicKey() { return publicKey;	}

	/**
	* Returns the ciphertext.
	*/
	ElGamalOnGroupElementCiphertext getCipher() { return cipher; }

	string toString() override;
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaElGamalEncryptedValueProver.<p>
*
* There are two versions of SigmaElGamalEncryptedValue protocol, depending upon if the prover knows
* the secret key or it knows the randomness used to generate the ciphertext.<p>
* This input represent the case that the prover knows the private key. <p>
* Thus, the prover gets a GroupElement x, an ElGamal public and private keys, and
* the ciphertext of x using the ElGamal encryption scheme.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalEncryptedValuePrivKeyProverInput : public SigmaProverInput {

private:
	shared_ptr<SigmaElGamalEncryptedValueCommonInput> input;
	ElGamalPrivateKey privateKey;

public:
	/**
	* Sets the given ciphertext, public key, encrypted value and private key.
	* @param isRandomness represents if the encryption was done by private key knowledge or by a randomness knowledge.
	* @param cipher ciphertext outputed by the encryption scheme on the given x
	* @param publicKey used to encrypt.
	* @param x encrypted value
	* @param privateKey used to decrypt.
	*/
	SigmaElGamalEncryptedValuePrivKeyProverInput(ElGamalOnGroupElementCiphertext cipher, ElGamalPublicKey pubKey, const shared_ptr<GroupElement> & x, ElGamalPrivateKey privateKey);

	/**
	* Returns the private key used in order to decrypt the ciphertext.
	*/
	ElGamalPrivateKey getPrivateKey() { return privateKey; }

	shared_ptr<SigmaCommonInput> getCommonInput() override { return input; }
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaElGamalEncryptedValueProver.<p>
*
* There are two versions of SigmaElGamalEncryptedValue protocol, depending upon if the prover knows
* the secret key or it knows the randomness used to generate the ciphertext.<p>
* This input represent the case that the prover knows the randomness. <p>
* Thus, the prover gets a GroupElement x, an ElGamal public key,
* the ciphertext of x using the ElGamal encryption scheme and the randomness used to encrypt.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalEncryptedValueRandomnessProverInput : public SigmaProverInput {

private:
	shared_ptr<SigmaElGamalEncryptedValueCommonInput> input;
	biginteger r;

public:
	/**
	* Sets the given ciphertext, public key, encrypted value and random value used to encrypt.<p>
	* @param isRandomness represents if the encryption was done by private key knowledge or by a randomness knowledge.
	* @param cipher ciphertext outputed by the encryption scheme on the given x
	* @param publicKey used to encrypt.
	* @param x encrypted value
	* @param r random value used to encrypt.
	*/
	SigmaElGamalEncryptedValueRandomnessProverInput(ElGamalOnGroupElementCiphertext cipher, ElGamalPublicKey pubKey, const shared_ptr<GroupElement> & x, const biginteger & r);

	/**
	* Returns the random value used to encrypt.
	*/
	biginteger getR() {	return r; }

	shared_ptr<SigmaCommonInput> getCommonInput() override { return input; }
};

/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that the value encrypted under ElGamal in the
* ciphertext (c1, c2) with public-key h is x.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.9 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalEncryptedValueSimulator : public SigmaSimulator {

	/*
	There are two versions of SigmaElGamalEncryptedValue protocol, depending upon if the prover knows
	the secret key or it knows the randomness used to generate the ciphertext.

	This class uses an instance of SigmaDHSimulator with:
	Common DlogGroup
	In case we use knowledge of the private key:
	Common input: (g,h,u,v) = (g,c1,h,c2/x) and
	In case we use knowledge of the randomness used to encrypt:
	Common input: (g,h,u,v) = (g,h,c1,c2/x)
	*/

private:
	SigmaDHSimulator dhSim; //underlying SigmaDHSimulator to use.
	shared_ptr<DlogGroup> dlog;			//We save the dlog because we need it to calculate the input for the underlying Sigma verifier.

	/**
	* Checks the given input and creates the input for the underlying DH simulator according to it.
	* @param in MUST be an instance of SigmaElGamalEncryptedValueCommonInput.
	* @return SigmaDHInput the input for the underlying simulator.
	* @throws IllegalArgumentException if input is not the expected.
	*/
	shared_ptr<SigmaDHCommonInput> checkAndCreateUnderlyingInput(SigmaCommonInput* in);

public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaElGamalEncryptedValueSimulator(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	*/
	int getSoundnessParam() override { return dhSim.getSoundnessParam(); }

	/**
	* Computes the simulator computation with the given challenge.
	* @param input MUST be an instance of SigmaElGamalEncryptedValueCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	* @throws IllegalArgumentException if input is not the expected.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input, const vector<byte> & challenge)  override;

	/**
	* Computes the simulator computation with a randomly chosen challenge.
	* @param input MUST be an instance of SigmaElGamalEncryptedValueInput.
	* @return the output of the computation - (a, e, z).
	* @throws IllegalArgumentException if input is not the expected.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input) override;

};

/**
* Concrete implementation of Sigma Protocol prover computation. <p>
*
* This protocol is used to prove that the value encrypted under ElGamal in the ciphertext (c1, c2) with public-key h is x.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.9 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalEncryptedValueProverComputation : public SigmaProverComputation, DlogBasedSigma {

	/*
	There are two versions of SigmaElGamalEncryptedValue protocol, depending upon if the prover knows
	the secret key or it knows the randomness used to generate the ciphertext.

	This class uses an instance of SigmaDHProver with:

	Common DlogGroup
	In case we use knowledge of the private key:
	Common input: (g,h,u,v) = (g,c1,h,c2/x) and
	P's private input: a value w <- Zq such that h=g^w and c2/x =c1^w
	In case we use knowledge of the randomness used to encrypt:
	Common input: (g,h,u,v) = (g,h,c1,c2/x)
	P's private input: a value r <- Zq such that c1=g^r and c2/x =h^r.
	*/

private:
	SigmaDHProverComputation sigmaDH;	//underlying SigmaDHProver to use.
	shared_ptr<DlogGroup> dlog;			//We save the dlog because we need it to calculate the input for the underlying Sigma prover.
	shared_ptr<PrgFromOpenSSLAES> prg;
	int t;
										
	/**
	* Converts the input for the underlying Sigma protocol.
	* There are two versions of this protocol, depending upon if the prover knows the secret key or it knows the randomness used to generate the ciphertext.
	* The only separation in these two version is the type of input.
	* In case we use knowledge of private key, the input should be an instance of SigmaElGamalEncryptedValuePrivKeyProverInput.
	* In case we use knowledge of randomness, the input should be an instance of SigmaElGamalEncryptedValueRandomnessProverInput.
	* @param input MUST be an instance of SigmaElGamalEncryptedValuePrivKeyProverInput OR SigmaElGamalEncryptedValueRandomnessProverInput.
	* @throws IllegalArgumentException if input is not the expected.
	*/
	shared_ptr<SigmaDHProverInput> convertInput(SigmaProverInput* in);

public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaElGamalEncryptedValueProverComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return sigmaDH.getSoundnessParam(); }

	/**
	* Computes the first message of the protocol.
	* @return the computed message
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
	* @return SigmaDlogSimulator
	*/
	shared_ptr<SigmaSimulator> getSimulator() override {
		return make_shared<SigmaElGamalEncryptedValueSimulator>(dlog, t, prg);
	}

};

/**
* Concrete implementation of Sigma Protocol verifier computation. <p>
*
* This protocol is used to prove that the value encrypted under ElGamal in the ciphertext (c1, c2) with public-key h is x.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.9 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalEncryptedValueVerifierComputation : public SigmaVerifierComputation, DlogBasedSigma {

	/*
	There are two versions of SigmaElGamalEncryptedValue protocol, depending upon if the prover knows
	the secret key or it knows the randomness used to generate the ciphertext.

	This class uses an instance of SigmaDHProver with:

	Common DlogGroup
	In case we use knowledge of the private key:
	Common input: (g,h,u,v) = (g,c1,h,c2/x) and
	P's private input: a value w <- Zq such that h=g^w and c2/x =c1^w
	In case we use knowledge of the randomness used to encrypt:
	Common input: (g,h,u,v) = (g,h,c1,c2/x)
	P's private input: a value r <- Zq such that c1=g^r and c2/x =h^r.
	*/

private:
	SigmaDHVerifierComputation sigmaDH;		//underlying SigmaDHVerifier to use.
	shared_ptr<DlogGroup> dlog;				//We save the dlog because we need it to calculate the input for the underlying Sigma verifier.
		
											/**
											* Sets the input for this Sigma protocol.
											* @param input MUST be an instance of SigmaElGamalEncryptedValueCommonInput.
											* @throws IllegalArgumentException if input is not the expected.
											*/
	shared_ptr<SigmaDHCommonInput> convertInput(SigmaCommonInput* in);

public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	*/
	SigmaElGamalEncryptedValueVerifierComputation(const shared_ptr<DlogGroup> & dlog, int t);

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
	*/
	vector<byte> getChallenge() override { return sigmaDH.getChallenge(); }

	/**
	* Verifies the proof.
	* @param z second message from prover
	* @return true if the proof has been verified; false, otherwise.
	* @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaDHMsg
	* @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
	*/
	bool verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) override;
};

