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
* Concrete implementation of SigmaProtocol input, used by the SigmaElGamalCommittedValue verifier and simulator.<p>
* In SigmaElGamalCommittedValue protocol, the common input contains an ElGamal commitment message
* and the value committed x.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalCommittedValueCommonInput : public SigmaCommonInput {

private: 
	shared_ptr<ElGamalPublicKey> publicKey;
	shared_ptr<ElGamalOnGrElSendableData> commitment;
	shared_ptr<GroupElement> x;

public:
	/**
	* Sets the public key, the commitment value and the committed value.
	* @param publicKey used to commit the committed value.
	* @param commitment the actual commitment value.
	* @param x committed value.
	*/
	SigmaElGamalCommittedValueCommonInput(const shared_ptr<ElGamalPublicKey> & publicKey, const shared_ptr<ElGamalOnGrElSendableData> & commitment, const shared_ptr<GroupElement> & x)  {
		this->publicKey = publicKey;
		this->commitment = commitment;
		this->x = x;
	}

	/**
	* Returns the actual commitment value.
	*/
	shared_ptr<ElGamalOnGrElSendableData> getCommitment() {	return commitment; }

	/**
	* Returns the committed value.
	*/
	shared_ptr<GroupElement> getX() { return x; }

	/**
	* Returns the public key used to commit.
	*/
	shared_ptr<ElGamalPublicKey> getPublicKey() { return publicKey;	}

	string toString() override;
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaElGamalCommittedValueProver.<p>
* In SigmaElGamalCommittedValue protocol, the prover gets an ElGamal commitment message,
* the value committed x and the value r in Zq such that c1=g^r and c2 =h^r*x.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalCommittedValueProverInput : public SigmaProverInput {

private:
	shared_ptr<SigmaElGamalCommittedValueCommonInput> input;
	biginteger r;

public:
	/**
	* Sets the given public key, commitment, committed value and random value used to commit.
	* @param publicKey used to commit
	* @param commitment actual commitment value outputed from the commitment scheme on the given committed value.
	* @param x committed value
	* @param r random value used to commit.
	*/
	SigmaElGamalCommittedValueProverInput(const shared_ptr<ElGamalPublicKey> & publicKey,
		const shared_ptr<ElGamalOnGrElSendableData> & commitment, const shared_ptr<GroupElement> & x, const biginteger & r) {

		input = make_shared<SigmaElGamalCommittedValueCommonInput>(publicKey, commitment, x);
		this->r = r;
	}

	/**
	* Returns the random value used to commit.
	* @return random value used to commit.
	*/
	biginteger getR() { return r; }

	shared_ptr<SigmaCommonInput> getCommonInput() override { return input; }

};

/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that the value committed to in the commitment (h,c1, c2) is x.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.7 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalCommittedValueSimulator : public SigmaSimulator {

	/*
	This class uses an instance of SigmaDHSimulator with:
	Common parameters (G,q,g) and t
	Common input: (g,h,u,v) = (g,h,c1,c2/x)
	*/

private:
	SigmaDHSimulator dhSim; 		//underlying SigmaDHSimulator to use.
	shared_ptr<DlogGroup> dlog;		//We need the DlogGroup instance in order to calculate the input for the underlying SigmaDlogProver
	shared_ptr<PrgFromOpenSSLAES> prg;

	/**
	* Converts the input to an input object for the underlying simulator.
	* @param in
	* @return
	*/
	shared_ptr<SigmaDHCommonInput> convertInput(SigmaCommonInput* in);

public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaElGamalCommittedValueSimulator(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg()) : dhSim(dlog, t, prg) {
		this->dlog = dlog;
		this->prg = prg;
	}

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return dhSim.getSoundnessParam(); }

	/**
	* Computes the simulator computation with the given challenge.
	* @param input MUST be an instance of SigmaElGamalCommittedValueCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCommittedValueCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input, const vector<byte> & challenge)  override;

	/**
	* Computes the simulator computation with a randomly chosen challenge.
	* @param in MUST be an instance of SigmaElGamalCommittedValueCommonInput.
	* @return the output of the computation - (a, e, z).
	* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCommittedValueCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input) override; 
};

/**
* Concrete implementation of Sigma Protocol prover computation.<p>
*
* This protocol is used for a committer to prove that the value committed to in the commitment (h,c1, c2) is x.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.7 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalCommittedValueProverComputation : public SigmaProverComputation, DlogBasedSigma {

	/*
	This class uses an instance of SigmaDHProver with:
	Common parameters (G,q,g) and t
	Common input: (g,h,u,v) = (g,h,c1,c2/x)
	P's private input: a value r in Zq such that c1=g^r and c2/x =h^r

	*/

private:
	SigmaDHProverComputation sigmaDH;	//underlying SigmaDHProver to use.
	shared_ptr<DlogGroup> dlog;			//We need the DlogGroup instance in order to calculate the input for the underlying SigmaDlogProver
	shared_ptr<PrgFromOpenSSLAES> prg;
	int t;

	/**
	* Converts the input for this Sigma protocol to the underlying protocol.
	* @param input MUST be an instance of SigmaElGamalCommittedValueProverInput.
	* @throws IllegalArgumentException if input is not an instance of SigmaElGamalCommittedValueProverInput.
	*/
	shared_ptr<SigmaDHProverInput> convertInput(SigmaProverInput* in);

public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaElGamalCommittedValueProverComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg()) : sigmaDH(dlog, t, prg){
		this->prg = prg;
		this->dlog = dlog;
		this->t = t;
	}

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override {	return sigmaDH.getSoundnessParam();	}

	/**
	* Computes the first message of the protocol.
	* @param input MUST be an instance of SigmaElGamalCommittedValueProverInput.
	* @return the computed message
	* @throws IllegalArgumentException if input is not an instance of SigmaElGamalCommittedValueProverInput.
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
	* @return SigmaElGamalCommittedValueSimulator
	*/
	shared_ptr<SigmaSimulator> getSimulator() override {
		return make_shared<SigmaElGamalCommittedValueSimulator>(dlog, t, prg);
	}

};

/**
* Concrete implementation of Sigma Protocol verifier computation. <p>
*
* This protocol is used for a committer to prove that the value committed to in the commitment (h,c1, c2) is x.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.7 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalCommittedValueVerifierComputation : public SigmaVerifierComputation, DlogBasedSigma {

	/*
	This class uses an instance of SigmaDHVerifier with:
	Common parameters (G,q,g) and t
	Common input: (g,h,u,v) = (g,h,c1,c2/x)
	*/

private:
	SigmaDHVerifierComputation sigmaDH;		//underlying SigmaDHVerifier to use.
	shared_ptr<DlogGroup> dlog;				//We need the DlogGroup instance in order to calculate the input for the underlying SigmaDlogProver

											/**
											* Converts the input for this Sigma protocol to the underlying protocol.
											* @param input MUST be an instance of SigmaElGamalCommittedValueCommonInput.
											* @throws IllegalArgumentException if input is not an instance of SigmaElGamalCommittedValueCommonInput.
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
	SigmaElGamalCommittedValueVerifierComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg())
		:sigmaDH(dlog, t, prg) {

		this->dlog = dlog;
	}

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
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
	vector<byte> getChallenge() { return sigmaDH.getChallenge(); }

	/**
	* Verifies the proof.
	* @param z second message from prover
	* @param input MUST be an instance of SigmaElGamalCommittedValueCommonInput.
	* @return true if the proof has been verified; false, otherwise.
	* @throws IllegalArgumentException if input is not an instance of SigmaElGamalCommittedValueCommonInput.
	* @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaDHMsg
	* @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
	*/
	bool verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) override {
		return sigmaDH.verify(convertInput(input).get(), a, z);
	}

};



