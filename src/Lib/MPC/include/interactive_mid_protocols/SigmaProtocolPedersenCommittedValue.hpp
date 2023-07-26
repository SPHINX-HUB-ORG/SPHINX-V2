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
#include "SigmaProtocolDlog.hpp"

/******************************************************************/
/**************** Inputs for the protocol *************************/
/******************************************************************/

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaPedersenCommittedValue verifier and simulator.<p>
* In SigmaPedersenCommittedValue protocol, the common input contains a GroupElement h, a commitment message and the committed value x.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaPedersenCommittedValueCommonInput : public SigmaCommonInput {

private:
	biginteger x;
	shared_ptr<GroupElement> h;
	shared_ptr<GroupElement> commitment;

public:
	/**
	* Sets the given h (public key), commitment value and the committed value.
	* @param h public key used to commit.
	* @param commitment the actual commitment value.
	* @param x the committed value.
	*/
	SigmaPedersenCommittedValueCommonInput(const shared_ptr<GroupElement> & h, const shared_ptr<GroupElement> & commitment, const biginteger & x) {
		this->h = h;
		this->commitment = commitment;
		this->x = x;
	}

	/**
	* Returns the committed value.
	*/
	biginteger getX() {
		return x;
	}

	/**
	* Returns the public key used to commit.
	*/
	shared_ptr<GroupElement> getH() { return h;	}

	/**
	* Returns the actual commitment value.
	*/
	shared_ptr<GroupElement> getCommitment() { return commitment; }

	string toString() override;
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaPedersenCommittedValueProver.<p>
* In SigmaPedersenCommittedValue protocol, the prover gets a GroupElement h, a commitment message,the committed value x
* and the value r in Zq such that c = g^r * h^x.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaPedersenCommittedValueProverInput : public SigmaProverInput {

private:
	shared_ptr<SigmaPedersenCommittedValueCommonInput> input;
	biginteger r;

public:
	/**
	* Sets the given h (public key), commitment value, committed value and the random value used to commit.
	* @param h public key used to commit.
	* @param commitment the actual commitment value.
	* @param x committed value
	* @param r random value used to commit
	*/
	SigmaPedersenCommittedValueProverInput(const shared_ptr<GroupElement> & h, const shared_ptr<GroupElement> & commitment, const biginteger & x, const biginteger & r) {
		input = make_shared<SigmaPedersenCommittedValueCommonInput>(h, commitment, x);
		this->r = r;
	}

	/**
	* Returns the random value used to commit.
	*/
	biginteger getR() {	return r; }

	shared_ptr<SigmaCommonInput> getCommonInput() override { return input; };
};


/**********************************************************/
/******* Sigma Pederesen committed value simulator ********/
/**********************************************************/

/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that the value committed to in the commitment (h, c) is x.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.5 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaPedersenCommittedValueSimulator : public SigmaSimulator {

	/*
	Since c = g^r*h^x, it suffices to prove knowledge of r s.t. g^r = c*h^(-x). This is just a DLOG Sigma protocol.

	This class uses an instance of SigmaDlogSimulator with:
	Common parameters (G,q,g) and t
	Common input: h' = c*h^(-x)
	*/

private:
	SigmaDlogSimulator dlogSim; 	//underlying SigmaDlogSimulator to use.
	DlogGroup* dlog;						//We need the DlogGroup instance in order to calculate the input for the underlying SigmaDlogVerifier.

	/**
	* Converts the given input to the underlying Dlog simulator input.
	* @param in input to convert MUST be an instance of SigmaPedersenCommittedValueCommonInput
	* @return the converted input
	* @throws IllegalArgumentException if the given input is not an instance of SigmaPedersenCommittedValueCommonInput.
	*/
	shared_ptr<SigmaDlogCommonInput> convertInput(SigmaCommonInput* in);

public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaPedersenCommittedValueSimulator(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return dlogSim.getSoundnessParam();}

	/**
	* Computes the simulator computation with the given challenge.
	* @param input MUST be an instance of SigmaPedersenCommittedValueCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	* @throws IllegalArgumentException if the given input is not an instance of SigmaPedersenCommittedValueCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input, const vector<byte> & challenge)  override;
	

	/**
	* Computes the simulator computation with a randomly chosen challenge.
	* @param input MUST be an instance of SigmaPedersenCommittedValueCommonInput.
	* @return the output of the computation - (a, e, z).
	* @throws IllegalArgumentException if the given input is not an instance of SigmaPedersenCommittedValueCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input) override;

};

/**
* Concrete implementation of Sigma Protocol prover computation. <p>
*
* This protocol is used for a committer to prove that the value committed to in the commitment (h, c) is x.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.5 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaPedersenCommittedValueProverComputation : public SigmaProverComputation, DlogBasedSigma {

	/*
	Since c = g^r*h^x, it suffices to prove knowledge of r s.t. g^r = c*h^(-x). This is just a DLOG Sigma protocol.

	This class uses an instance of SigmaDlogProver with:
	Common parameters (G,q,g) and t
	Common input: h' = c*h^(-x)
	P's private input: a value r in Zq such that h' = g^r
	*/

private:
	SigmaDlogProverComputation sigmaDlog;	//underlying SigmaDlogProver to use.
	shared_ptr<PrgFromOpenSSLAES> prg;
	shared_ptr<DlogGroup> dlog;				//We need the DlogGroup instance in order to calculate the input for the underlying SigmaDlogProver
	int t;

	/**
	* Converts the input for the underlying prover computation.
	* @param input MUST be an instance of SigmaPedersenCommittedValueProverInput.
	* @throws IllegalArgumentException if input is not an instance of SigmaPedersenCommittedValueProverInput.
	*/
	shared_ptr<SigmaDlogProverInput> convertInput(SigmaProverInput* in);
										
public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaPedersenCommittedValueProverComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override;

	/**
	* Computes the first message of the protocol.
	* @param input MUST be an instance of SigmaPedersenCommittedValueProverInput.
	* @return the computed message
	* @throws IllegalArgumentException if input is not an instance of SigmaPedersenCommittedValueProverInput.
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
		return make_shared<SigmaPedersenCommittedValueSimulator>(dlog, t, prg);
	}
};

/**
* Concrete implementation of Sigma Protocol verifier computation. <p>
*
* This protocol is used for a committer to prove that the value committed to in the commitment (h, c) is x.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.5 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaPedersenCommittedValueVerifierComputation : public SigmaVerifierComputation, DlogBasedSigma {
	/*
	Since c = g^r*h^x, it suffices to prove knowledge of r s.t. g^r = c*h^(-x). This is just a DLOG Sigma protocol.

	This class uses an instance of SigmaDlogProver with:
	Common parameters (G,q,g) and t
	Common input: h' = c*h^(-x)
	*/

private:
	SigmaDlogVerifierComputation sigmaDlog;	//underlying SigmaDlogVerifier to use.
	shared_ptr<DlogGroup> dlog;					//We need the DlogGroup instance in order to calculate the input for the underlying SigmaDlogVerifier.

	/**
	* Sets the input for this Sigma protocol.
	* @param input MUST be an instance of SigmaPedersenCommittedValueCommonInput.
	* @throws IllegalArgumentException if input is not an instance of SigmaPedersenCommittedValueCommonInput.
	*/
	shared_ptr<SigmaDlogCommonInput> convertInput(SigmaCommonInput* in);

public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	*/
	SigmaPedersenCommittedValueVerifierComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg()) : sigmaDlog(dlog, t, prg) {
		this->dlog = dlog;
	}

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return sigmaDlog.getSoundnessParam();	}

	/**
	* Samples the challenge e <- {0,1}^t.
	*/
	void sampleChallenge() override { sigmaDlog.sampleChallenge(); }

	/**
	* Sets the given challenge.
	* @param challenge
	*/
	void setChallenge(const vector<byte> & challenge) override { sigmaDlog.setChallenge(challenge); }

	/**
	* Returns the sampled challenge.
	* @return the challenge.
	*/
	vector<byte> getChallenge() override {	return sigmaDlog.getChallenge(); }

	/**
	* Verifies the proof.
	* @param z second message from prover
	* @return true if the proof has been verified; false, otherwise.
	* @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaGroupElementMsg
	* @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
	*/
	bool verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) override {
		return sigmaDlog.verify(convertInput(input).get(), a, z);
	}

};