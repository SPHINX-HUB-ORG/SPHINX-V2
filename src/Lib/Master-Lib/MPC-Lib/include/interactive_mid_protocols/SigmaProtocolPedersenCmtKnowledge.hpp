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
#include "../primitives/Dlog.hpp"
#include "../primitives/Prg.hpp"

/******************************************************************/
/**************** Inputs for the protocol *************************/
/******************************************************************/

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaPedersenCTKnowledge verifier and simulator.<p>
*
* In SigmaPedersenCTKnowledge protocol, the common input contains a GroupElement h and a commitment message.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaPedersenCmtKnowledgeCommonInput : public SigmaCommonInput {

private:
	shared_ptr<GroupElement> h;
	shared_ptr<GroupElement> commitment;

public:
	/**
	* Sets the given h (public key) and commitment value.
	* @param h public key used to commit.
	* @param commitment the actual commitment value.
	*/
	 SigmaPedersenCmtKnowledgeCommonInput(const shared_ptr<GroupElement> & h, const shared_ptr<GroupElement> & commitment) {
		this->h = h;
		this->commitment = commitment;
	}

	/**
	* Returns the public key used to commit.
	* @return public key used to commit.
	*/
	 shared_ptr<GroupElement> getH() { return h; }

	/**
	* Returns the actual commitment value.
	* @return the actual commitment value.
	*/
	 shared_ptr<GroupElement> getCommitment() {	return commitment; }

	 string toString() override;
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaPedersenCTKnowledgeProver.<p>
*
* In SigmaPedersenCTKnowledge protocol, the prover gets a GroupElement h, commitment message and
* values x,r <- Zq such that c = g^r * h^x.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaPedersenCmtKnowledgeProverInput : public SigmaProverInput {

private:
	shared_ptr<SigmaPedersenCmtKnowledgeCommonInput> input;
	biginteger x;
	biginteger r;

public:
	/**
	* Sets the given h (public key), commitment value, committed value and the random value used to commit.
	* @param h public key used to commit.
	* @param commitment the actual commitment value.
	* @param x committed value
	* @param r random value used to commit
	*/
	SigmaPedersenCmtKnowledgeProverInput(const shared_ptr<GroupElement> & h, const shared_ptr<GroupElement> & commitment, const biginteger & x, const biginteger & r) {
		input = make_shared<SigmaPedersenCmtKnowledgeCommonInput>(h, commitment);
		this->x = x;
		this->r = r;
	}

	/**
	* Returns the committed value.
	*/
	biginteger getX() {	return x; }

	/**
	* Returns the random value used to commit.
	*/
	biginteger getR() { return r; }

	
	shared_ptr<SigmaCommonInput> getCommonInput() override { return input; }
};

/*******************************************************/
/*********************protocol message******************/
/*******************************************************/

/**
* Concrete implementation of SigmaProtocol message.
* This message contains two BigIntegers and used when the SigmaPedersenCTKnowledge prover send the first message to the verifier.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaPedersenCmtKnowledgeMsg : public SigmaProtocolMsg {

private:
	biginteger u;
	biginteger v;

public:
	SigmaPedersenCmtKnowledgeMsg(const biginteger & u, const biginteger & v) {
		this->u = u;
		this->v = v;
	}

	biginteger getU() {	return u; }

	biginteger getV() {	return v; }

	void initFromString(const string & s) override;
	string toString() override { return u.str() + ":" + v.str(); };
};

/**********************************************************/
/*************** Sigma Pederesen simulator ****************/
/**********************************************************/

/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that that the value committed to in the commitment (h, c) is x.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.4 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaPedersenCmtKnowledgeSimulator : public SigmaSimulator {
	/*
	This class computes the following calculations:
	SAMPLE random values u, v in Zq
	COMPUTE a = h^u*g^v*c^(-e) (where -e here means -e mod q)
	OUTPUT (a,e,(u,v))
	*/

private:
	shared_ptr<DlogGroup> dlog; 		//Underlying DlogGroup.
	int t;								//Soundness parameter.
	shared_ptr<PrgFromOpenSSLAES> random;

	/**
	* Checks the validity of the given soundness parameter.
	* @return true if the soundness parameter is valid; false, otherwise.
	*/
	bool checkSoundnessParam();

	bool checkChallengeLength(int size) {
		//If the challenge's length is equal to t, return true. else, return false.
		return (size == (t / 8) ? true : false);
	}

public:

	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	* @throws IllegalArgumentException if soundness parameter is invalid.
	*/
	SigmaPedersenCmtKnowledgeSimulator(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return t; }

	/**
	* Computes the simulator computation with the given challenge.
	* @param input MUST be an instance of SigmaPedersenCTKnowledgeCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	* @throws IllegalArgumentException if the given input is not an instance of SigmaPedersenCTKnowledgeCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input, const vector<byte> & challenge)  override;

	/**
	* Computes the simulator computation with randomly chosen challenge.
	* @param input MUST be an instance of SigmaPedersenCTKnowledgeInput.
	* @return the output of the computation - (a, e, z).
	* @throws IllegalArgumentException if the given input is not an instance of SigmaPedersenCTKnowledgeInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input) override;

};

/**
* Concrete implementation of Sigma Protocol prover computation.<p>
*
* This protocol is used for a committer to prove that the value committed to in the commitment (h, c) is x.<P>
*
* The pseudo code of this protocol can be found in Protocol 1.4 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaPedersenCmtKnowledgeProverComputation : public SigmaProverComputation, DlogBasedSigma {

	/*
	This class computes the following calculations:
	SAMPLE random values alpha, beta <- Zq
	COMPUTE a = (h^alpha)*(g^beta)
	COMPUTE u = alpha + ex mod q and v = beta + er mod q.
	*/

private:
	shared_ptr<DlogGroup> dlog;								// Underlying DlogGroup.
	int t; 													// soundness parameter in BITS.
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<SigmaPedersenCmtKnowledgeProverInput> input;	// Contains h, c, x, r.
	biginteger alpha, beta;									//random values used in the protocol.

	/**
	* Checks the validity of the given soundness parameter.
	* @return true if the soundness parameter is valid; false, otherwise.
	*/
	bool checkSoundnessParam(); 

	/**
	* Checks if the given challenge length is equal to the soundness parameter.
	* @return true if the challenge length is t; false, otherwise.
	*/
	bool checkChallengeLength(int size) {
		//If the challenge's length is equal to t, return true. else, return false.
		return (size == (t / 8) ? true : false);
	}

public:

	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	* @throws IllegalArgumentException if soundness parameter is invalid.
	*/
	SigmaPedersenCmtKnowledgeProverComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	*/
	int getSoundnessParam() override { return t; }

	/**
	* Computes the first message of the protocol.<p>
	* "SAMPLE random values alpha, beta <- Zq<p>
	*  COMPUTE a = (h^alpha)*(g^beta)".
	* @return the computed message
	*/
	shared_ptr<SigmaProtocolMsg> computeFirstMsg(const shared_ptr<SigmaProverInput> & input) override;

	/**
	* Computes the second message of the protocol.<p>
	* "COMPUTE u = alpha + ex mod q and v = beta + er mod q".
	* @param challenge
	* @return the computed message.
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	*/
	shared_ptr<SigmaProtocolMsg> computeSecondMsg(const vector<byte> & challenge) override;

	/**
	* Returns the simulator that matches this sigma protocol prover.
	* @return SigmaDlogSimulator
	*/
	shared_ptr<SigmaSimulator> getSimulator() override{
		return make_shared<SigmaPedersenCmtKnowledgeSimulator>(dlog, t, random);
	}
};

/**
* Concrete implementation of Sigma Protocol verifier computation. <p>
*
* This protocol is used for a committer to prove that the value committed to in the commitment (h, c) is x.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.4 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaPedersenCmtKnowledgeVerifierComputation : public SigmaVerifierComputation, DlogBasedSigma {

	/*
	This class computes the following calculations:
	SAMPLE a random challenge  e <- {0, 1}^t
	ACC IFF VALID_PARAMS(G,q,g)=TRUE AND h in G AND h^u*g^v=a*c^e.
	*/

private:
	shared_ptr<DlogGroup> dlog;			// Underlying DlogGroup.
	int t; 								//Soundness parameter in BITS.
	vector<byte> e;						//The challenge.
	shared_ptr<PrgFromOpenSSLAES> random;

	/**
	* Checks the validity of the given soundness parameter.
	* @return true if the soundness parameter is valid; false, otherwise.
	*/
	bool checkSoundnessParam();

public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	* @throws InvalidDlogGroupException if the given DlogGroup is not valid.
	* @throws IllegalArgumentException if soundness parameter is invalid.
	*/
	SigmaPedersenCmtKnowledgeVerifierComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return t; }

	/**
	* Samples the challenge for this protocol.<p>
	* 	"SAMPLE a random challenge e<-{0,1}^t".
	*/
	void sampleChallenge() override;

	/**
	* Sets the given challenge.
	* @param challenge
	*/
	void setChallenge(const vector<byte> & challenge) override { e = challenge; }

	/**
	* Returns the sampled challenge.
	* @return the challenge.
	*/
	vector<byte> getChallenge() override { return e; }

	/**
	* Computes the varification of the protocol.<p>
	* 	"ACC IFF VALID_PARAMS(G,q,g)=TRUE AND h in G AND h^u*g^v=a*c^e".
	* @param input MUST be an instance of SigmaPedersenCTKnowledgeCommonInput.
	* @param a first message from prover
	* @param z second message from prover
	* @return true if the proof has been verified; false, otherwise.
	* @throws IllegalArgumentException if input is not an instance of SigmaPedersenCTKnowledgeCommonInput.
	* @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaGroupElementMsg
	* @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaPedersenCTKnowledgeMsg
	*/
	bool verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) override;

};
