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
/**************** Inputs for DH extended protocol******************/
/******************************************************************/
/**
* Concrete implementation of SigmaProtocol input, used by the SigmaDHExtended verifier and simulator.<p>
* In SigmaProtocolDHExtended, the common input contains an extended DH tuple - (g1,...,gm,h1,...,hm).
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDHExtendedCommonInput : public SigmaCommonInput {

private:
	vector<shared_ptr<GroupElement>> gArray;
	vector<shared_ptr<GroupElement>> hArray;

public:
	/**
	* Sets the input arrays.
	* @param gArray
	* @param hArray
	*/
	SigmaDHExtendedCommonInput(const vector<shared_ptr<GroupElement>> & gArray, const vector<shared_ptr<GroupElement>> & hArray) {
		this->gArray = gArray;
		this->hArray = hArray;
	}

	vector<shared_ptr<GroupElement>> getGArray() {
		return gArray;
	}

	vector<shared_ptr<GroupElement>> getHArray() {
		return hArray;
	}

	string toString() override;
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaDHExtendedProver.<p>
* In SigmaProtocolDHExtended, the prover gets an extended DH tuple - (g1,...,gm,h1,...,hm) and a value w in Zq such that hi=gi^w for all i.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDHExtendedProverInput : public SigmaProverInput {

private:
	shared_ptr<SigmaDHExtendedCommonInput> params;
	biginteger w;

public:
	/**
	* Sets the input for the prover. <p>
	* The prover gets an extended DH tuple - (g1,...,gm,h1,...,hm) and a value w in Zq such that hi=gi^w for all i.
	* @param gArray
	* @param hArray
	* @param w
	*/
	SigmaDHExtendedProverInput(const vector<shared_ptr<GroupElement>> & gArray, const vector<shared_ptr<GroupElement>> & hArray, const biginteger & w) {
		params = make_shared<SigmaDHExtendedCommonInput>(gArray, hArray);
		this->w = w;
	}

	biginteger getW() {	return w; }

	shared_ptr<SigmaCommonInput> getCommonInput() override { return params; }
};

/**********************************************************/
/************* Messages ***********************************/
/**********************************************************/
class SigmaDHExtendedSimulator;
/**
* Concrete implementation of SigmaProtocol message.
* This message contains an array of GroupElementSendableData and used when the DHExtended prover sends the first message to the verifier.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDHExtendedMsg : public SigmaProtocolMsg {

private:
	vector<shared_ptr<GroupElementSendableData>> aArray;

public:
	SigmaDHExtendedMsg(const vector<shared_ptr<GroupElementSendableData>> & aArray) { this->aArray = aArray; }
	vector<shared_ptr<GroupElementSendableData>> getArray() { return aArray; }
	// SerializedNetwork implementation:
	void initFromString(const string & s) override;
	string toString() override;
};

/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that the input tuple (g1,...,gm,h1,...,hm) is an
* extended Diffie-Hellman tuple, meaning that there exists a single w in Zq such that hi=gi^w for all i.<P>
*
* The pseudo code of this protocol can be found in Protocol 1.3 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDHExtendedSimulator : public SigmaSimulator {
	/*
	This class computes the following calculations:
	SAMPLE a random z <- Zq
	For every i=1,...,m, COMPUTE ai = gi^z*hi^(-e) (where -e here means -e mod q)
	OUTPUT ((a1,...,am),e,z)
	*/
private:

	shared_ptr<DlogGroup> dlog; 		//Underlying DlogGroup.
	int t;								//Soundness parameter.
	shared_ptr<PrgFromOpenSSLAES> random;

	/**
	* Checks if the given challenge length is equal to the soundness parameter.
	* @return true if the challenge length is t; false, otherwise.
	*/
	bool checkChallengeLength(int size) { return size == (t / 8) ? true : false; }

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
	* @throws IllegalArgumentException if soundness parameter is invalid.
	*/
	SigmaDHExtendedSimulator(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	*/
	int getSoundnessParam() { return t; }

	/**
	* Computes the simulator computation with the given challenge.
	* @param input MUST be an instance of SigmaDHExtendedCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	* @throws IllegalArgumentException if the given input is not an instance of SigmaDHExtendedCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input, const vector<byte> & challenge)  override;

	/**
	* Computes the simulator computation with randomly chosen challenge.
	* @param input MUST be an instance of SigmaDHExtendedInput.
	* @return the output of the computation - (a, e, z).
	* @throws IllegalArgumentException if the given input is not an instance of SigmaDHExtendedInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input) override;
};

/**
* Concrete implementation of Sigma Protocol prover computation. <p>
*
* This protocol is used for a prover to convince a verifier that the input tuple (g1,...,gm,h1,...,hm) is an
* extended Diffie-Hellman tuple, meaning that there exists a single w in Zq such that hi=gi^w for all i.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.3 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDHExtendedProverComputation : public SigmaProverComputation, DlogBasedSigma {

	/*
	This class computes the following calculations:
	SAMPLE a random r <- Zq and COMPUTE ai = gi^r for all i
	SET a=(a1,...,am)
	COMPUTE z = r + ew mod q.
	*/

private:
	shared_ptr<DlogGroup> dlog;						// Underlying DlogGroup.
	int t; 											// Soundness parameter in BITS.
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<SigmaDHExtendedProverInput> input;	// Contains g and h arrays and w. 
	biginteger r;									// The value chosen in the protocol.

	/**
	* Checks if the given challenge length is equal to the soundness parameter.
	* @return true if the challenge length is t; false, otherwise.
	*/
	bool checkChallengeLength(int size) { return size == (t / 8) ? true : false; }

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
	* @throws IllegalArgumentException if soundness parameter is invalid.
	*/
	SigmaDHExtendedProverComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() { return t; }

	/**
	* Computes the first message of the protocol.<p>
	* "SAMPLE a random r in Zq<p>
	* COMPUTE ai = gi^r for all i". <p>
	* @param input MUST be an instance of SigmaDHExtendedProverInput.
	* @return the computed message
	* @throws IllegalArgumentException if input is not an instance of SigmaDHExtendedProverInput.
	*/
	shared_ptr<SigmaProtocolMsg> computeFirstMsg(const shared_ptr<SigmaProverInput> & input) override;

	/**
	* Computes the second message of the protocol.<p>
	* "COMPUTE z = (r + ew) mod q".<p>
	* @param challenge
	* @return the computed message.
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	*/
	shared_ptr<SigmaProtocolMsg> computeSecondMsg(const vector<byte> & challenge) override;
	
	/**
	* Returns the simulator that matches this sigma protocol prover.
	* @return SigmaDHSimulator
	*/

	shared_ptr<SigmaSimulator> getSimulator() override {
		return make_shared<SigmaDHExtendedSimulator>(dlog, t, random);
	}
};

/**
* Concrete implementation of Sigma Protocol verifier computation. <p>
*
* This protocol is used for a prover to convince a verifier that the input tuple (g1,...,gm,h1,...,hm) is an
* extended Diffie-Hellman tuple, meaning that there exists a single w in Zq such that hi=gi^w for all i.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.3 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDHExtendedVerifierComputation : public SigmaVerifierComputation, DlogBasedSigma {

	/*
	This class computes the following calculations:
	SAMPLE a random challenge  e <- {0, 1}^t
	ACC IFF VALID_PARAMS(G,q,g)=TRUE AND all g1,...,gm in G AND for all i=1,...,m it holds that gi^z = ai*hi^e

	*/

private:
	shared_ptr<DlogGroup> dlog;		// Underlying DlogGroup.
	int t; 							//Soundness parameter in BITS.
	vector<byte> e;					//The challenge.
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
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	* @throws IllegalArgumentException if soundness parameter is invalid.
	*/
	SigmaDHExtendedVerifierComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() { return t; }

	/**
	* Samples the chaalenge for this protocol.<p>
	* 	"SAMPLE a random challenge e<-{0,1}^t".
	*/
	void sampleChallenge() override;

	/**
	* Sets the given challenge.
	* @param challenge
	*/
	void setChallenge(const vector<byte> & challenge) {	e = challenge; }

	/**
	* Returns the sampled challenge.
	* @return the challenge.
	*/
	vector<byte> getChallenge() { return e; }

	/**
	* Computes the protocol's verification.<p>
	* Computes the following line from the protocol:<p>
	* 	"ACC IFF VALID_PARAMS(G,q,g)=TRUE AND all g1,...,gm in G AND for all i=1,...,m it holds that gi^z = ai*hi^e".   <p>
	* @param input MUST be an instance of SigmaDHExtendedCommonInput.
	* @param z second message from prover
	* @return true if the proof has been verified; false, otherwise.
	* @throws IllegalArgumentException if input is not an instance of SigmaDHExtendedCommonInput.
	* @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaDHExtendedMsg
	* @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
	*/
	bool verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) override;

};

