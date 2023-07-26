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

/**
* Checks if the given challenge length is equal to the soundness parameter.
*/
bool checkChallengeLength(const vector<byte> & challenge, int t);



/**
* Concrete implementation of SigmaProtocol input, used by the SigmaDlog verifier and simulator.<p>
* In SigmaProtocolDlog, the common input contains a GroupElement h.
*/
class SigmaDlogCommonInput : public SigmaCommonInput {
public:
	SigmaDlogCommonInput(const shared_ptr<GroupElement> & h) { this->h = h; };
	shared_ptr<GroupElement> getH() { return h; };

	string toString() override { return h->generateSendableData()->toString(); }

private:
	shared_ptr<GroupElement> h;
};

/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that it knows the discrete log of the value h in G.<P>
*
* For more information see protocol 6.1.1, page 148 of Hazay - Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 1.1 of pseudo codes document at{ @link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.
*/
class SigmaDlogSimulator : public SigmaSimulator {
	/*
	This class computes the following calculations:
	SAMPLE a random z <- Zq
	COMPUTE a = g^z*h^(-e)  (where -e here means -e mod q)
	OUTPUT (a,e,z).
	*/
public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	*/
	SigmaDlogSimulator(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());
	/**
	* Returns the soundness parameter for this Sigma protocol.
	*/
	int getSoundnessParam() override { return t; };
	/**
	* Computes the simulator computation, using the given challenge.<p>
	* "SAMPLE a random z <- Zq <p>
	*	COMPUTE a = g^z*h^(-e)  (where -e here means -e mod q)<p>
	*	OUTPUT (a,e,z)".	<p>
	* @param input MUST be an instance of SigmaDlogCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, eSize, z).
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input, 
		const vector<byte> & challenge) override;
	/**
	* Computes the simulator computation, using random challenge.<p>
	* "SAMPLE a random z <- Zq<p>
	*	COMPUTE a = g^z*h^(-e)  (where -e here means -e mod q)<p>
	*	OUTPUT (a,e,z)".	<p>
	* @param input MUST be an instance of SigmaDlogCommonInput.
	* @return the output of the computation - (a, e, z).
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input) override;

private:
	shared_ptr<DlogGroup> dlog; 		//Underlying DlogGroup.
	int t;					//Soundness parameter.
	shared_ptr<PrgFromOpenSSLAES> random;
	biginteger qMinusOne;
	
	/**
	* Checks the validity of the given soundness parameter.
	*/
	bool checkSoundnessParam();
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaDlogProver.<p>
* In SigmaProtocolDlog, the prover gets a GroupElement h and a BigInteger w such that g^w = h.
*/
class SigmaDlogProverInput : public SigmaProverInput {
public:
	/**
	* Sets the given h and w, such that g^w = h.
	*/
	SigmaDlogProverInput(const shared_ptr<GroupElement> & h, const biginteger & w) {
		params = make_shared<SigmaDlogCommonInput>(h);
		this->w = w;
	};
	/**
	* Returns w element, such that g^w = h.
	*/
	biginteger getW() { return w; };
	shared_ptr<SigmaCommonInput> getCommonInput() override { return params; };

private:
	shared_ptr<SigmaDlogCommonInput> params;
	biginteger w;
};


/**
* Concrete implementation of Sigma Protocol prover computation.<p>
* This protocol is used for a prover to convince a verifier that it knows the discrete log of the value h in G. <p>
* This implementation is based on Schnorr's sigma protocol for Dlog Group, see reference in Protocol 6.1.1, page 148 of Hazay-Lindell.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.1 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.
*/
class SigmaDlogProverComputation : public SigmaProverComputation, public DlogBasedSigma {
	/*
	This class computes the following calculations:
	SAMPLE a random r in Zq
	COMPUTE a = g^r
	COMPUTE z = r + ew mod q
	*/
public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	*/
	SigmaDlogProverComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());
	int getSoundnessParam() override { return t; };
	/**
	* Computes the first message from the protocol.<p>
	* "SAMPLE a random r in Zq<p>
	*  COMPUTE a = g^r". <p>
	* @param input MUST be an instance of SigmaDlogProverInput.
	* @return the computed message
	*/
	shared_ptr<SigmaProtocolMsg> computeFirstMsg(const shared_ptr<SigmaProverInput> & input) override;
	/**
	* Computes the secong message from the protocol.<p>
	* "COMPUTE z = (r + ew) mod q".<p>
	* @param challenge<p>
	* @return the computed message.
	*/
	shared_ptr<SigmaProtocolMsg> computeSecondMsg(const vector<byte> & challenge) override;
	/**
	* Returns the simulator that matches this sigma protocol prover.
	*/
	shared_ptr<SigmaSimulator> getSimulator() override { 
		auto res = make_shared<SigmaDlogSimulator>(dlog, t, random);
		return res; };

private:
	shared_ptr<DlogGroup> dlog;				// Underlying DlogGroup.
	int t;	 						// soundness parameter in BITS.
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<SigmaDlogProverInput> input;	// Contains h and w.
	biginteger r;				// The value chosen in the protocol.
	biginteger qMinusOne;

	/**
	* Checks the validity of the given soundness parameter.
	* @return true if the soundness parameter is valid; false, otherwise.
	*/
	bool checkSoundnessParam();
};

/**
* Concrete implementation of Sigma Protocol verifier computation. <p>
* This protocol is used for a prover to convince a verifier that it knows the discrete log of the value h in G. <P>
* This implementation is based on Schnorr's sigma protocol for Dlog Group, see reference in Protocol 6.1.1, page 148 of Hazay-Lindell..<p>
* The pseudo code of this protocol can be found in Protocol 1.1 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.
*/
class SigmaDlogVerifierComputation : public SigmaVerifierComputation, public DlogBasedSigma {
	/*
	This class computes the following calculations:
	SAMPLE a random challenge  e <- {0, 1}^t
	ACC IFF VALID_PARAMS(G,q,g) = TRUE AND h in G AND g^z = ah^e
	*/
public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaDlogVerifierComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());
	/**
	* Returns the soundness parameter for this Sigma protocol.
	*/
	int getSoundnessParam() override { return t; }
	/**
	* Samples the challenge to use in the protocol.<p>
	* 	"SAMPLE a random challenge e<-{0,1}^t".
	*/
	void sampleChallenge() override;
	/**
	* Sets the given challenge and its size.
	*/
	void setChallenge(const vector<byte> & challenge) override { e = challenge;	}

	/**
	* Returns the sampled challenge.
	*/
	vector<byte> getChallenge() override { return e; };

	/**
	* Verifies the proof.<p>
	* Computes the following line from the protocol:<p>
	* 	"ACC IFF VALID_PARAMS(G,q,g) = TRUE AND h in G AND g^z = ah^e".<p>
	* @param a first message from prover
	* @param z second message from prover
	* @param input MUST be an instance of SigmaDlogCommonInput.
	* @return true if the proof has been verified; false, otherwise.
	*/
	bool verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) override;

private:
	shared_ptr<DlogGroup> dlog;		// Underlying DlogGroup.
	int t; 							// Soundness parameter in BITS.
	vector<byte> e;					// The challenge.
	shared_ptr<PrgFromOpenSSLAES> random;

	/**
	* Checks the validity of the given soundness parameter.
	*/
	bool checkSoundnessParam();
};
