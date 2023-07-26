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
* Concrete implementation of SigmaProtocol input, used by the SigmaDH verifier and simulator.<p>
* In SigmaProtocolDH, the common input contains three GroupElements - h, u, v.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDHCommonInput : public SigmaCommonInput {
public:
	/**
	* Sets the common input of this sigma protocol.
	* @param h
	* @param u
	* @param v
	*/
	SigmaDHCommonInput(const shared_ptr<GroupElement> & h, const shared_ptr<GroupElement> & u, const shared_ptr<GroupElement> & v) {
		this->h = h;
		this->u = u;
		this->v = v;
	}

	shared_ptr<GroupElement> getH() { return h; }

	shared_ptr<GroupElement> getU() { return u; }

	shared_ptr<GroupElement> getV() { return v; }

	string toString() override;

private:
	shared_ptr<GroupElement> h;
	shared_ptr<GroupElement> u;
	shared_ptr<GroupElement> v;

};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaDHProver.<p>
* In SigmaProtocolDH, the prover gets three GroupElements - h, u, v and a BigInteger w such that g^w = u and h^w = v.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDHProverInput: public SigmaProverInput {
public:
	/**
	* Sets the prover's input values that satisfy g^w = u and h^w = v.
	* @param h
	* @param u
	* @param v
	* @param w
	*/
	SigmaDHProverInput(const shared_ptr<GroupElement> & h, const shared_ptr<GroupElement> & u, const shared_ptr<GroupElement> & v, const biginteger & w) {
		params = make_shared<SigmaDHCommonInput>(h, u, v);
		this->w = w;
	}
	biginteger getW() {	return w; }
	shared_ptr<SigmaCommonInput> getCommonInput() override { return params; }

private:
	shared_ptr<SigmaDHCommonInput> params;
	biginteger w;
};

/**
* Concrete implementation SigmaProtocol message. <p>
* This message contains two GroupElement sendable data and used when the DH prover send the first message to the verifier.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDHMsg: public SigmaProtocolMsg {

public:
	SigmaDHMsg(const shared_ptr<GroupElementSendableData> & a, const shared_ptr<GroupElementSendableData> & b) {
		this->a = a;
		this->b = b;
	}
	shared_ptr<GroupElementSendableData> getA() { return a;	}
	shared_ptr<GroupElementSendableData> getB() { return b;	}
	
	// SerializedNetwork implementation:
	void initFromString(const string & s) override;
	string toString() override { return a->toString() + ":" + b->toString(); };

private:
	shared_ptr<GroupElementSendableData> a;
	shared_ptr<GroupElementSendableData> b;

};

/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that the input tuple (g,h,u,v)
* is a Diffie-Hellman tuple.<p>
*
* For more information see Protocol 6.2.4, page 152 of Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 1.2 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDHSimulator : public SigmaSimulator {
	/*
	This class computes the following calculations:
	SAMPLE a random z <- Zq
	COMPUTE a = g^z*u^(-e) and b = h^0z*v^(-e) (where -e here means -e mod q)
	OUTPUT ((a,b),e,z)

	*/
public:

	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaDHSimulator(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() { return t;	}

	/**
	* Computes the simulator computation.
	* @param input MUST be an instance of SigmaDHCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	* @throws IllegalArgumentException if the given input is not an instance of SigmaDHCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input, const vector<byte> & challenge)  override;

	/**
	* Computes the simulator computation.
	* @param input MUST be an instance of SigmaDHInput.
	* @return the output of the computation - (a, e, z).
	* @throws IllegalArgumentException if the given input is not an instance of SigmaDHInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input) override;

private:

	shared_ptr<DlogGroup> dlog; 		//Underlying DlogGroup.
	int t;								//Soundness parameter.
	shared_ptr<PrgFromOpenSSLAES> random;
	biginteger qMinusOne;

	/**
	* Checks if the given challenge length is equal to the soundness parameter.
	* @return true if the challenge length is t; false, otherwise.
	*/
	bool checkChallengeLength(int size) { return ((size == (t / 8)) ? true : false); }

	/**
	* Checks the validity of the given soundness parameter.
	* @return true if the soundness parameter is valid; false, otherwise.
	*/
	bool checkSoundnessParam();

};

/**
* Concrete implementation of Sigma Protocol prover computation. <p>
* This protocol is used for a prover to convince a verifier that the input tuple (g,h,u,v)
* is a Diffie-Hellman tuple.<p>
*
* For more information see Protocol 6.2.4, page 152 of Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 1.2 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDHProverComputation : public SigmaProverComputation, public DlogBasedSigma {

public:
	/*
	This class computes the following calculations:
	SAMPLE a random r in Zq
	COMPUTE a = g^r and b = h^r
	COMPUTE z = r + ew mod q
	*/

	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	* @throws IllegalArgumentException if soundness parameter is invalid.
	*/
	SigmaDHProverComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return t; }

	/**
	* Computes the first message of the protocol.<p>
	* "SAMPLE a random r in Zq<p>
	* COMPUTE a = g^r and b = h^r".
	* @param input MUST be an instance of SigmaDHProverInput.
	* @return the computed message
	* @throws IllegalArgumentException if input is not an instance of SigmaDHProverInput.
	*/
	shared_ptr<SigmaProtocolMsg> computeFirstMsg(const shared_ptr<SigmaProverInput> & input) override;

	/**
	* Computes the second message of the protocol.<p>
	* "COMPUTE z = (r + ew) mod q".
	* @param challenge
	* @return the computed message.
	* @throws CheatAttemptException if the length of the received challenge is not equal to the soundness parameter.
	*/
	shared_ptr<SigmaProtocolMsg> computeSecondMsg(const vector<byte> & challenge) override;

	/**
	* Returns the simulator that matches this sigma protocol prover.
	* @return SigmaDHSimulator
	*/
	shared_ptr<SigmaSimulator> getSimulator() override {
		auto res = make_shared<SigmaDHSimulator>(dlog, t, random);
		return res;
	}

private:
	shared_ptr<DlogGroup> dlog;				// Underlying DlogGroup.
	int t; 									// soundness parameter in BITS.
	shared_ptr<PrgFromOpenSSLAES> random;							//source of randomness to use.
	shared_ptr<SigmaDHProverInput> input;	// Contains h, u, v and w. 
	biginteger r;							// The value chosen in the protocol.
	biginteger qMinusOne;

	/**
	* Checks if the given challenge length is equal to the soundness parameter.
	* @return true if the challenge length is t; false, otherwise.
	*/
	bool checkChallengeLength(int size) { return ((size == (t / 8)) ? true : false); }

	/**
	* Checks the validity of the given soundness parameter.
	* @return true if the soundness parameter is valid; false, otherwise.
	*/
	bool checkSoundnessParam();

};


/**
* Concrete implementation of Sigma Protocol verifier computation. <p>
* This protocol is used for a prover to convince a verifier that the input tuple (g,h,u,v)
* is a Diffie-Hellman tuple.<p>
*
* For more information see Protocol 6.2.4, page 152 of Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 1.2 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaDHVerifierComputation : public SigmaVerifierComputation, public DlogBasedSigma {
public:
	/*
	This class computes the following calculations:
	SAMPLE a random challenge  e <- {0, 1}^t
	ACC IFF VALID_PARAMS(G,q,g) = TRUE AND h in G AND g^z = au^e  AND h^z = bv^e
	*/

	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	* @throws IllegalArgumentException if soundness parameter is invalid.
	*/
	SigmaDHVerifierComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return t;	}

	/**
	* Samples the challenge of the protocol.<P>
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
	* Computers the protocol's verification.<p>
	* Computes the following line from the protocol:<p>
	* 	"ACC IFF VALID_PARAMS(G,q,g) = TRUE AND h in G AND g^z = au^e  AND h^z = bv^e".   <p>
	* @param input MUST be an instance of SigmaDHCommonInput.
	* @param z second message from prover
	* @return true if the proof has been verified; false, otherwise.
	* @throws IllegalArgumentException if input is not an instance of SigmaDHCommonInput.
	* @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaDHMsg
	* @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
	*/
	bool verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) override;

private:
		shared_ptr<DlogGroup> dlog;			// Underlying DlogGroup.
		int t; 								//Soundness parameter in BITS.
		vector<byte> e;						// The challenge.
		shared_ptr<PrgFromOpenSSLAES> random;

		/**
		* Checks the validity of the given soundness parameter.
		* @return true if the soundness parameter is valid; false, otherwise.
		*/
		bool checkSoundnessParam();

};