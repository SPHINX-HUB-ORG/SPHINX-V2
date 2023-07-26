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
#include "../primitives/Prg.hpp"

/**
* Concrete implementation of Sigma Protocol prover computation.<p>
*
* This protocol is used for a prover to convince a verifier that the AND of any number of statements are true,
* where each statement can be proven by an associated Sigma protocol.<P>
*
* The pseudo code of this protocol can be found in Protocol 1.14 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class SigmaANDProverComputation : public SigmaProverComputation {
	/*
	This class computes the following calculations:
	COMPUTE all first prover messages a1,...,am
	COMPUTE all second prover messages z1,...,zm
	*/

public:
	/**
	* Constructor that sets the underlying provers.
	* @param provers array of SigmaProverComputation, where each object represent a statement
	* 		  and the prover wants to prove to the verify that the AND of all statements are true.
	* @param t soundness parameter. t MUST be equal to all t values of the underlying provers object.
	*/
	SigmaANDProverComputation(const vector<shared_ptr<SigmaProverComputation>> & provers, int t, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg());
	/**
	* Returns the soundness parameter for this Sigma protocol.
	*/
	int getSoundnessParam() { return t; };
	/**
	* Computes the first message the protocol.<p>
	* "COMPUTE all first prover messages a1,...,am".
	* @param input MUST be an instance of SigmaANDInput.
	* @return SigmaMultipleMsg contains a1, ..., am.
	*/
	shared_ptr<SigmaProtocolMsg> computeFirstMsg(const shared_ptr<SigmaProverInput> & in) override;
	/**
	* Computes the second message of the protocol.<p>
	* "COMPUTE all second prover messages z1,...,zm".
	* @param challenge
	* @return SigmaMultipleMsg contains z1, ..., zm.
	*/
	shared_ptr<SigmaProtocolMsg> computeSecondMsg(const vector<byte> & challenge) override;
	/**
	* Returns the simulator that matches this sigma protocol prover.
	* @return SigmaANDSimulator
	*/
	shared_ptr<SigmaSimulator> getSimulator() override;

private:
	vector<shared_ptr<SigmaProverComputation>> provers;	// underlying Sigma protocol's provers to the AND calculation.
	shared_ptr<PrgFromOpenSSLAES> prg;
	int len;								// number of underlying provers.
	int t;									// soundness parameter.
	/**
	* Sets the inputs for each one of the underlying prover.
	* @param input MUST be an instance of SigmaANDProverInput.
	*/
	SigmaMultipleProverInput* checkInput(SigmaProverInput* in);
};

/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that the AND of any number of statements are true,
* where each statement can be proven by an associated Sigma protocol.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.14 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class SigmaANDSimulator : public SigmaSimulator {
	/*
	This class computes the following calculations:
	SAMPLE random values z1 <- ZN, z2 <- Z*n, z3 <- Z*n
	COMPUTE a1 = (1+n)^z1*(z2^N/c1^e) mod N' AND a2 = c2^z1/(z3^N*c3^e) mod N'
	OUTPUT (a,e,z) where a = (a1,a2) AND z=(z1,z2,z3)
	*/
public:
	/**
	* Constructor that gets the underlying simulators.
	* @param simulators array of SigmaSimulator, where each object represent a statement
	* 		  where the prover wants to prove to the verify that that the AND of all statements are true.
	* @param t soundness parameter. t MUST be equal to all t values of the underlying simulators object.
	* @param random source of randomness
	*/
	SigmaANDSimulator(const vector<shared_ptr<SigmaSimulator>> & simulators, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());
	int getSoundnessParam() override { return t; };
	/**
	* Computes the simulator computation with the given challenge.
	* @param input MUST be an instance of SigmaANDCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input, 
		const vector<byte> & challenge) override;
	/**
	* Computes the simulator computation with a randomly chosen challenge.
	* @param input MUST be an instance of SigmaANDCommonInput.
	* @return the output of the computation - (a, e, z).
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input) override;

private:
	vector<shared_ptr<SigmaSimulator>> simulators;	// Underlying Sigma protocol's simulators to the AND calculation.
	int len;							// Number of underlying simulators.
	int t;								// Soundness parameter.
	shared_ptr<PrgFromOpenSSLAES> random;
	/**
	* Checks if the given challenge length is equal to the soundness parameter.
	* @return true if the challenge length is t; false, otherwise.
	*/
	bool checkChallengeLength(int challenge_size) {
		// if the challenge's length is equal to t, return true. else, return false.
		return (challenge_size == (t / 8) ? true : false);
	};
};

/**
* Concrete implementation of Sigma Protocol verifier computation.<p>
* This protocol is used for a prover to convince a verifier that the AND of any number of statements are true,
* where each statement can be proven by an associated Sigma protocol.<p>
* The pseudo code of this protocol can be found in Protocol 1.14 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class SigmaANDVerifierComputation : public SigmaVerifierComputation {
public:
	/*
	This class computes the following calculations:
	SAMPLE a random challenge  e <- {0, 1}^t
	ACC IFF all verifier checks are ACC.
	*/

	/**
	* Constructor that gets the underlying verifiers.
	* @param verifiers array of SigmaVerifierComputation, where each object represent a statement
	* 		  and the prover wants to prove to the verify that that the AND of all statements are true.
	* @param t soundness parameter. t MUST be equal to all t values of the underlying verifiers object.
	* @param random source of randomness
	*/
	SigmaANDVerifierComputation(const vector<shared_ptr<SigmaVerifierComputation>> & verifiers, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());
	/**
	* Returns the soundness parameter for this Sigma protocol.
	*/
	int getSoundnessParam() override { return t; }
	/**
	* Samples the challenge of the protocol.<p>
	* 	"SAMPLE a random challenge e<-{0,1}^t".
	*/
	void sampleChallenge() override;

	void setChallenge(const vector<byte> & challenge) override;

	vector<byte> getChallenge() override { return e; };
	/**
	* Computes the verification of the protocol.<p>
	* 	"ACC IFF all verifier checks are ACC".
	* @param input MUST be an instance of SigmaANDCommonInput.
	* @param a first message from prover
	* @param z second message from prover
	* @return true if the proof has been verified; false, otherwise.
	*/
	bool verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) override;

private:
	vector<shared_ptr<SigmaVerifierComputation>> verifiers;	// underlying Sigma protocol's verifier to the AND calculation
	int len;										// number of underlying verifiers
	vector<byte>  e;								// the challenge
	int t;											// soundness parameter
	shared_ptr<PrgFromOpenSSLAES> random;							// prg
};



