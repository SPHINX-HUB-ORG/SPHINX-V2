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
#include "../infra/Common.hpp"
#include "../primitives/Prg.hpp"

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaProtocolORTwoProver.<p>
*
* In SigmaProtocolORTwo protocol, the prover gets an input for the true statement (with witness),
* an input for the false statement (without witness) and a bit b, such that (xb,w) is in R.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaOrTwoProverInput : public SigmaProverInput {

private:
	shared_ptr<SigmaProverInput> proverInput;
	shared_ptr<SigmaCommonInput> simulatorInput;
	byte b;

public:
	/**
	* Sets the inputs for the underlying prover and simulator and a bit b, such that (xb,w) is in R.
	* @param proverInput
	* @param simulatorInput
	* @param b such that (xb,w) is in R.
	*/
	SigmaOrTwoProverInput(const shared_ptr<SigmaProverInput> & proverInput, const shared_ptr<SigmaCommonInput> & simulatorInput, byte b) {
		this->proverInput = proverInput;
		this->simulatorInput = simulatorInput;
		this->b = b;
	}

	/**
	* Returns the bit b such that (xb,w) is in R.
	*/
	byte getB() { return b;	}

	/**
	* Returns the input for the underlying prover.
	*/
	shared_ptr<SigmaProverInput> getProverInput() {	return proverInput;	}

	/**
	* Returns the input for the underlying simulator.
	*/
	shared_ptr<SigmaCommonInput> getSimulatorInput() { return simulatorInput; }

	shared_ptr<SigmaCommonInput> getCommonInput() override;
};

/**
* Concrete implementation of SigmaProtocol message.
*
* This message contains two SigmaProtocolMsg and two challenges and used when the SigmaORProver sends the second message to the verifier.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar - Ilan University(Moriya Farbstein)
*
*/
class SigmaOrTwoSecondMsg : public SigmaProtocolMsg {


private:
	shared_ptr<SigmaProtocolMsg> z0;
	vector<byte> e0;
	shared_ptr<SigmaProtocolMsg> z1;
	vector<byte> e1;

public:
	SigmaOrTwoSecondMsg(const shared_ptr<SigmaProtocolMsg> & z0, const vector<byte> & e0, const shared_ptr<SigmaProtocolMsg> & z1, const vector<byte> & e1) {
		this->z0 = z0;
		this->e0 = e0;
		this->z1 = z1;
		this->e1 = e1;
	}

	shared_ptr<SigmaProtocolMsg> getZ0() { return z0; }

	vector<byte> getE0() { return e0; }

	shared_ptr<SigmaProtocolMsg> getZ1() {return z1; }

	vector<byte> getE1() { return e1; }

	void initFromString(const string & s) override;
	string toString() override;
};

/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that at least one of two statements is true,
* where each statement can be proven by an associated Sigma protocol.
*
* For more information see Protocol 6.4.1, page 159 of Hazay-Lindell.<P>
* The pseudo code of this protocol can be found in Protocol 1.15 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaOrTwoSimulator : public SigmaSimulator {

	/*
	This class computes the following calculations:
	SAMPLE a random e0,
	COMPUTE e1 = e XOR e0
	RUN the Sigma protocol simulator for each protocol with the resulting e0,e1 values.

	*/

private:
	vector<shared_ptr<SigmaSimulator>> simulators;			//underlying simulators.
	int t;													// Soundness parameter.
	shared_ptr<PrgFromOpenSSLAES> random;

	/**
	* Checks if the given challenge length is equal to the soundness parameter.
	* @return true if the challenge length is t; false, otherwise.
	*/
	bool checkChallengeLength(int size);

public:
	/**
	* Constructor that gets the underlying simulators.
	* @param simulators array of SigmaSimulator that contains TWO underlying simulators.
	* @param t soundness parameter. t MUST be equal to both t values of the underlying simulators object.
	* @throws IllegalArgumentException if the given t is not equal to both t values of the underlying simulators.
	* @throws IllegalArgumentException if the given simulators array does not contains two objects.
	*/
	SigmaOrTwoSimulator(const vector<shared_ptr<SigmaSimulator>> & simulators, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return t; }

	/**
	* Computes the simulator computation with the given challenge.
	* @param input MUST be an instance of SigmaORTwoCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	* @throws IllegalArgumentException if the given input is not an instance of SigmaORTwoCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input, const vector<byte> & challenge)  override;

	/**
	* Computes the simulator computation with a randomly chosen challenge.
	* @param input MUST be an instance of SigmaORTwoCommonInput.
	* @return the output of the computation - (a, e, z).
	* @throws IllegalArgumentException if the given input is not an instance of SigmaORTwoCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input) override;
};

/**
* Concrete implementation of Sigma Protocol prover computation.<p>
*
* This protocol is used for a prover to convince a verifier that at least one of two statements is true,
* where each statement can be proven by an associated Sigma protocol.
*
* For more information see Protocol 6.4.1, page 159 of Hazay-Lindell.<P>
* The pseudo code of this protocol can be found in Protocol 1.15 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaOrTwoProverComputation : public SigmaProverComputation {
	/*
	Let (ai,ei,zi) denote the steps of a Sigma protocol SigmaI for proving that xi is in LRi (i=0,1)
	This class computes the following calculations:
	COMPUTE the first message ab in SigmaB, using (xb,w) as input
	SAMPLE a random challenge  e1-b <- {0, 1}^t
	RUN the simulator M for SigmaI on input (x1-b, e1-b) to obtain (a1-b, e1-b, z1-b)
	The message is (a0,a1); e1-b,z1-b are stored for later.
	SET eb = e XOR e1-b
	COMPUTE the response zb to (ab, eb) in SigmaB using input (xb,w)
	The message is e0,z0,e1,z1

	*/

private:
	shared_ptr<SigmaProverComputation> prover;		//Underlying Sigma protocol prover.
	shared_ptr<SigmaSimulator> simulator;			//Underlying Sigma protocol simulator.
	shared_ptr<PrgFromOpenSSLAES> random;
	int t;											//Soundness parameter.
	int b;											// The bit b such that (xb,w) is in R.
	vector<byte> eOneMinusB;						//Sampled challenge for the simulator.
	shared_ptr<SigmaProtocolMsg> zOneMinusB;		// The output of the simulator.

	/**
	* Checks if the given challenge length is equal to the soundness parameter.
	* @return true if the challenge length is t; false, otherwise.
	*/
	bool checkChallengeLength(int size);

public:
	/**
	* Constructor that gets the underlying provers.
	* @param provers array of SigmaProverComputation that contains TWO underlying provers.
	* @param t soundness parameter. t MUST be equal to both t values of the underlying provers object.
	* @throws IllegalArgumentException if the given t is not equal to both t values of the underlying provers.
	* @throws IllegalArgumentException if the given provers array does not contains two objects.
	*/
	SigmaOrTwoProverComputation(const shared_ptr<SigmaProverComputation> & prover, const shared_ptr<SigmaSimulator> & simulator, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return t; }

	/**
	* Computes the frist message of the protocol.<p>
	* "SAMPLE a random challenge  e1-b <- {0, 1}^t" for the simulator.<p>
	*  COMPUTE the first message ab in SigmaB, using (xb,w) as input.<p>
	*	RUN the simulator M for SigmaI on input (x1-b, e1-b) to obtain (a1-b, e1-b, z1-b).<p>
	*	The message is (a0,a1); e1-b,z1-b are stored for later".
	* @param input MUST be an instance of SigmaORTwoProverInput.
	* @return SigmaORFirstMsg contains a0, a1.
	* @throws IllegalArgumentException if input is not an instance of SigmaORTwoProverInput.
	*/
	shared_ptr<SigmaProtocolMsg> computeFirstMsg(const shared_ptr<SigmaProverInput> & input) override;

	/**
	* Computes the second message of the protocol.<p>
	* "SET eb = e XOR e1-b<p>
	*	COMPUTE the response zb to (ab, eb) in SigmaB using input (xb,w)<p>
	*	The message is e0,z0,e1,z1".
	* @param challenge
	* @return SigmaORTwoSecondMsg contains e0,z0,e1,z1.
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	*/
	shared_ptr<SigmaProtocolMsg> computeSecondMsg(const vector<byte> & challenge) override;

	/**
	* Returns the simulator that matches this sigma protocol prover.
	* @return SigmaProtocolANDSimulator
	*/
	shared_ptr<SigmaSimulator> getSimulator() override;
};

/**
* Concrete implementation of Sigma Protocol verifier computation.<p>
*
* This protocol is used for a prover to convince a verifier that at least one of two statements is true,
* where each statement can be proven by an associated Sigma protocol.
*
* For more information see Protocol 6.4.1, page 159 of Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 1.15 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaOrTwoVerifierComputation : public SigmaVerifierComputation {

	/*
	Let (ai,ei,zi) denote the steps of a Sigma protocol SigmaI for proving that xi is in LRi (i=0,1)
	This class computes the following calculations:
	SAMPLE a single random challenge  e <- {0, 1}^t
	ACC IFF all verifier checks are ACC.
	*/

private:
	vector<shared_ptr<SigmaVerifierComputation>> verifiers;	// Underlying Sigma protocol verifiers to the OR calculation.
	vector<byte> e;											//The challenge.
	int t;													//Soundness parameter.
	shared_ptr<PrgFromOpenSSLAES> random;

public:
	/**
	* Constructor that gets the underlying verifiers.
	* @param verifiers array of SigmaVerifierComputation that contains TWO underlying verifiers.
	* @param t soundness parameter. t MUST be equal to both t values of the underlying verifiers objects.
	* @throws IllegalArgumentException if the given t is not equal to both t values of the underlying verifiers.
	* @throws IllegalArgumentException if the given verifiers array does not contains two objects.
	*/
	SigmaOrTwoVerifierComputation(const vector<shared_ptr<SigmaVerifierComputation>> & verifiers, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return t; }

	/**
	* Samples the challenge of the protocol.<p>
	* 	"SAMPLE a random challenge e<-{0,1}^t".
	*/
	void sampleChallenge() override {
		//make space for t/8 bytes and fill it with random values.
		e.resize(t / 8);
		random->getPRGBytes(e, 0, t / 8);
	}

	/**
	* Sets the given challenge.
	* @param challenge
	*/
	void setChallenge(const vector<byte> & challenge) override { e = challenge;	}

	/**
	* Returns the sampled challenge.
	* @return the challenge.
	*/
	vector<byte> getChallenge() { return e; }

	/**
	* Computes the following line from the protocol:
	* 	"ACC IFF all verifier checks are ACC".
	* @param input MUST be an instance of SigmaORTwoCommonInput.
	* @param a first message from prover
	* @param z second message from prover
	* @return true if the proof has been verified; false, otherwise.
	* @throws IllegalArgumentException if input is not an instance of SigmaORTwoCommonInput.
	* @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaORTwoFirstMsg
	* @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaORTwoSecondMsg
	*/
	bool verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) override; 
};

