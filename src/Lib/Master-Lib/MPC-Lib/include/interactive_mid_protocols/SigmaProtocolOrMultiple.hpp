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
#include <NTL/GF2X.h>
#include <NTL/GF2E.h>
#include <NTL/GF2XFactoring.h>
#include <NTL/vec_GF2E.h>
#include <NTL/GF2EX.h>
#include <NTL/ZZ.h>

#include "SigmaProtocol.hpp"
#include "../primitives/Prg.hpp"
#include <map>

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaProtocolORMultiple verifier and simulator.<p>
* In SigmaProtocolORMultiple, the common input contains an array of inputs to all of
* its underlying objects and k - number of true statements.
*/
class SigmaOrMultipleCommonInput : public SigmaCommonInput {
public:

	/**
	* Sets the input array and the number of statements that have a witness.
	* @param input contains inputs for all the underlying sigma protocol.
	* @param k number of statements that have a witness.
	*/
	SigmaOrMultipleCommonInput(const vector<shared_ptr<SigmaCommonInput>> & input, int k) {
		sigmaInputs = input;
		this->k = k;
	};

	/**
	* Returns the input array contains inputs for all the underlying sigma protocol.
	*/
	vector<shared_ptr<SigmaCommonInput>> getInputs() { return sigmaInputs; };

	/**
	* Returns the number of statements that have a witness.
	*/
	int getK() { return k; };

	string toString() override;

private:
	vector<shared_ptr<SigmaCommonInput>> sigmaInputs;
	int k; //number of statements that have a witness.
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaProtocolORMultipleProver.<p>
* This input contains inputs for the true statements(including witnesses) and input for the false atatements(without witnesses).
*/
class SigmaOrMultipleProverInput  : public SigmaProverInput {
private:
	//hold the prover private input.
	map<int, shared_ptr<SigmaProverInput>> proverInputs;

	//Hold the common parameters of the statement where the prover does not know the witness.
	map<int, shared_ptr<SigmaCommonInput>> simulatorInputs;

public:
	/**
	* Sets the inputs for the underlying provers and simulators.
	* @param proverInputs
	* @param simulatorInputs
	*/
	SigmaOrMultipleProverInput(const map<int, shared_ptr<SigmaProverInput>> & proverInputs, const map<int, shared_ptr<SigmaCommonInput>> & simulatorInputs) {
		this->proverInputs = proverInputs;
		this->simulatorInputs = simulatorInputs;
	}

	/**
	* Returns an array holds the inputs for the underlying provers.
	* @return an array holds the inputs for the underlying provers.
	*/
	map<int, shared_ptr<SigmaProverInput>> getProversInput() { return proverInputs; };

	/**
	* Returns an array holds the inputs for the underlying simulators.
	* @return an array holds the inputs for the underlying simulators.
	*/
	map<int, shared_ptr<SigmaCommonInput>> getSimulatorsInput() { return simulatorInputs; };

	shared_ptr<SigmaCommonInput> getCommonInput() override;
};

/**
* Concrete implementation of SigmaProtocol message.
* This message contains an array the interpolated polynomial, array of SigmaProtocolMsg and challenges.
* The prover used this message to send the first message to the verifier.
*/
class SigmaOrMultipleSecondMsg : public SigmaProtocolMsg {

private:
	vector<vector<byte>> polynomial;
	vector<shared_ptr<SigmaProtocolMsg>> z;
	vector<vector<byte>> challenges;

public:
	SigmaOrMultipleSecondMsg(const vector<vector<byte>> & polynomBytes, const vector<shared_ptr<SigmaProtocolMsg>> & z, const vector<vector<byte>> & challenges) {
		this->polynomial = polynomBytes;
		this->z = z;
		this->challenges = challenges;
	};

	vector<vector<byte>> getPolynomial() { return polynomial; };

	vector<shared_ptr<SigmaProtocolMsg>> getMessages() { return z; };

	vector<vector<byte>> getChallenges() { return challenges; };

	string toString() override;
	void initFromString(const string & raw) override;
};

//Initializes the field GF2E with a random irreducible polynomial with degree t.
void initField(int t, int seed);
//Samples random field elements to be the challenges.
vector<vector<byte>> sampleRandomFieldElements(int numElements, int t, vector<shared_ptr<NTL::GF2E>> & elements, PrgFromOpenSSLAES*  random);
vector<byte> convertElementToBytes(NTL::GF2E & element);
NTL::GF2E convertBytesToGF2E(const vector<byte> & elementByts);
NTL::GF2E generateIndexPolynomial(int i);
//Interpolates the points to get a polynomial.
NTL::GF2EX interpolate(const vector<byte> & challenge, vector<shared_ptr<NTL::GF2E>> & fieldElements, const vector<int> & sampledIndexes);
//Calculates the challenges for the statements with the witnesses.
vector<vector<byte>> getRestChallenges(NTL::GF2EX & polynomial, const vector<int> & indexesInI);
//Returns the byteArray of the polynomial coefficients.
vector<vector<byte>> getPolynomialBytes(NTL::GF2EX & polynomial);

/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that at least k out of n
* statements is true, where each statement can be proven by an associated Sigma protocol.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.16 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaOrMultipleSimulator : public SigmaSimulator {

	/*
	This class computes the following calculations:
	SAMPLE random points e1,...,en-k in GF[2t].
	COMPUTE the polynomial Q and values en-k+1,...,en like in the protocol.
	RUN the simulator on each statement/challenge pair (xi,ei) for all i=1,...,n to obtain (ai,ei,zi).
	OUTPUT (a1,e1,z1),..., (an,en,zn).
	*/

private:
	vector<shared_ptr<SigmaSimulator>> simulators;	// Underlying simulators.
	int t;								// Soundness parameter.
	int len;							// Number of underlying simulators.
	shared_ptr<PrgFromOpenSSLAES> random;

	/**
	* Checks if the given challenge length is equal to the soundness parameter.
	* @return true if the challenge length is t; false, otherwise.
	*/
	bool checkChallengeLength(int size);

public:
	/**
	* Constructor that gets the underlying simulators.
	* @param simulators array of SigmaSimulator that contains underlying simulators.
	* @param t soundness parameter. t MUST be equal to both t values of the underlying simulators object.
	* @param random
	*/
	SigmaOrMultipleSimulator(const vector<shared_ptr<SigmaSimulator>> & simulators, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return t; }

	/**
	* Computes the simulator computation with the given challenge.
	* @param input MUST be an instance of SigmaORMultipleCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	* @throws IllegalArgumentException if the given input is not an instance of SigmaORMultipleCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input, const vector<byte> & challenge) override;

	/**
	* Computes the simulator computation with a randomly chosen challenge.
	* @param input MUST be an instance of SigmaORMultipleCommonInput.
	* @return the output of the computation - (a, e, z).
	* @throws IllegalArgumentException if the given input is not an instance of SigmaORMultipleCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input) override;
};


/**
* Concrete implementation of Sigma Protocol prover computation.<p>
*
* This protocol is used for a prover to convince a verifier that at least k out of n statements are true,
* where each statement can be proven by an associated Sigma protocol.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.16 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaOrMultipleProverComputation : public SigmaProverComputation {

	/*
	* Let (ai,ei,zi) denote the steps of a Sigma protocol SigmaI for proving that xi is in LRi
	* Let I denote the set of indices for which P has witnesses
	This class computes the following calculations:
	For every j not in I, SAMPLE a random element ej <- GF[2^t]
	For every j not in I, RUN the simulator on statement xj and challenge ej to get transcript (aj,ej,zj)
	For every i in I, RUN the prover P on statement xi to get first message ai
	SET a=(a1,...,an)

	INTERPOLATE the points (0,e) and {(j,ej)} for every j not in I to obtain a degree n-k polynomial Q (s.t. Q(0)=e and Q(j)=ej for every j not in I)
	For every i in I, SET ei = Q(i)
	For every i in I, COMPUTE the response zi to (ai, ei) in SigmaI using input (xi,wi)
	The message is Q,e1,z1,...,en,zn (where by Q we mean its coefficients)
	*/

private:
	map<int, shared_ptr<SigmaProverComputation>> provers;	// Underlying Sigma protocol's provers to the OR calculation.
	map<int, shared_ptr<SigmaSimulator>> simulators;		// Underlying Sigma protocol's simulators to the OR calculation.
	int len;												// Number of underlying provers.
	int t;													// Soundness parameter.
	int k;													//number of witnesses.
	shared_ptr<PrgFromOpenSSLAES> random;											// The indexes of the statements which the prover knows the witnesses.

	shared_ptr<SigmaOrMultipleProverInput> input;			// Used in computeFirstMsg function.

	vector<vector<byte>> challenges;						// hold the challenges to the underlying simulators and provers.
															// Some will be calculate in sampleRandomValues function and some in compueSecondMsg. 

	map<int, shared_ptr<SigmaSimulatorOutput>> simulatorsOutput;		// We save this because we calculate it in computeFirstMsg and using 
															// it after that, in computeSecondMsg

	vector<shared_ptr<NTL::GF2E>> elements;					//Will hold pointers to the sampled field elements, 
															//we save the pointers to save the creation of the elements again in computeSecondMsg function.

public:
	/**
	* Constructor that gets the underlying provers.
	* @param provers array of SigmaProverComputation, where each object represent a statement
	* 		  and the prover wants to prove to the verify that the OR of all statements are true.
	* @param t soundness parameter. t MUST be equal to all t values of the underlying provers object.
	* @throws IllegalArgumentException if the given t is not equal to all t values of the underlying provers object.
	*/
	SigmaOrMultipleProverComputation(const map<int, shared_ptr<SigmaProverComputation>> & provers, const map<int, shared_ptr<SigmaSimulator>> & simulators, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return t; }

	/**
	* Computes the first message of the protocol.<p>
	* "For every j not in I, SAMPLE a random element ej <- GF[2^t]<p>
	*  For every j not in I, RUN the simulator on statement xj and challenge ej to get transcript (aj,ej,zj)<p>
	For every i in I, RUN the prover P on statement xi to get first message ai<p>
	SET a=(a1,...,an)".
	* @param input MUST be an instance of SigmaORMultipleInput.
	* @return SigmaMultipleMsg contains a1, ..., am.
	* @throws IllegalArgumentException if input is not an instance of SigmaORMultipleInput.
	* @throws IllegalArgumentException if the number of given inputs is different from the number of underlying provers.
	*/
	shared_ptr<SigmaProtocolMsg> computeFirstMsg(const shared_ptr<SigmaProverInput> & input) override;

	/**
	* Computes the second message of the protocol.<p>
	* "INTERPOLATE the points (0,e) and {(j,ej)} for every j not in I to obtain a degree n-k polynomial Q (s.t. Q(0)=e and Q(j)=ej for every j not in I)<p>
	For every i in I, SET ei = Q(i)<p>
	For every i in I, COMPUTE the response zi to (ai, ei) in Sigmai using input (xi,wi)<p>
	The message is Q,e1,z1,...,en,zn (where by Q we mean its coefficients)".<p>
	* @param challenge
	* @return SigmaMultipleMsg contains z1, ..., zm.
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	*/
	shared_ptr<SigmaProtocolMsg> computeSecondMsg(const vector<byte> & challenge) override;

	/**
	* Returns the simulator that matches this sigma protocol prover.
	* @return SigmaORMultipleSimulator
	*/
	shared_ptr<SigmaSimulator> getSimulator() override;
};

/**
* Concrete implementation of Sigma Protocol verifier computation.<p>
*
* This protocol is used for a prover to convince a verifier that at least k out of n statements is true,
* where each statement can be proven by an associated Sigma protocol.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.16 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaOrMultipleVerifierComputation : public SigmaVerifierComputation {

	/*
	Let (ai,ei,zi) denote the steps of a Sigma protocol Sigmai for proving that xi is in LRi
	This class computes the following calculations:
	WAIT for messages a1,...,an
	SAMPLE a single random challenge  e <- GF[2^t]

	ACC IFF Q is of degree n-k AND Q(i)=ei for all i=1,...,n AND Q(0)=e, and the verifier output on (ai,ei,zi) for all i=1,...,n is ACC

	*/

private:
	vector<shared_ptr<SigmaVerifierComputation>> verifiers;	// Underlying Sigma protocol verifiers to the OR calculation.
	int len;										// Number of underlying verifiers.
	vector<byte> challengeBytes;										// The challenge.
	int t;											// Soundness parameter.
	NTL::GF2E challengeElement;							// Pointer to the sampled challenge element.
	int k;											// Number of true statements.
	shared_ptr<PrgFromOpenSSLAES> random;

	bool checkPolynomialValidity(const vector<vector<byte>> & polynomial, int k, const NTL::GF2E & challengeElement, const vector<vector<byte>> & challenges);
	NTL::GF2EX createPolynomial(const vector<vector<byte>> & polynomialBytes);

public:
	/**
	* Constructor that gets the underlying verifiers.
	* @param verifiers array of SigmaVerifierComputation, where each object represent a statement
	* 		  and the prover wants to convince a verifier that at least k out of n statements is true.
	* @param t soundness parameter. t MUST be equal to all t values of the underlying verifiers object.
	* @param random source of randomness
	* @throws IllegalArgumentException if the given t is not equal to all t values of the underlying verifiers object.
	*/
	SigmaOrMultipleVerifierComputation(const vector<shared_ptr<SigmaVerifierComputation>> & verifiers, int t, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return t; }

	/**
	* Samples the challenge of the protocol.<p>
	* 	"SAMPLE a single random challenge  e <- GF[2^t]".
	*/
	void sampleChallenge() override;

	/**
	* Sets the given challenge.
	* @param challenge
	*/
	void setChallenge(const vector<byte> & challenge) override;

	/**
	* Returns the sampled challenge.
	* @return the challenge.
	*/
	vector<byte> getChallenge() override { return challengeBytes; }

	/**
	* Computes the verification of the protocol.<p>
	* 	"ACC IFF Q is of degree n-k AND Q(i)=ei for all i=1,...,n AND Q(0)=e, and the verifier output on (ai,ei,zi) for all i=1,...,n is ACC".
	* @param input MUST be an instance of SigmaORMultipleCommonInput.
	* @param a first message from prover
	* @param z second message from prover
	* @return true if the proof has been verified; false, otherwise.
	* @throws IllegalArgumentException if input is not an instance of SigmaORMultipleCommonInput.
	* @throws IllegalArgumentException if the number of given inputs is different from the number of underlying verifier.
	* @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaMultipleMsg
	* @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaORMultipleSecondMsg
	*/
	bool verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) override;
};
