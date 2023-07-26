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
#include "../mid_layer/ElGamalEnc.hpp"

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaElGamalCTKnowldge verifier and simulator.<p>
* In SigmaElGamalCTKnowldge protocol, the common input contains an ElGamal commitment message.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalCmtKnowledgeCommonInput : public SigmaCommonInput {

private:
	ElGamalPublicKey publicKey;

public:
	/**
	* Sets the given ElGamal public key.
	* @param publicKey used to commit.
	*/
	SigmaElGamalCmtKnowledgeCommonInput(ElGamalPublicKey publicKey) : publicKey(publicKey) {}

	/**
	* Returns the public key used for commit.
	* @return the public key used for commit.
	*/
	ElGamalPublicKey getPublicKey() { return publicKey; }

	string toString() override { return publicKey.generateSendableData()->toString(); }
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaElGamalCTKnowldgeProver.<p>
* In SigmaElGamalCTKnowldge protocol, the prover gets an ElGamal commitment message and a value w in Zq such that h = g^w.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalCmtKnowledgeProverInput : public SigmaProverInput {

private:
	shared_ptr<SigmaElGamalCmtKnowledgeCommonInput> input;
	biginteger w;

public:
	/**
	* Sets the public keyused to ensrypt and the private key.
	* @param publicKey
	* @param w
	*/
	SigmaElGamalCmtKnowledgeProverInput(ElGamalPublicKey publicKey, const biginteger & w) {
		input = make_shared<SigmaElGamalCmtKnowledgeCommonInput>(publicKey);
		this->w = w;
	}

	/**
	* Returns the private key.
	*/
	biginteger getW() { return w; }

	shared_ptr<SigmaCommonInput> getCommonInput() override { return input; }
};

/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that it knows the value committed to in the commitment (h,c1, c2).<p>
*
* The pseudo code of this protocol can be found in Protocol 1.6 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalCmtKnowledgeSimulator : public SigmaSimulator {

	/*
	This class uses an instance of SigmaDlogSimulator with:
	Common parameters (G,q,g) and t
	Common input: h (1st element of commitment)
	*/

private:
	SigmaDlogSimulator dlogSim; //underlying SigmaDlogSimulator to use.

	/**
	* Converts the given input to an input object of the underlying Sigma simulator.
	* @param input MUST be an instance of SigmaElGamalCTKnowledgeCommonInput.
	* @return the converted input.
	* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCTKnowledgeCommonInput.
	*/
	shared_ptr<SigmaDlogCommonInput> convertInput(SigmaCommonInput* input);

public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaElGamalCmtKnowledgeSimulator(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg()) : dlogSim(dlog, t, prg) {}

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return dlogSim.getSoundnessParam(); }

	/**
	* Computes the simulator computation.
	* @param input MUST be an instance of SigmaElGamalCTKnowledgeCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCTKnowledgeCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input, const vector<byte> & challenge)  override;

	/**
	* Computes the simulator computation.
	* @param input MUST be an instance of SigmaElGamalCTKnowledgeCommonInput.
	* @return the output of the computation - (a, e, z).
	* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCTKnowledgeCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input) override;

};

/**
* Concrete implementation of Sigma Protocol prover computation.<p>
*
* This protocol is used for a committer to prove that it knows the value committed to in the commitment (h,c1, c2).<p>
*
* The pseudo code of this protocol can be found in Protocol 1.6 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalCmtKnowledgeProverComputation : public SigmaProverComputation, DlogBasedSigma {

	/*
	This class uses an instance of SigmaDlogProver with:
	Common parameters (G,q,g) and t
	Common input: h (1st element of commitment)
	P's private input: a value w in Zq such that h = g^w (given w can decrypt and so this proves knowledge of committed value).
	*/

private:
	SigmaDlogProverComputation sigmaDlog;	//underlying SigmaDlogProver to use.
	shared_ptr<PrgFromOpenSSLAES> prg;
	shared_ptr<DlogGroup> dlog;				//We need the DlogGroup instance in order to calculate the input for the underlying SigmaDlogProver
	int t;
	
	/**
	* Converts the input for this Sigma protocol to the underlying protocol.
	* @param input MUST be an instance of SigmaElGamalCTKnowledgeProverInput.
	* @throws IllegalArgumentException if input is not an instance of SigmaElGamalCTKnowledgeProverInput.
	*/
	shared_ptr<SigmaDlogProverInput> convertInput(SigmaProverInput* in);

public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaElGamalCmtKnowledgeProverComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg());

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override{ return sigmaDlog.getSoundnessParam();	}

	/**
	* Computes the first message of the protocol.
	* @param input MUST be an instance of SigmaElGamalCTKnowledgeProverInput.
	* @return the computed message
	* @throws IllegalArgumentException if input is not an instance of SigmaElGamalCTKnowledgeProverInput.
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
		return make_shared<SigmaElGamalCmtKnowledgeSimulator>(dlog, t, prg);
	}

};

/**
* Concrete implementation of Sigma Protocol verifier computation. <p>
*
* This protocol is used for a committer to prove that it knows the value committed to in the commitment (h,c1, c2).<p>
*
* The pseudo code of this protocol can be found in Protocol 1.6 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalCmtKnowledgeVerifierComputation : public SigmaVerifierComputation, DlogBasedSigma {

	/*
	This class uses an instance of SigmaDlogVerifier with:
	Common parameters (G,q,g) and t
	Common input: h (1st element of commitment)
	*/

private:
	SigmaDlogVerifierComputation sigmaDlog;//underlying SigmaDlogVerifier to use.

	/**
	* Convert the input for this Sigma protocol to the underlying protocol.
	* @param input MUST be an instance of SigmaElGamalCTKnowledgeCommonInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaElGamalCTKnowledgeCommonInput.
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
	SigmaElGamalCmtKnowledgeVerifierComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & prg = get_seeded_prg()) : sigmaDlog(dlog, t, prg) {}

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override {
		//Delegates to the underlying Sigma Dlog verifier.
		return sigmaDlog.getSoundnessParam();
	}

	/**
	* Samples the challenge e <- {0,1}^t.
	*/
	void sampleChallenge() override {
		//Delegates to the underlying Sigma Dlog verifier.
		sigmaDlog.sampleChallenge();
	}

	/**
	* Sets the given challenge.
	* @param challenge
	*/
	void setChallenge(const vector<byte> & challenge) override {
		//Delegates to the underlying Sigma Dlog verifier.
		sigmaDlog.setChallenge(challenge);
	}

	/**
	* Returns the sampled challenge.
	* @return the challenge.
	*/
	vector<byte> getChallenge() override {
		//Delegates to the underlying Sigma Dlog verifier.
		return sigmaDlog.getChallenge();
	}

	/**
	* Verifies the proof.
	* @param z second message from prover
	* @param input MUST be an instance of SigmaElGamalCTKnowledgeCommonInput.
	* @return true if the proof has been verified; false, otherwise.
	* @throws IllegalArgumentException if input is not an instance of SigmaElGamalCTKnowledgeCommonInput.
	* @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaGroupElementMsg
	* @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
	*/
	bool verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) override {
		return sigmaDlog.verify(convertInput(input).get(), a, z);
	}

};

