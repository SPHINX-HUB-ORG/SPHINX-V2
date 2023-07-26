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


#include "../../include/interactive_mid_protocols/SigmaProtocolPedersenCmtKnowledge.hpp"

string SigmaPedersenCmtKnowledgeCommonInput::toString() {
	string output = h->generateSendableData()->toString();
	output += ":";
	output += commitment->generateSendableData()->toString();
	return output;

}

void SigmaPedersenCmtKnowledgeMsg::initFromString(const string & s) {
	auto str_vec = explode(s, ':');
	assert(str_vec.size() == 2);
	u = biginteger(str_vec[0]);
	v = biginteger(str_vec[1]);
}

/**
* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
* @param dlog
* @param t Soundness parameter in BITS.
* @param random
* @throws IllegalArgumentException if soundness parameter is invalid.
*/
SigmaPedersenCmtKnowledgeSimulator::SigmaPedersenCmtKnowledgeSimulator(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {

	//Sets the parameters.
	this->dlog = dlog;
	this->t = t;

	//Check the soundness validity.
	if (!checkSoundnessParam()) {
		throw invalid_argument("soundness parameter t does not satisfy 2^t<q");
	}

	this->random = random;
}

bool SigmaPedersenCmtKnowledgeSimulator::checkSoundnessParam() {
	//If soundness parameter does not satisfy 2^t<q, return false.
	biginteger soundness = mp::pow(biginteger(2), t);
	biginteger q = dlog->getOrder();
	return (soundness < q);
}

shared_ptr<SigmaSimulatorOutput> SigmaPedersenCmtKnowledgeSimulator::simulate(SigmaCommonInput* input, const vector<byte> & challenge) {
	//  SAMPLE random values u, v in Zq  
	//	COMPUTE a = h^u*g^v*c^(-e) (where -e here means -e mod q)
	//	OUTPUT (a,e,(u,v))
	//

	//check the challenge validity.
	if (!checkChallengeLength(challenge.size())) {
		throw CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
	}

	SigmaPedersenCmtKnowledgeCommonInput* params = dynamic_cast<SigmaPedersenCmtKnowledgeCommonInput*>(input);
	if (params == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaPedersenCTKnowledgeCommonInput");
	}
	
	//SAMPLE a random u, v <- Zq
	biginteger qMinusOne = dlog->getOrder() - 1;
	biginteger u = getRandomInRange(0, qMinusOne, random.get());
	biginteger v = getRandomInRange(0, qMinusOne, random.get());

	//COMPUTE a = h^u*g^v*c^(-e) (where -e here means -e mod q)
	//Compute h^u
	auto hToU = dlog->exponentiate(params->getH().get(), u);
	//Compute g^v
	auto gToV = dlog->exponentiate(dlog->getGenerator().get(), v);
	//Compute c^(-e) 
	biginteger e = decodeBigInteger(challenge.data(), challenge.size());
	biginteger minusE = dlog->getOrder() - e;
	auto c = params->getCommitment();
	auto cToE = dlog->exponentiate(c.get(), minusE);
	auto a = dlog->multiplyGroupElements(hToU.get(), gToV.get());
	a = dlog->multiplyGroupElements(a.get(), cToE.get());

	//OUTPUT (a,e,z).
	return make_shared<SigmaSimulatorOutput>(make_shared<SigmaGroupElementMsg>(a->generateSendableData()), challenge, make_shared<SigmaPedersenCmtKnowledgeMsg>(u, v));
}

shared_ptr<SigmaSimulatorOutput> SigmaPedersenCmtKnowledgeSimulator::simulate(SigmaCommonInput* input) {
	//Create a new byte array of size t/8, to get the required byte size.
	vector<byte> e(t / 8);
	random->getPRGBytes(e, 0, t / 8);

	//Call the other simulate function with the given input and the sampled e.
	return simulate(input, e);
}

/**
* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
* @param dlog
* @param t Soundness parameter in BITS.
* @param random
* @throws IllegalArgumentException if soundness parameter is invalid.
*/
SigmaPedersenCmtKnowledgeProverComputation::SigmaPedersenCmtKnowledgeProverComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {

	//Sets the parameters.
	this->dlog = dlog;
	this->t = t;

	//Check the soundness validity.
	if (!checkSoundnessParam()) {
		throw invalid_argument("soundness parameter t does not satisfy 2^t<q");
	}

	this->random = random;
}

/**
* Computes the first message of the protocol.<p>
* "SAMPLE random values alpha, beta <- Zq<p>
*  COMPUTE a = (h^alpha)*(g^beta)".
* @return the computed message
*/
shared_ptr<SigmaProtocolMsg> SigmaPedersenCmtKnowledgeProverComputation::computeFirstMsg(const shared_ptr<SigmaProverInput> & input) {
	
	this->input = dynamic_pointer_cast<SigmaPedersenCmtKnowledgeProverInput>(input);
	if (this->input == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaPedersenCTKnowledgeProverInput");
	}
	
	//Sample random alpha, beta.
	biginteger qMinusOne = dlog->getOrder() - 1;
	alpha = getRandomInRange(0, qMinusOne, random.get());
	beta = getRandomInRange(0, qMinusOne, random.get());

	//Compute h^alpha
	auto hToAlpha = dlog->exponentiate(dynamic_pointer_cast<SigmaPedersenCmtKnowledgeCommonInput>(this->input->getCommonInput())->getH().get(), alpha);
	//Compute g^beta
	auto gToBeta = dlog->exponentiate(dlog->getGenerator().get(), beta);
	//Compute a = (h^alpha)*(g^beta)
	auto a = dlog->multiplyGroupElements(hToAlpha.get(), gToBeta.get());

	//Create and return SigmaGroupElementMsg with a.
	return make_shared<SigmaGroupElementMsg>(a->generateSendableData());
}
/**
* Checks the validity of the given soundness parameter.
* @return true if the soundness parameter is valid; false, otherwise.
*/
bool SigmaPedersenCmtKnowledgeProverComputation::checkSoundnessParam() {
	//If soundness parameter does not satisfy 2^t<q, return false.
	biginteger soundness = mp::pow(biginteger(2), t);
	biginteger q = dlog->getOrder();
	return (soundness < q);
}

/**
* Computes the second message of the protocol.<p>
* "COMPUTE u = alpha + ex mod q and v = beta + er mod q".
* @param challenge
* @return the computed message.
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
*/
shared_ptr<SigmaProtocolMsg> SigmaPedersenCmtKnowledgeProverComputation::computeSecondMsg(const vector<byte> & challenge) {

	//check the challenge validity.
	if (!checkChallengeLength(challenge.size())) {
		throw CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
	}

	//Compute u = alpha + ex mod q
	biginteger q = dlog->getOrder();
	biginteger e = decodeBigInteger(challenge.data(), challenge.size());
	biginteger ex = (e * input->getX()) % q;
	biginteger u = (alpha + ex) % q;

	//Compute v = beta + er mod q
	biginteger er = (e * input->getR()) % q;
	biginteger v = (beta + er) % q;

	//Delete the random values alpha, beta
	alpha = 0;
	beta = 0;

	//Create and return SigmaPedersenCTKnowledgeMsg with z.
	return make_shared<SigmaPedersenCmtKnowledgeMsg>(u, v);

}


/**
* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
* @param dlog
* @param t Soundness parameter in BITS.
* @param random
* @throws InvalidDlogGroupException if the given DlogGroup is not valid.
* @throws IllegalArgumentException if soundness parameter is invalid.
*/
SigmaPedersenCmtKnowledgeVerifierComputation::SigmaPedersenCmtKnowledgeVerifierComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {

	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("invalid dlog");

	//Sets the parameters.
	this->dlog = dlog;
	this->t = t;

	//Check the soundness validity.
	if (!checkSoundnessParam()) {
		throw invalid_argument("soundness parameter t does not satisfy 2^t<q");
	}

	this->random = random;
}

/**
* Checks the validity of the given soundness parameter.
* @return true if the soundness parameter is valid; false, otherwise.
*/
bool SigmaPedersenCmtKnowledgeVerifierComputation::checkSoundnessParam() {
	//If soundness parameter does not satisfy 2^t<q, return false.
	biginteger soundness = mp::pow(biginteger(2), t);
	biginteger q = dlog->getOrder();
	return (soundness < q);
}

/**
* Samples the challenge for this protocol.<p>
* 	"SAMPLE a random challenge e<-{0,1}^t".
*/
void SigmaPedersenCmtKnowledgeVerifierComputation::sampleChallenge() {
	//make space for t/8 bytes and fill it with random values.
	e.resize(t / 8);
	random->getPRGBytes(e, 0, t / 8);
}

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
bool SigmaPedersenCmtKnowledgeVerifierComputation::verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) {	
	auto params = dynamic_cast<SigmaPedersenCmtKnowledgeCommonInput*>(input);
	if (params == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaPedersenCTKnowledgeCommonInput");
	}

	//The first check "ACC IFF VALID_PARAMS(G,q,g)=TRUE" is done in the constructor.

	bool verified = true;

	//If one of the messages is illegal, throw exception.
	auto firstMsg = dynamic_cast<SigmaGroupElementMsg*>(a);
	auto secondMsg = dynamic_cast<SigmaPedersenCmtKnowledgeMsg*>(z);
	if (firstMsg == NULL) {
		throw invalid_argument("first message must be an instance of SigmaGroupElementMsg");
	}
	if (secondMsg == NULL) {
		throw invalid_argument("second message must be an instance of SigmaPedersenCTKnowledgeMsg");
	}

	//Get the h from the input and verify that it is in the Dlog Group.
	auto h = params->getH();

	//If h is not member in the group, set verified to false.
	verified = verified && dlog->isMember(h.get());

	//check that h^u*g^v=a*c^e:

	//Compute h^u
	auto hToU = dlog->exponentiate(h.get(), secondMsg->getU());
	//Compute g^v
	auto gToV = dlog->exponentiate(dlog->getGenerator().get(), secondMsg->getV());
	//compute h^u*g^v (left size of the verify equation)
	auto left = dlog->multiplyGroupElements(hToU.get(), gToV.get());

	//Convert e to BigInteger.
	biginteger eBI = decodeBigInteger(e.data(), e.size()); 	// convert e to biginteger.
	//Compute c^e.
	auto c = params->getCommitment();
	auto cToe = dlog->exponentiate(c.get(), eBI);
	//Calculate a*c^e (right side of the verify equation
	auto aElement = dlog->reconstructElement(true, firstMsg->getElement().get());
	auto right = dlog->multiplyGroupElements(aElement.get(), cToe.get());

	//If left and right sides of the equation are not equal, set verified to false.
	verified = verified && *left == *right;

	e.clear(); //Delete the random value e.

	//Return true if all checks returned true; false, otherwise.
	return verified;
}
