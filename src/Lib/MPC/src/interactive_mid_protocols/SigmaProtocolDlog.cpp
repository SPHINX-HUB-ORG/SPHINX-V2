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


#include "../../include/interactive_mid_protocols/SigmaProtocolDlog.hpp"

bool check_soundness(int t, const shared_ptr<DlogGroup> & dlog) {
	// if soundness parameter does not satisfy 2^t<q, return false.
	biginteger soundness = mp::pow(biginteger(2), t);
	biginteger q = dlog->getOrder();
	return (soundness < q);
}

bool checkChallengeLength(const vector<byte> & challenge, int t) {
	// if the challenge's length is equal to t, return true. else, return false.
	biginteger e = abs(decodeBigInteger(challenge.data(), challenge.size()));
	return (e >= 0) && (e < mp::pow(biginteger(2), t));
}

/***************************************/
/*   SigmaDlogSimulator                */
/***************************************/

SigmaDlogSimulator::SigmaDlogSimulator(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {
	this->dlog = dlog;
	this->t = t;
	if (!checkSoundnessParam()) // check the soundness validity.
		throw invalid_argument("soundness parameter t does not satisfy 2^t<q. q=" +
			dlog->getOrder().str() + " t=" + to_string(t) + "\n");
	this->random = random;
	qMinusOne = dlog->getOrder() - 1;
}

shared_ptr<SigmaSimulatorOutput> SigmaDlogSimulator::simulate(SigmaCommonInput* input,
	const vector<byte> & challenge) {
	//check the challenge validity.
	if (!checkChallengeLength(challenge, t))
		throw CheatAttemptException(
			"the length of the given challenge is different from the soundness parameter");
	SigmaDlogCommonInput* dlogInput = (SigmaDlogCommonInput*)input;

	// SAMPLE a random z <- Zq
	biginteger z = getRandomInRange(0, qMinusOne, random.get());

	// COMPUTE a = g^z*h^(-e)  (where -e here means -e mod q)
	auto gToZ = dlog->exponentiate(dlog->getGenerator().get(), z);
	biginteger e = abs(decodeBigInteger(challenge.data(), challenge.size()));
	biginteger minusE = dlog->getOrder() - e;
	auto hToE = dlog->exponentiate(dlogInput->getH().get(), minusE);
	auto a = dlog->multiplyGroupElements(gToZ.get(), hToE.get());

	// OUTPUT (a,e,eSize,z).
	auto SigmaGEMsg = make_shared<SigmaGroupElementMsg>(a->generateSendableData());
	auto SigmaBMsg = make_shared<SigmaBIMsg>(z);
	return make_shared<SigmaSimulatorOutput>(SigmaGEMsg, challenge, SigmaBMsg);
}

shared_ptr<SigmaSimulatorOutput> SigmaDlogSimulator::simulate(SigmaCommonInput* input) {
	//Create a new byte array of size t/8, to get the required byte size and fill it with random values.
	vector<byte> e(t / 8);
	random->getPRGBytes(e, 0, t / 8);

	// call the other simulate function with the given input and the sampled e.
	return simulate(input, e);
}

bool SigmaDlogSimulator::checkSoundnessParam() {
	return check_soundness(t, dlog);
}

/***************************************/
/*   SigmaDlogProverComputation        */
/***************************************/

SigmaDlogProverComputation::SigmaDlogProverComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {
	this->dlog = dlog;
	this->t = t;
	if (!checkSoundnessParam()) // check the soundness validity.
		throw invalid_argument("soundness parameter t does not satisfy 2^t<q");
	this->random = random;
	qMinusOne = dlog->getOrder() - 1;
}

shared_ptr<SigmaProtocolMsg> SigmaDlogProverComputation::computeFirstMsg(const shared_ptr<SigmaProverInput> & input) {
	this->input = dynamic_pointer_cast<SigmaDlogProverInput>(input);
	// sample random r in Zq
	r = getRandomInRange(0, qMinusOne, random.get());
	// compute a = g^r.
	auto a = dlog->exponentiate(dlog->getGenerator().get(), r);
	auto x = a->generateSendableData();
	// create and return SigmaGroupElementMsg with a.
	return make_shared<SigmaGroupElementMsg>(x);

}

shared_ptr<SigmaProtocolMsg> SigmaDlogProverComputation::computeSecondMsg(const vector<byte> & challenge) {
	if (!checkChallengeLength(challenge, t)) // check the challenge validity.
		throw CheatAttemptException(
			"the length of the given challenge is different from the soundness parameter");

	// compute z = (r+ew) mod q
	biginteger q = dlog->getOrder();
	biginteger e = abs(decodeBigInteger(challenge.data(), challenge.size()));
	biginteger ew = (e * input->getW()) % q;
	biginteger z = (r + ew) % q;

	r = 0; // reset the random value for re-use.
	
	// create and return SigmaBIMsg with z
	return make_shared<SigmaBIMsg>(z);
}

bool SigmaDlogProverComputation::checkSoundnessParam() {
	return check_soundness(t, dlog);
}

/***************************************/
/*   SigmaDlogVerifierComputation      */
/***************************************/

SigmaDlogVerifierComputation::SigmaDlogVerifierComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("invalid dlog");

	this->dlog = dlog;
	this->t = t;
	if (!checkSoundnessParam()) // check the soundness validity.
		throw invalid_argument("soundness parameter t does not satisfy 2^t<q");
	this->random = random;
}

void SigmaDlogVerifierComputation::sampleChallenge() {
	biginteger e_number = getRandomInRange(0, mp::pow(biginteger(2), t) - 1, random.get());
	int eSize = bytesCount(e_number);
	// create a new byte array of size t/8, to get the required byte size.
	shared_ptr<byte> e = std::shared_ptr<byte>(new byte[eSize], std::default_delete<byte[]>());
	encodeBigInteger(e_number, e.get(), eSize);
	
	//Create a new byte array of size t/8, to get the required byte size.
	copy_byte_array_to_byte_vector(e.get(), eSize, this->e, 0);

}

bool SigmaDlogVerifierComputation::verify(SigmaCommonInput* input, 
	SigmaProtocolMsg* a, SigmaProtocolMsg* z) {
	auto cInput = dynamic_cast<SigmaDlogCommonInput*>(input);
	if (!cInput)
		throw invalid_argument("input to Dlog verifier should always be instance of SigmaDlogCommonInput");
	
	bool verified = true;
	auto firstMsg = dynamic_cast<SigmaGroupElementMsg*>(a);
	if (!firstMsg)
		throw invalid_argument("first message to Dlog verifier should always be instance of SigmaGroupElementMsg");
	auto exponent = dynamic_cast<SigmaBIMsg*>(z);
	if (!exponent)
		throw invalid_argument("second message to Dlog verifier should always be instance of SigmaBIMsg");
	
	auto aElement = dlog->reconstructElement(true, firstMsg->getElement().get());
	// get the h from the input and verify that it is in the Dlog Group.
	auto h = cInput->getH();
	// if h is not member in the group, set verified to false.
	verified = verified && dlog->isMember(h.get());
	
	// compute g^z (left size of the verify equation).
	auto left = dlog->exponentiate(dlog->getGenerator().get(), exponent->getMsg());
	
	// compute a*h^e (right side of the verify equation).
	biginteger eBI = abs(decodeBigInteger(e.data(), e.size())); 	// convert e to biginteger.
	
	auto hToe = dlog->exponentiate(h.get(), eBI); // calculate h^e.
	// calculate a*h^e.
	auto right = dlog->multiplyGroupElements(aElement.get(), hToe.get());
	// if left and right sides of the equation are not equal, set verified to false.
	verified = verified && (*left==*right);
	
	e.clear();  //reset the challenge for re-use.

	// return true if all checks returned true; false, otherwise.
	return verified;
}

bool SigmaDlogVerifierComputation::checkSoundnessParam() {
	return check_soundness(t, dlog);
}