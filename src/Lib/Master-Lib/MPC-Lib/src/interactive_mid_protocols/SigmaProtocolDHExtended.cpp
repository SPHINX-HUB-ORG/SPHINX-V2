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


#include "../../include/interactive_mid_protocols/SigmaProtocolDHExtended.hpp"

/**************************************************/
/**************** Input*** ************************/
/**************************************************/
string SigmaDHExtendedCommonInput::toString() {

	string output = "";
	for (int i = 0; i < (int) gArray.size(); i++) {
		output += gArray[i]->generateSendableData()->toString();
		output += ":";
	}
	for (int i = 0; i < (int) hArray.size(); i++) {
		output += gArray[i]->generateSendableData()->toString();
		output += ":";
	}
	return output;
}

/**************************************************/
/**************** Messages ************************/
/**************************************************/

string SigmaDHExtendedMsg::toString() {
	int size = aArray.size();
	string output = "";
	for (int i = 0; i < size; i++) {
		output += aArray[i]->toString() + ":";
	}
	return output;
}

void SigmaDHExtendedMsg::initFromString(const string & s) {
	auto str_vec = explode(s, ':');
	int size = str_vec.size();
	for (int i = 0; i < size; i++) {
		aArray[i]->initFromString(str_vec[i]);
	}

}

/**************************************************/
/******** Sigma DH Extended simulator *************/
/**************************************************/

/**
* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
* @param dlog
* @param t Soundness parameter in BITS.
* @param random
* @throws IllegalArgumentException if soundness parameter is invalid.
*/
SigmaDHExtendedSimulator::SigmaDHExtendedSimulator(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {
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
bool SigmaDHExtendedSimulator::checkSoundnessParam() {
	//If soundness parameter does not satisfy 2^t<q, return false.
	biginteger soundness = mp::pow(biginteger(2), t);
	biginteger q = dlog->getOrder();
	return (soundness < q);
}

shared_ptr<SigmaSimulatorOutput> SigmaDHExtendedSimulator::simulate(SigmaCommonInput* input, const vector<byte> & challenge) {
	//check the challenge validity.
	if (!checkChallengeLength(challenge.size())) {
		throw CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
	}

	SigmaDHExtendedCommonInput* dhInput = dynamic_cast<SigmaDHExtendedCommonInput*>(input);
	if (dhInput == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaDHExtendedCommonInput");
	}
	
	//Get the array from the input.
	vector<shared_ptr<GroupElement>> gArray = dhInput->getGArray();
	vector<shared_ptr<GroupElement>> hArray = dhInput->getHArray();
	size_t size = gArray.size();

	//Check that the arrays are in the same size.
	if (size != hArray.size()) {
		throw invalid_argument("the given g and h array are not in the same size");
	}

	// The simulation is: 
	//	SAMPLE a random z <- Zq
	//	For every i=1,...,m, COMPUTE ai = gi^z*hi^(-e) (where -e here means -e mod q)
	//	OUTPUT ((a1,...,am),e,z)

	//Sample a random z <- Zq
	biginteger qMinusOne = dlog->getOrder() - 1;
	biginteger z = getRandomInRange(0, qMinusOne, random.get());

	//Compute -e (where -e here means -e mod q)
	biginteger e = decodeBigInteger(challenge.data(), challenge.size());
	biginteger minusE = dlog->getOrder() - e;

	vector<shared_ptr<GroupElementSendableData>> aArray;
	shared_ptr<GroupElement> gToZ;
	shared_ptr<GroupElement> hToE;
	shared_ptr<GroupElement> a;
	//For every i=1,...,m, Compute ai = gi^z*hi^(-e) 
	for (size_t i = 0; i<size; i++) {

		gToZ = dlog->exponentiate(gArray[i].get(), z);
		hToE = dlog->exponentiate(hArray[i].get(), minusE);
		a = dlog->multiplyGroupElements(gToZ.get(), hToE.get());
		aArray.push_back(a->generateSendableData());
	}

	//Output ((a,b),e,z).
	return make_shared<SigmaSimulatorOutput>(make_shared<SigmaDHExtendedMsg>(aArray), challenge, make_shared<SigmaBIMsg>(z));

}

shared_ptr<SigmaSimulatorOutput> SigmaDHExtendedSimulator::simulate(SigmaCommonInput* input) {
	//Create a new byte array of size t/8, to get the required byte size.
	vector<byte> e(t / 8);
	random->getPRGBytes(e, 0, t / 8);
	
	//Call the other simulate function with the given input and the sampled e.
	return simulate(input, e);
}

/**************************************************/
/******** Sigma DH Extended prover ****************/
/**************************************************/

SigmaDHExtendedProverComputation::SigmaDHExtendedProverComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {

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
bool SigmaDHExtendedProverComputation::checkSoundnessParam() {
	//If soundness parameter does not satisfy 2^t<q, return false.
	biginteger soundness = mp::pow(biginteger(2), t);
	biginteger q = dlog->getOrder();
	return (soundness < q);
}

shared_ptr<SigmaProtocolMsg> SigmaDHExtendedProverComputation::computeFirstMsg(const shared_ptr<SigmaProverInput> & input) {
	this->input = dynamic_pointer_cast<SigmaDHExtendedProverInput>(input);
	if (this->input == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaDHExtendedProverInput");
	}

	shared_ptr<SigmaDHExtendedCommonInput> commonInput = dynamic_pointer_cast<SigmaDHExtendedCommonInput>(this->input->getCommonInput());
	if (commonInput->getGArray().size() != commonInput->getHArray().size()) {
		throw invalid_argument("the given g and h array are not in the same size");
	}
	
	//Sample random r in Zq
	biginteger qMinusOne = dlog->getOrder() - 1;
	r = getRandomInRange(0, qMinusOne, random.get());

	//get g array from the input.
	auto gArray = commonInput->getGArray();
	vector<shared_ptr<GroupElementSendableData>> aArray;
	int len = gArray.size();

	for (int i = 0; i<len; i++) {
		//Compute ai = gi^r.
		aArray.push_back(dlog->exponentiate(gArray[i].get(), r)->generateSendableData());
	}

	//Create and return SigmaDHExtendedMsg with aArray.
	return make_shared<SigmaDHExtendedMsg>(aArray);
}

shared_ptr<SigmaProtocolMsg> SigmaDHExtendedProverComputation::computeSecondMsg(const vector<byte> & challenge) {

	//check the challenge validity.
	if (!checkChallengeLength(challenge.size())) {
		throw CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
	}

	//Compute z = (r+ew) mod q
	biginteger q = dlog->getOrder();
	biginteger e = decodeBigInteger(challenge.data(), challenge.size());
	biginteger ew = (e * (input->getW())) % q;
	biginteger z = (r + ew) % q;

	//Reset the random value r
	r = 0;

	//Create and return SigmaBIMsg with z.
	return make_shared<SigmaBIMsg>(z);
}

/**************************************************/
/******** Sigma DH Extended Verifier* *************/
/**************************************************/

/**
* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
* @param dlog
* @param t Soundness parameter in BITS.
* @param random
* @throws InvalidDlogGroupException if the given dlog is invalid.
* @throws IllegalArgumentException if soundness parameter is invalid.
*/
SigmaDHExtendedVerifierComputation::SigmaDHExtendedVerifierComputation(const shared_ptr<DlogGroup> & dlog, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {

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
bool SigmaDHExtendedVerifierComputation::checkSoundnessParam() {
	//If soundness parameter does not satisfy 2^t<q, return false.
	biginteger soundness = mp::pow(biginteger(2), t);
	biginteger q = dlog->getOrder();
	return (soundness < q);
}

/**
* Samples the chaalenge for this protocol.<p>
* 	"SAMPLE a random challenge e<-{0,1}^t".
*/
void SigmaDHExtendedVerifierComputation::sampleChallenge() {
	//make space for t/8 bytes and fill it with random values.
	e.resize(t / 8);
	random->getPRGBytes(e, 0, t / 8);
}

bool SigmaDHExtendedVerifierComputation::verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) {
	//the first check "ACC IFF VALID_PARAMS(G,q,g)=TRUE" is already done in the constructor.

	//Check the input.
	SigmaDHExtendedCommonInput* dhInput = dynamic_cast<SigmaDHExtendedCommonInput*>(input);
	if (dhInput == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaDHExtendedCommonInput");
	}

	auto gArray = dhInput->getGArray();
	auto hArray = dhInput->getHArray();

	if (gArray.size() != hArray.size()) {
		throw invalid_argument("the given g and h array are not in the same size");
	}

	bool verified = true;

	//If one of the messages is illegal, throw exception.
	SigmaDHExtendedMsg* firstMsg = dynamic_cast<SigmaDHExtendedMsg*>(a);
	SigmaBIMsg* exponent = dynamic_cast<SigmaBIMsg*>(z);
	if (firstMsg == NULL) {
		throw invalid_argument("first message must be an instance of SigmaDHExtendedMsg");
	}
	if (exponent == NULL) {
		throw invalid_argument("second message must be an instance of SigmaBIMsg");
	}

	//Get the g array from the input. 
	int len = gArray.size();

	//Verify that each gi is in the DlogGroup.
	for (int i = 0; i<len; i++) {
		//If gi is not member in the group, set verified to false.
		verified = verified && dlog->isMember(gArray[i].get());
	}


	//Get the h and a arrays.
	auto aArray = firstMsg->getArray();
	
	biginteger eBI = decodeBigInteger(e.data(), e.size()); 	// convert e to biginteger.
	shared_ptr<GroupElement> left, right, hToe, aElement;

	for (int i = 0; i<len; i++) {
		//Verify that gi^z = ai*hi^e:

		//Compute gi^z (left size of the equation).
		left = dlog->exponentiate(gArray[i].get(), exponent->getMsg());

		//Compute ai*hi^e (right side of the verify equation).
		//Calculate hi^e.
		hToe = dlog->exponentiate(hArray[i].get(), eBI);
		//Calculate a*hi^e.
		aElement = dlog->reconstructElement(true, aArray[i].get());
		right = dlog->multiplyGroupElements(aElement.get(), hToe.get());

		//If left and right sides of the equation are not equal, set verified to false.
		verified = verified && *left == *right;
	}

	e.clear(); //Delete the random value e.

	//Return true if all checks returned true; false, otherwise.
	return verified;
}