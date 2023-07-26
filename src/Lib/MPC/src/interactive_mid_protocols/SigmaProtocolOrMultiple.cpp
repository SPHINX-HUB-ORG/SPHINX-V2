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


#include "../../include/interactive_mid_protocols/SigmaProtocolOrMultiple.hpp"

string SigmaOrMultipleCommonInput::toString() {
	string output = "";
	for (int i = 0; i < (int) sigmaInputs.size(); i++) {
		output += sigmaInputs[i]->toString();
		output += ":";
	}
	output += k;
	output += ":";
	return output;

}

shared_ptr<SigmaCommonInput> SigmaOrMultipleProverInput::getCommonInput() {
	/*
	*
	* There are two options to implement this function:
	* 1. Create a new instance of SigmaANDCommonInput every time the function is called.
	* 2. Create the object in the construction time and return it every time this function is called.
	* This class holds an array of SigmaProverInput, where each instance in the array holds
	* an instance of SigmaCommonParams inside it.
	* In the second option above, this class will have in addition an array of SigmaCommonInput.
	* This way, the SigmaCommonInput instances will appear twice -
	* once in the array and once in the corresponding SigmaProverInput.
	* This is an undesired duplication and redundancy, So we decided to implement using the
	* first way, although this is less efficient.
	* In case the efficiency is important, a user can derive this class and override this implementation.
	*/
	int len = proverInputs.size() + simulatorInputs.size();
	vector<shared_ptr<SigmaCommonInput>> paramsArr;
	for (int i = 0; i<len; i++) {
		if (proverInputs.count(i) == 1) { //There is such keyin the map
			paramsArr.push_back(proverInputs[i]->getCommonInput());
		} else {
			paramsArr.push_back(simulatorInputs[i]);
		}
	}
	return make_shared<SigmaOrMultipleCommonInput>(paramsArr, proverInputs.size());
}

string SigmaOrMultipleSecondMsg::toString() {
	string output = to_string(polynomial.size());
	output += ":";
	for (size_t i = 0; i < polynomial.size(); i++) {
		const byte * poly = polynomial[i].data();
		output += string(reinterpret_cast<char const*>(poly), polynomial[i].size());
		output += ":";
	}
	output += to_string(z.size());
	output += ":";
	for (size_t i = 0; i < z.size(); i++) {
		output += z[i]->toString();
		output += ":";
	}
	output += to_string(challenges.size());
	output += ":";
	for (size_t i = 0; i < challenges.size(); i++) {
		const byte * challenge = challenges[i].data();
		output += string(reinterpret_cast<char const*>(challenge), challenges[i].size());
		output += ":";
	}

	return output;
}

void SigmaOrMultipleSecondMsg::initFromString(const string & row) {
	auto str_vec = explode(row, ':');

	int polynomialSize = stoi(str_vec[0]);
	for (int i = 0; i < polynomialSize; i++) {
		vector<byte> poly;
		poly.assign(str_vec[1 + i].begin(), str_vec[1 + i].end());
		polynomial.push_back(poly);
	}
	int zSize = stoi(str_vec[polynomialSize]);
	for (int i = 0; i < zSize; i++) {
		z[i]->initFromString(str_vec[polynomialSize + 1 + i]);
	}
	int challengesSize = stoi(str_vec[polynomialSize + zSize]);
	for (int i = 0; i < challengesSize; i++) {
		vector<byte> challenge;
		challenge.assign(str_vec[polynomialSize + zSize + 1 + i].begin(), str_vec[polynomialSize + zSize + 1 + i].end());
		challenges.push_back(challenge);
	}
}

/*********************************/
/*   SigmaORMultipleSimulator    */
/*********************************/

/**
* Constructor that gets the underlying simulators.
* @param simulators array of SigmaSimulator that contains underlying simulators.
* @param t soundness parameter. t MUST be equal to both t values of the underlying simulators object.
* @param random
*/
SigmaOrMultipleSimulator::SigmaOrMultipleSimulator(const vector<shared_ptr<SigmaSimulator>> & simulators, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {
	len = simulators.size();

	//If the given t is different from one of the underlying object's t values, throw exception.
	for (int i = 0; i < len; i++) {
		if (t != simulators[i]->getSoundnessParam()) {
			throw invalid_argument("the given t does not equal to one of the t values in the underlying simulators objects.");
		}
	}
	this->simulators = simulators;
	this->t = t;
	this->random = random;

	//Initialize the field GF2E with a random irreducible polynomial with degree t.
	initField(t, random->getRandom32());
	
}

void initField(int t, int s) {
	//Create an irreducible polynomial.
	NTL::GF2X irredPoly = NTL::BuildSparseIrred_GF2X(t);

	//init the field with the newly generated polynomial.
	NTL::GF2E::init(irredPoly);
	//Sets the seed to the random calculations.
	NTL::ZZ seed;
	seed = s;
	SetSeed(seed);
}

/**
* Computes the simulator computation with the given challenge.
* @param input MUST be an instance of SigmaORMultipleCommonInput.
* @param challenge
* @return the output of the computation - (a, e, z).
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
* @throws IllegalArgumentException if the given input is not an instance of SigmaORMultipleCommonInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaOrMultipleSimulator::simulate(SigmaCommonInput* input, const vector<byte> & challenge)  {
	if (!checkChallengeLength(challenge.size())) {
		throw CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
	}

	auto orInput = dynamic_cast<SigmaOrMultipleCommonInput*>(input);
	if (orInput == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaOrMultipleCommonInput");
	}
	
	int nMinusK = len - orInput->getK();

	vector<shared_ptr<NTL::GF2E>> elements;
	//For every j = 1 to n-k, sample a random element ej <- GF[2^t]. We sample the random elements in one native call.
	vector<vector<byte>> challenges = sampleRandomFieldElements(nMinusK, t, elements, random.get());

	//Create two arrays of indexes. These arrays used for calculate the interpolated polynomial.
	vector<int> indexesNotInI;
	vector<int> indexesInI;
	//Fill the arrays with the indexes.
	for (int i = 0; i < len; i++) {
		if (i<len - orInput->getK()) {
			indexesNotInI.push_back(i + 1); //i+1 because Q(0) = e.
		} else {
			indexesInI.push_back(i + 1);
		}
	}
	//Interpolate the points (0,e) and {(j,ej)} for every j=1 to n-k to obtain a degree n-k polynomial Q.
	auto polynomial = interpolate(challenge, elements, indexesNotInI);
	
	//Get the rest of the challenges by computing for every i = n-k+1 to n, ei = Q(i).
	auto ejs = getRestChallenges(polynomial, indexesInI);
	challenges.insert(challenges.end(), ejs.begin(), ejs.end());

	vector<shared_ptr<SigmaProtocolMsg>> aOutputs;
	vector<vector<byte>> eOutputs;
	vector<shared_ptr<SigmaProtocolMsg>> zOutputs;
	shared_ptr<SigmaSimulatorOutput> output;
	//Run the simulator on each statement,challenge pair (xi,ei) for all i=1,...,n to obtain (ai,ei,zi).
	for (int i = 0; i < len; i++) {
		output = simulators[i]->simulate(orInput->getInputs()[i].get(), challenges[i]);
		aOutputs.push_back(output->getA());
		eOutputs.push_back(output->getE());
		zOutputs.push_back(output->getZ());
	}

	//prepare the input for the sigmaSimulatorOutput.
	auto polynomBytes = getPolynomialBytes(polynomial);
	auto first = make_shared<SigmaMultipleMsg>(aOutputs);
	auto second = make_shared<SigmaOrMultipleSecondMsg>(polynomBytes, zOutputs, challenges);

	return make_shared<SigmaSimulatorOutput>(first, challenge, second);
}

vector<vector<byte>> getPolynomialBytes(NTL::GF2EX & polynomial) {
	long degree = deg(polynomial);

	vector<vector<byte>> polynomBytes;

	//convert each coefficient polynomial to byte array and put it in the output array.
	for (int i = 0; i <= degree; i++) {
		//get the coefficient polynomial
		NTL::GF2E coefficient = coeff(polynomial, i);

		//get the bytes of the coefficient.
		polynomBytes.push_back(convertElementToBytes(coefficient));
	}

	return polynomBytes;
}

vector<vector<byte>> getRestChallenges(NTL::GF2EX & polynomial, const vector<int> & indexesInI) {

	int size = indexesInI.size();
	vector<vector<byte>> challenges;

	//calculate the y coordinate (the challenge) to each one of the indexes (the indexes).
	for (int i = 0; i<size; i++) {

		//get the index polynomial
		auto element = generateIndexPolynomial(indexesInI[i]);
		//Evaluate the polyomial on the index to get the challenge element.
		NTL::GF2E result = eval(polynomial, element);

		challenges.push_back(convertElementToBytes(result));
	}

	return challenges;
}

NTL::GF2EX interpolate(const vector<byte> & challenge, vector<shared_ptr<NTL::GF2E>> & fieldElements, const vector<int> & sampledIndexes) {
	//Create vectors of polynomials to the interpolate function.
	NTL::vec_GF2E xVector; //the x coordinates
	NTL::vec_GF2E yVector; //the y coordinates

	int size = sampledIndexes.size();

	//set the length of the arrays to the number of points + the point (0,e)
	xVector.SetLength(size + 1);
	yVector.SetLength(size + 1);

	//put the first point in the coordinates arrays.
	yVector[0] = convertBytesToGF2E(challenge);
	xVector[0] = NTL::to_GF2E(0);

	//put all the other point in the coordinates arrays.
	for (int i = 0; i<size; i++) {

		//put the challenge polynomial in y array
		yVector[i + 1] = *fieldElements[i];

		//put the index polynomial in x array
		xVector[i + 1] = generateIndexPolynomial(sampledIndexes[i]);
	}

	//create a GF2EX polynomial 
	NTL::GF2EX polynomial;

	//interpolate the points, put the result polynomial in the created polynomial and return it.
	interpolate(polynomial, xVector, yVector);

	//free the allocated memory
	return polynomial;
}

NTL::GF2E generateIndexPolynomial(int i) {

	NTL::ZZ index;
	index = i;
	unsigned char* indexBytes = new unsigned char[4];
	BytesFromZZ(indexBytes, index, 4);

	NTL::GF2X indexPoly;
	GF2XFromBytes(indexPoly, (unsigned char*)indexBytes, 4);

	delete [](indexBytes);

	return to_GF2E(indexPoly);
}

vector<vector<byte>> sampleRandomFieldElements(int numElements, int t, vector<shared_ptr<NTL::GF2E>> & elements, PrgFromOpenSSLAES* random) {
	vector<vector<byte>> challenges;

	//Samples random elements, puts their bytes in the output array and put their addresses in the pointers array.
	for (int i = 0; i<numElements; i++) {
		vector<byte> e(t / 8);
		random->getPRGBytes(e, 0, t / 8);
		//modify the challenge to be positive.
		e.data()[e.size() - 1] = e.data()[e.size() - 1] & 127;
		//sample random field element.
		auto element = new NTL::GF2E;
		*element = convertBytesToGF2E(e);
		elements.push_back(shared_ptr<NTL::GF2E>(element));
		challenges.push_back(e);
	}

	return challenges;
}

vector<byte> convertElementToBytes(NTL::GF2E & element) {
	//Get the bytes of the random element.
	NTL::GF2X fromEl = NTL::rep(element); //convert the GF2E element to GF2X element.
	int numBytes = NTL::NumBytes(fromEl); //get the number of element bytes.
	
	vector<byte> challenge(numBytes);
	//the function rep returns the representation of GF2E as the related GF2X, it returns as read only.
	BytesFromGF2X(challenge.data(), fromEl, numBytes);
	return challenge;
}

NTL::GF2E convertBytesToGF2E(const vector<byte> & elementByts) {
	
	//translate the bytes into a GF2X element.
	NTL::GF2X e;
	NTL::GF2XFromBytes(e, elementByts.data(), elementByts.size());

	//convert the GF2X to GF2E
	return to_GF2E(e);
}

/**
* Computes the simulator computation with a randomly chosen challenge.
* @param input MUST be an instance of SigmaORMultipleCommonInput.
* @return the output of the computation - (a, e, z).
* @throws IllegalArgumentException if the given input is not an instance of SigmaORMultipleCommonInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaOrMultipleSimulator::simulate(SigmaCommonInput* input)  {
	//Create a new byte array of size t/8, to get the required byte size and fill the byte array with random values.
	vector<byte> e(t / 8);
	random->getPRGBytes(e, 0, t / 8);
	//modify the challenge to be positive.
	e.data()[e.size() - 1] = e.data()[e.size() - 1] & 127;

	//Call the other simulate function with the given input and the sampled e.
	return simulate(input, e);
}

/**
* Checks if the given challenge length is equal to the soundness parameter.
* @return true if the challenge length is t; false, otherwise.
*/
bool SigmaOrMultipleSimulator::checkChallengeLength(int size) {
	//If the challenge's length is equal to t, return true. else, return false.
	return (size == (t / 8) ? true : false);
}

/*********************************/
/*   SigmaORMultipleProverComputation     */
/*********************************/

/**
* Constructor that gets the underlying provers.
* @param provers array of SigmaProverComputation, where each object represent a statement
* 		  and the prover wants to prove to the verify that the OR of all statements are true.
* @param t soundness parameter. t MUST be equal to all t values of the underlying provers object.
* @throws IllegalArgumentException if the given t is not equal to all t values of the underlying provers object.
*/
SigmaOrMultipleProverComputation::SigmaOrMultipleProverComputation(const map<int, shared_ptr<SigmaProverComputation>> & provers, const map<int, shared_ptr<SigmaSimulator>> & simulators, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {
	//If the given t is different from one of the underlying object's t values, throw exception.

	for (auto prover : provers) {
		if (t != prover.second->getSoundnessParam()) {
			throw invalid_argument("the given t does not equal to one of the t values in the underlying provers objects.");
		}
	}
	for (auto simulator : simulators) {
		if (t != simulator.second->getSoundnessParam()) {
			throw invalid_argument("the given t does not equal to one of the t values in the underlying simulators objects.");
		}
	}
	this->provers = provers;
	k = provers.size();
	this->simulators = simulators;
	len = k + simulators.size();
	this->t = t;
	this->random = random;
	//Initialize the field GF2E with a random irreducible polynomial with degree t.
	initField(t, random->getRandom32());
}

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
shared_ptr<SigmaProtocolMsg> SigmaOrMultipleProverComputation::computeFirstMsg(const shared_ptr<SigmaProverInput> & input) {
	//Check the given input.
	auto in = dynamic_pointer_cast<SigmaOrMultipleProverInput>(input);
	if (in == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaOrMultipleProverInput");
	}
	
	int inputLen = in->getProversInput().size() + in->getSimulatorsInput().size();
	challenges.resize(len);
	
	// If number of inputs is not equal to number of provers, throw exception.
	if (inputLen != len) {
		throw invalid_argument("number of inputs is different from number of underlying provers");
	}
	auto proversInput = in->getProversInput();
	auto simulatorsInput = in->getSimulatorsInput();
	
	//Sample random values for this protocol.
	//For every j not in I, sample a random element ej <- GF[2^t]. We sample the random elements in one native call.
	auto sChallenges = sampleRandomFieldElements(len - k, t, elements, random.get());
	
	//Create an array to hold all messages.
	vector<shared_ptr<SigmaProtocolMsg>> firstMessages;
	int simulatorsIndex = 0;

	//Compute all first messages and add them to the array list.
	for (int i = 0; i < len; i++) {
		//If i in I, call the underlying computeFirstMsg.
		if (provers.count(i) == 1){
			firstMessages.push_back(provers[i]->computeFirstMsg(proversInput[i]));
			
		//If i not in I, run the simulator for xi.
		} else {
			challenges.at(i) = sChallenges[simulatorsIndex++];

			auto output = simulators[i]->simulate(simulatorsInput[i].get(), challenges[i]);
			firstMessages.push_back(output->getA());
			simulatorsOutput[i] = output;
		}
	}
	//Create a SigmaMultipleMsg with the messages array.
	return make_shared<SigmaMultipleMsg>(firstMessages);

}

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
shared_ptr<SigmaProtocolMsg> SigmaOrMultipleProverComputation::computeSecondMsg(const vector<byte> & challenge) {
	//Create two arrays of indexes. These arrays used to calculate the interpolated polynomial.
	vector<int> indexesNotInI;
	vector<int> indexesInI;
	//Fill the arrays with the indexes.
	for (int i = 0; i < len; i++) {
		if (provers.count(i) == 1) { //prover i has a witness
			indexesInI.push_back(i + 1); //i+1 because Q(0) = e.
		} else {
			indexesNotInI.push_back(i + 1);
		}
	}
	//Interpolate the points (0,e) and {(j,ej)} for every j NOT in I to obtain a degree n-k polynomial Q.
	auto polynomial = interpolate(challenge, elements, indexesNotInI);

	//Get the rest of the challenges by computing for every i in I, ei = Q(i).
	auto pChallenges = getRestChallenges(polynomial, indexesInI);

	//Create an array to hold all messages.
	vector<shared_ptr<SigmaProtocolMsg>> secondMessages;
	int proversIndex = 0;
	//Compute all second messages and add them to the array list.
	for (int i = 0; i < len; i++) {
		//If i in I, call the underlying computeSecondMsg.
		if (provers.count(i) == 1){
			challenges.at(i) = pChallenges[proversIndex++];
			secondMessages.push_back(provers[i]->computeSecondMsg(challenges[i]));
		//If i not in I, get z from the simulator output for xi.
		} else {
			secondMessages.push_back(simulatorsOutput[i]->getZ());
		}
	}

	//Get the byte array that represent the polynomial
	auto polynomBytes = getPolynomialBytes(polynomial);

	//Create a SigmaORMultipleSecondMsg with the messages array.
	return make_shared<SigmaOrMultipleSecondMsg>(polynomBytes, secondMessages, challenges);

}

/**
* Returns the simulator that matches this sigma protocol prover.
* @return SigmaORMultipleSimulator
*/
shared_ptr<SigmaSimulator> SigmaOrMultipleProverComputation::getSimulator() {
	vector<shared_ptr<SigmaSimulator>> sim;
	for (int i = 0; i < len; i++) {
		if (provers.count(i) == 1) {
			sim.push_back(provers[i]->getSimulator());
		}
		else {
			sim.push_back(simulators[i]);
		}

	}
	return make_shared<SigmaOrMultipleSimulator>(sim, t, random);
}

/**
* Constructor that gets the underlying verifiers.
* @param verifiers array of SigmaVerifierComputation, where each object represent a statement
* 		  and the prover wants to convince a verifier that at least k out of n statements is true.
* @param t soundness parameter. t MUST be equal to all t values of the underlying verifiers object.
* @param random source of randomness
* @throws IllegalArgumentException if the given t is not equal to all t values of the underlying verifiers object.
*/
SigmaOrMultipleVerifierComputation::SigmaOrMultipleVerifierComputation(const vector<shared_ptr<SigmaVerifierComputation>> & verifiers, int t, const shared_ptr<PrgFromOpenSSLAES> & random) {
	//If the given t is different from one of the underlying object's t values, throw exception.
	for (size_t i = 0; i < verifiers.size(); i++) {
		if (t != verifiers[i]->getSoundnessParam()) {
			throw invalid_argument("the given t does not equal to one of the t values in the underlying verifiers objects.");
		}
	}
	this->verifiers = verifiers;
	len = verifiers.size();
	this->t = t;
	this->random = random;

	//Initialize the field GF2E with a random irreducible polynomial with degree t.
	initField(t, random->getRandom32());
}

/**
* Samples the challenge of the protocol.<p>
* 	"SAMPLE a single random challenge  e <- GF[2^t]".
*/
void SigmaOrMultipleVerifierComputation::sampleChallenge() {
	//make space for t/8 bytes and fill it with random values.
	challengeBytes.resize(t / 8);
	random->getPRGBytes(challengeBytes, 0, t / 8);
	//modify the challenge to be positive.
	challengeBytes.data()[challengeBytes.size() - 1] = challengeBytes.data()[challengeBytes.size() - 1] & 127;
	challengeElement = convertBytesToGF2E(challengeBytes);
}

/**
* Sets the given challenge.
* @param challenge
*/
void SigmaOrMultipleVerifierComputation::setChallenge(const vector<byte> & challenge) {
	challengeBytes = challenge;

	challengeElement = convertBytesToGF2E(challenge);
}

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
bool SigmaOrMultipleVerifierComputation::verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) {
	//Checks the given input.
	auto in = dynamic_cast<SigmaOrMultipleCommonInput*>(input);
	if (in == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaOrMultipleCommonInput");
	}
	
	int inputLen = in->getInputs().size();
	// If number of inputs is not equal to number of verifiers, throw exception.
	if (inputLen != len) {
		throw invalid_argument("number of inputs is different from number of underlying verifiers.");
	}

	this->k = in->getK();
	auto verifiersInput = in->getInputs();

	bool verified = true;

	//If one of the messages is illegal, throw exception.
	auto first = dynamic_cast<SigmaMultipleMsg*>(a);
	auto second = dynamic_cast<SigmaOrMultipleSecondMsg*>(z);
	if (first == NULL) {
		throw invalid_argument("first message must be an instance of SigmaMultipleMsg");
	}
	if (second == NULL) {
		throw invalid_argument("second message must be an instance of SigmaOrMultipleSecondMsg");
	}
	
	auto firstMessages = first->getMessages();
	auto secondMessages = second->getMessages();
	auto polynomial = second->getPolynomial();
	auto challenges = second->getChallenges();

	//Call native function to check the polynomial validity.
	verified = verified && checkPolynomialValidity(polynomial, k, challengeElement, challenges);

	//Compute all verifier checks.
	for (int i = 0; i < len; i++) {
		verifiers[i]->setChallenge(challenges[i]);
		verified = verified && verifiers[i]->verify(verifiersInput[i].get(), firstMessages[i].get(), secondMessages[i].get());
	}

	//Return true if all verifiers returned true; false, otherwise.
	return verified;
}

bool SigmaOrMultipleVerifierComputation::checkPolynomialValidity(const vector<vector<byte>> & polynomial, int k, const NTL::GF2E & challengeElement, const vector<vector<byte>> & challenges) {
	bool valid = true;

	//Create the polynomial out of the coefficeints array.
	NTL::GF2EX polynom = createPolynomial(polynomial);
	//Create the polynomial out of the coefficeints array.

	//check if the degree of the polynomial os n-k, while n is the number of challenges.
	int size = challenges.size();
	if (deg(polynom) != (size - k)) {
		valid = false;
	}

	//check if Q(0)=e.
	NTL::GF2E zero = NTL::to_GF2E(0);
	NTL::GF2E e = eval(polynom, zero); //Q(0)
	if (e != challengeElement) {
		valid = false;
	}

	//for each one of the challenges, check that Q(i)=ei
	for (int i = 0; i<size; i++) {
		//create the challenge element out of the byte array.
		NTL::GF2E challengeElement = convertBytesToGF2E(challenges[i]);

		//create the index element
		NTL::GF2E indexElement = generateIndexPolynomial(i + 1);

		//compute Q(i)
		NTL::GF2E result = eval(polynom, indexElement);
		//check that Q(i)=ei
		if (result != challengeElement) {
			valid = false;
		}
	}

	return valid;
}

NTL::GF2EX SigmaOrMultipleVerifierComputation::createPolynomial(const vector<vector<byte>> & polynomialBytes) {
	int deg = polynomialBytes.size();
	NTL::GF2EX polynom;

	//set each coefficient to the polynomial.
	for (int i = 0; i<deg; i++) {
		//create the polynomial of the coefficient
		//Set the coeeficient to the GF2EX polynomial
		NTL::GF2E coeffElement = convertBytesToGF2E(polynomialBytes[i]);
		SetCoeff(polynom, i, coeffElement);
	}
	return polynom;
}