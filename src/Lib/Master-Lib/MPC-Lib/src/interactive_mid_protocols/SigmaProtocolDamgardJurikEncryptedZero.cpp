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


#include "../../include/interactive_mid_protocols/SigmaProtocolDamgardJurikEncryptedZero.hpp"

string SigmaDJEncryptedZeroCommonInput::toString() {
	string output = publicKey.generateSendableData()->toString();
	output += ":";
	output += cipher.generateSendableData()->toString();
	return output;
}
/**
* Constructor that gets the soundness parameter, length parameter and SecureRandom.
* @param t Soundness parameter in BITS.
* @param lengthParameter length parameter in BITS.
* @param random
*/
SigmaDJEncryptedZeroSimulator::SigmaDJEncryptedZeroSimulator(int t, int lengthParameter, const shared_ptr<PrgFromOpenSSLAES> & random) {
	this->t = t;
	this->lengthParameter = lengthParameter;
	this->random = random;
}

/**
* Computes the simulator computation with the given challenge.
* @param input MUST be an instance of SigmaDJEncryptedZeroCommonInput.
* @param challenge
* @return the output of the computation - (a, e, z).
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
* @throws IllegalArgumentException if the given input is not an instance of SigmaDJEncryptedZeroCommonInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaDJEncryptedZeroSimulator::simulate(SigmaCommonInput* input, const vector<byte> & challenge) {
	//check the challenge validity.
	if (!checkChallengeLength(challenge)) {
		throw CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
	}

	auto djInput = dynamic_cast<SigmaDJEncryptedZeroCommonInput*>(input);
	if (djInput == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaDJEncryptedZeroInput");
	}
	
	biginteger n = djInput->getPublicKey().getModulus();
	//Check the soundness validity.
	if (!checkSoundnessParam(n)) {
		throw invalid_argument("t must be less than a third of the length of the public key n");
	}

	//Sample a random value z <- Z*n
	biginteger z = getRandomInRange(1, n - 1, random.get());

	//Calculate N = n^s and N' = n^(s+1)
	biginteger N = mp::pow(n, lengthParameter);
	biginteger NTag = mp::pow(n, lengthParameter + 1);
	biginteger e = decodeBigInteger(challenge.data(), challenge.size());

	//Compute a = z^N/c^e mod N'
	biginteger zToN = mp::powm(z, N, NTag);
	biginteger denominator = mp::powm(djInput->getCiphertext().getCipher(), e, NTag);
	biginteger denomInv = MathAlgorithms::modInverse(denominator, NTag);
	biginteger a = (zToN * denomInv) % NTag;

	//Output (a,e,z).
	return make_shared<SigmaSimulatorOutput>(make_shared<SigmaBIMsg>(a), challenge, make_shared<SigmaBIMsg>(z));

}

/**
* Computes the simulator computation with a randomly chosen challenge.
* @param input MUST be an instance of SigmaDJEncryptedZeroInput.
* @return the output of the computation - (a, e, z).
* @throws IllegalArgumentException if the given input is not an instance of SigmaDJEncryptedZeroInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaDJEncryptedZeroSimulator::simulate(SigmaCommonInput* input)  {
	//make space for t/8 bytes and fill it with random values.
	vector<byte> e(t / 8);
	random->getPRGBytes(e, 0, t / 8);
	//modify the challenge to be positive.
	e.data()[e.size() - 1] = e.data()[e.size() - 1] & 127;
	
	// call the other simulate function with the given input and the sampled e.
	return simulate(input, e);
}

/**
* Checks the validity of the given soundness parameter.<p>
* t must be less than a third of the length of the public key n.
* @return true if the soundness parameter is valid; false, otherwise.
*/
bool SigmaDJEncryptedZeroSimulator::checkSoundnessParam(const biginteger & modulus) {
	//If soundness parameter is not less than a third of the publicKey n, return false.
	int third = NumberOfBits(modulus) / 3;
	return (t < third);
}

/**
* Checks if the given challenge length is equal to the soundness parameter.
* @return true if the challenge length is t; false, otherwise.
*/
bool SigmaDJEncryptedZeroSimulator::checkChallengeLength(const vector<byte> & challenge) {
	//If the challenge's length is equal to t, return true. else, return false.
	return ((int) challenge.size() == (t / 8) ? true : false);
}

/**
* Constructor that gets the soundness parameter, length parameter and SecureRandom.
* @param t Soundness parameter in BITS.
* @param lengthParameter length parameter in BITS.
* @param random
*/
SigmaDJEncryptedZeroProverComputation::SigmaDJEncryptedZeroProverComputation(int t, int lengthParameter, const shared_ptr<PrgFromOpenSSLAES> & random) {
	this->t = t;
	this->lengthParameter = lengthParameter;
	this->random = random;
}

/**
* Checks the validity of the given soundness parameter.<p>
* t must be less than a third of the length of the public key n.
* @return true if the soundness parameter is valid; false, otherwise.
*/
bool SigmaDJEncryptedZeroProverComputation::checkSoundnessParam(const biginteger & modulus) {
	//If soundness parameter is not less than a third of the publicKey n, return false.
	int third = NumberOfBits(modulus) / 3;
	return (t < third);
}

/**
* Computes the first message of the protocol.<p>
* "SAMPLE random value s <- Z*n<p>
* COMPUTE a = s^N mod N'".
* @param input MUST be an instance of SigmaDJEncryptedZeroProverInput.
* @return the computed message
* @throws IllegalArgumentException if input is not an instance of SigmaDJEncryptedZeroProverInput.
*/
shared_ptr<SigmaProtocolMsg> SigmaDJEncryptedZeroProverComputation::computeFirstMsg(const shared_ptr<SigmaProverInput> & input) {
	this->input = dynamic_pointer_cast<SigmaDJEncryptedZeroProverInput>(input);
	if (this->input == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaDJEncryptedZeroProverInput");
	}

	n = dynamic_pointer_cast<SigmaDJEncryptedZeroCommonInput>(this->input->getCommonInput())->getPublicKey().getModulus();
	//Check the soundness validity.
	if (!checkSoundnessParam(n)) {
		throw invalid_argument("t must be less than a third of the length of the public key n");
	}

	//Sample s in Z*n
	s = getRandomInRange(1, n - 1, random.get());
	
	//Calculate N = n^s and N' = n^(s+1)
	biginteger N = mp::pow(n, lengthParameter);
	biginteger NTag = mp::pow(n, lengthParameter + 1);

	//Compute a = s^N mod N'.
	biginteger a = mp::powm(s, N, NTag);
	
	//Create and return SigmaBIMsg with a.
	return make_shared<SigmaBIMsg>(a);
}

/**
* Computes the second message of the protocol.<p>
* "COMPUTE z = s*r^e mod n".
* @param challenge
* @return the computed message.
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
*/
shared_ptr<SigmaProtocolMsg> SigmaDJEncryptedZeroProverComputation::computeSecondMsg(const vector<byte> & challenge) {

	//check the challenge validity.
	if (!checkChallengeLength(challenge)) {
		throw CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
	}

	//Compute z = (s*r^e) mod n
	biginteger e = decodeBigInteger(challenge.data(), challenge.size());
	biginteger rToe = mp::powm(input->getR(), e, n);
	biginteger z = (s * rToe) % n;

	//Delete the random value r
	s = 0;

	//Create and return SigmaBIMsg with z.
	return make_shared<SigmaBIMsg>(z);

}

/**
* Checks the validity of the given soundness parameter. <p>
* t must be less than a third of the length of the public key n.
* @return true if the soundness parameter is valid; false, otherwise.
*/
bool SigmaDJEncryptedZeroVerifierComputation::checkSoundnessParam(const biginteger & modulus) {
	//If soundness parameter is not less than a third of the publicKey n, throw IllegalArgumentException.
	int third = NumberOfBits(modulus) / 3;
	return (t < third);
}

/**
* Constructor that gets the soundness parameter, length parameter and SecureRandom.
* @param t Soundness parameter in BITS.
* @param lengthParameter length parameter in BITS.
* @param random
*/
SigmaDJEncryptedZeroVerifierComputation::SigmaDJEncryptedZeroVerifierComputation(int t, int lengthParameter, const shared_ptr<PrgFromOpenSSLAES> & random) {

	this->t = t;
	this->lengthParameter = lengthParameter;
	this->random = random;
}

/**
* Samples the challenge of the protocol.<p>
* 	"SAMPLE a random challenge e<-{0,1}^t".
*/
void SigmaDJEncryptedZeroVerifierComputation::sampleChallenge() {
	//make space for t/8 bytes and fill it with random values.
	e.resize(t / 8);
	random->getPRGBytes(e, 0, t / 8);
	//modify the challenge to be positive.
	e.data()[e.size()-1] = e.data()[e.size() - 1] & 127;
}

/**
* Computes the verification of the protocol.<p>
* 	"ACC IFF c,a,z are relatively prime to n AND z^N = (a*c^e) mod N'".
* @param input MUST be an instance of SigmaDJEncryptedZeroCommonInput.
* @param z second message from prover
* @return true if the proof has been verified; false, otherwise.
* @throws IllegalArgumentException if input is not an instance of SigmaDJEncryptedZeroCommonInput.
* @throws IllegalArgumentException if the one of the prover's messages are not an instance of SigmaBIMsg
*/
bool SigmaDJEncryptedZeroVerifierComputation::verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) {
	auto djInput = dynamic_cast<SigmaDJEncryptedZeroCommonInput*>(input);
	if (djInput == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaDJEncryptedZeroCommonInput");
	}

	n = djInput->getPublicKey().getModulus();
	//Check the soundness validity.
	if (!checkSoundnessParam(n)) {
		throw invalid_argument("t must be less than a third of the length of the public key n");
	}

	bool verified = true;
	auto aV = dynamic_cast<SigmaBIMsg*>(a);
	auto zV = dynamic_cast<SigmaBIMsg*>(z);
	//If one of the messages is illegal, throw exception.
	if (aV == NULL) {
		throw invalid_argument("first message must be an instance of SigmaBIMsg");
	}
	if (zV == NULL) {
		throw invalid_argument("second message must be an instance of SigmaBIMsg");
	}

	//Get the exponent in the second message from the prover.
	biginteger zBI = zV->getMsg();
	//Get the exponent in the second message from the prover.
	biginteger aBI = aV->getMsg();
	
	//Get the cipher value.
	biginteger c = djInput->getCiphertext().getCipher();

	//If a is not relatively prime to n, set verified to false.
	verified = verified && (mp::gcd(aBI, n) == 1);

	//If z is not relatively prime to n, set verified to false.
	verified = verified && (mp::gcd(zBI, n) == 1);

	//If c is not relatively prime to n, set verified to false.
	verified = verified && (mp::gcd(c, n) == 1);
	
	//Calculate N = n^s and N' = n^(s+1)
	biginteger N = mp::pow(n, lengthParameter);
	biginteger NTag = mp::pow(n, lengthParameter + 1);

	//Calculate z^N mod N' (left side of the equation).
	biginteger left = mp::powm(zBI, N, NTag);
	//Calculate (a*c^e) mod N' (left side of the equation).
	//Convert e to BigInteger.
	biginteger eBI = decodeBigInteger(e.data(), e.size());
	biginteger cToe = mp::powm(c, eBI, NTag);
	biginteger right = (aBI* cToe) % NTag;
	
	//If left and right sides of the equation are not equal, set verified to false.
	verified = verified && left == right;

	e.clear(); //Delete the random value e.

	//Return true if all checks returned true; false, otherwise.
	return verified;
}