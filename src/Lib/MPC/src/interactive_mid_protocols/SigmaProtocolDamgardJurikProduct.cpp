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


#include "../../include/interactive_mid_protocols/SigmaProtocolDamgardJurikProduct.hpp"


string SigmaDJProductCommonInput::toString() {
	string output = publicKey.generateSendableData()->toString();
	output += ":";
	output += cipher1.generateSendableData()->toString();
	output += ":";
	output += cipher2.generateSendableData()->toString();
	output += ":";
	output += cipher3.generateSendableData()->toString();
	return output;
}

/**
* Sets the given public key, three ciphertexts, three random values, and two plaintexts.
* @param publicKey used to encrypt.
* @param c1 first ciphertext
* @param c2 second ciphertext
* @param c3 third ciphertext
* @param r1 first random number used to encrypt x1
* @param r2 first random number used to encrypt x2
* @param r3 first random number used to encrypt x3
* @param x1 first plaintext
* @param x2 second plaintext
*/
SigmaDJProductProverInput::SigmaDJProductProverInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext c1, BigIntegerCiphertext c2, BigIntegerCiphertext c3,
	const biginteger & r1, const biginteger & r2, const biginteger & r3, BigIntegerPlainText x1, BigIntegerPlainText x2) : x1(x1), x2(x2) {

	input = make_shared<SigmaDJProductCommonInput>(publicKey, c1, c2, c3);
	this->r1 = r1;
	this->r2 = r2;
	this->r3 = r3;
}

/**
* This protocol assumes that the prover knows the randomness used to encrypt.
* If the prover knows the secret key, then it can compute (once) the value m=n^(-1) mod phi(n)=n^(-1) mod (p-1)(q-1).
* Then, it can recover the randomness ri from ci by computing ci^m mod n (this equals ri^(n/n) mod n = ri).
* Once given r, the prover can proceed with the protocol.
* @param c1 first ciphertext
* @param c2 second ciphertext
* @param c3 third ciphertext
* @param privateKey used to recover r1, r2, r3
* @param x1 first plaintext
* @param x2 second plaintext
*
*/
SigmaDJProductProverInput::SigmaDJProductProverInput(DamgardJurikPublicKey publicKey, BigIntegerCiphertext c1, BigIntegerCiphertext c2, BigIntegerCiphertext c3,
	DamgardJurikPrivateKey privateKey, BigIntegerPlainText x1, BigIntegerPlainText x2) : x1(x1), x2(x2) {
	
	input = make_shared<SigmaDJProductCommonInput>(publicKey, c1, c2, c3);
	
	//Calculate r from the given private key.
	biginteger p = privateKey.getP();
	biginteger q = privateKey.getQ();
	biginteger pMinusOne = p - 1;
	biginteger qMinusOne = q - 1;
	biginteger n = p * q;
	//(p-1)*(q-1)
	biginteger phiN = pMinusOne * qMinusOne;
	//m = n^(-1) mod (p-1)(q-1).
	biginteger m = MathAlgorithms::modInverse(n, phiN);
	//ri = ci^m mod n
	r1 = mp::powm(c1.getCipher(), m, n);
	r2 = mp::powm(c2.getCipher(), m, n);
	r3 = mp::powm(c3.getCipher(), m, n);
}

string SigmaDJProductFirstMsg::toString() {
	return a1.str() + ":" + a2.str();
}
void SigmaDJProductFirstMsg::initFromString(const string & row) {
	auto str_vec = explode(row, ':');
	assert(str_vec.size() == 2);
	a1 = biginteger(str_vec[0]);
	a2 = biginteger(str_vec[1]);
}

string SigmaDJProductSecondMsg::toString() {
	return z1.str() + ":" + z2.str() + ":" + z3.str();
}

void SigmaDJProductSecondMsg::initFromString(const string & row) {
	auto str_vec = explode(row, ':');
	assert(str_vec.size() == 3);
	z1 = biginteger(str_vec[0]);
	z2 = biginteger(str_vec[1]);
	z3 = biginteger(str_vec[2]);
}


/**
* Constructor that gets the soundness parameter, length parameter and SecureRandom.
* @param t Soundness parameter in BITS.
* @param lengthParameter length parameter in BITS.
* @param random
*/
SigmaDJProductSimulator::SigmaDJProductSimulator(int t, int lengthParameter, const shared_ptr<PrgFromOpenSSLAES> & random) {

	this->t = t;
	this->lengthParameter = lengthParameter;
	this->random = random;
}

/**
* Computes the simulator computation with the given challenge.
* @param input MUST be an instance of SigmaDJProductCommonInput.
* @param challenge
* @return the output of the computation - (a, e, z).
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
* @throws IllegalArgumentException if the given input is not an instance of SigmaDJProductCommonInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaDJProductSimulator::simulate(SigmaCommonInput* input, const vector<byte> & challenge) {
	/*
	* SAMPLE random values z1 <- ZN, z2 <- Z*n, z3 <- Z*n
	* COMPUTE a1 = (1+n)^z1*(z2^N/c1^e) mod N' AND a2 = c2^z1/(z3^N*c3^e) mod N'
	* OUTPUT (a,e,z) where a = (a1,a2) AND z=(z1,z2,z3)
	*/

	//check the challenge validity.
	if (!checkChallengeLength(challenge)) {
		throw CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
	}

	auto djInput = dynamic_cast<SigmaDJProductCommonInput*>(input);
	if (djInput == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaDJProductCommonInput");
	}
	
	biginteger n = djInput->getPublicKey().getModulus();
	//Check the soundness validity.
	if (!checkSoundnessParam(n)) {
		throw invalid_argument("t must be less than a third of the length of the public key n");
	}

	//Calculate N = n^s and N' = n^(s+1)
	biginteger N = mp::pow(n, lengthParameter);
	biginteger NTag = mp::pow(n, lengthParameter + 1);

	//Sample a random value z1 <- ZN
	biginteger z1 = getRandomInRange(0, N - 1, random.get());
	//Sample a random value z2 <- Z*n
	biginteger z2 = getRandomInRange(1, n - 1, random.get());
	//Sample a random value z3 <- Z*n
	biginteger z3 = getRandomInRange(1, n - 1, random.get());

	//Create the BigInteger value out of the challenge.
	biginteger e = decodeBigInteger(challenge.data(), challenge.size());

	//Compute a1 = (1+n)^z1*(z2^N/c1^e) mod N'
	biginteger leftMul = mp::powm(n + 1, z1, NTag);
	biginteger z2ToN = mp::powm(z2, N, NTag);
	biginteger denom = mp::powm(djInput->getC1().getCipher(), e, NTag);
	biginteger denomInv = MathAlgorithms::modInverse(denom, NTag);
	biginteger rightMul = (z2ToN * denomInv) % (NTag);
	biginteger a1 = (leftMul * rightMul) % (NTag);

	//Compute a2 = c2^z1/(z3^N*c3^e) mod N'
	biginteger c2ToZ1 = mp::powm(djInput->getC2().getCipher(), z1, NTag);
	biginteger z3ToN = mp::powm(z3, N, NTag);
	biginteger c3ToE = mp::powm(djInput->getC3().getCipher(), e, NTag);
	denom = (c3ToE * z3ToN) % (NTag);
	denomInv = MathAlgorithms::modInverse(denom, NTag);
	biginteger a2 = (c2ToZ1* denomInv) % (NTag);

	//Output (a,e,z).
	return make_shared<SigmaSimulatorOutput>(make_shared<SigmaDJProductFirstMsg>(a1, a2), challenge, make_shared<SigmaDJProductSecondMsg>(z1, z2, z3));
}

/**
* Computes the simulator computation with a randomly chosen challenge.
* @param input MUST be an instance of SigmaDJProductInput.
* @return the output of the computation - (a, e, z).
* @throws IllegalArgumentException if the given input is not an instance of SigmaDJProductInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaDJProductSimulator::simulate(SigmaCommonInput* input) { 
	//Create a new byte array of size t/8, to get the required byte size.
	vector<byte> e(t / 8);
	random->getPRGBytes(e, 0, t / 8);
	//modify the challenge to be positive.
	e.data()[e.size() - 1] = e.data()[e.size() - 1] & 127;
	//Call the other simulate function with the given input and the sampled e.
	return simulate(input, e);
}

/**
* Checks the validity of the given soundness parameter.
* t must be less than a third of the length of the public key n.
* @return true if the soundness parameter is valid; false, otherwise.
*/
bool SigmaDJProductSimulator::checkSoundnessParam(const biginteger & modulus) {
	//If soundness parameter is not less than a third of the publicKey n, return false.
	int third = NumberOfBits(modulus) / 3;
	return (t < third);
}

/**
* Checks if the given challenge length is equal to the soundness parameter.
* @return true if the challenge length is t; false, otherwise.
*/
bool SigmaDJProductSimulator::checkChallengeLength(const vector<byte> & challenge) {
	//If the challenge's length is equal to t, return true. else, return false.
	return ((int) challenge.size() == (t / 8) ? true : false);
}

/**
* Constructor that gets the soundness parameter, length parameter and SecureRandom.
* @param t Soundness parameter in BITS.
* @param lengthParameter length parameter in BITS.
* @param random
*/
SigmaDJProductProverComputation::SigmaDJProductProverComputation(int t, int lengthParameter, const shared_ptr<PrgFromOpenSSLAES> & random) {

	this->t = t;
	this->lengthParameter = lengthParameter;
	this->random = random;
}

/**
* Computes the first message of the protocol.<p>
* "SAMPLE random values d <- ZN, rd <- Z*n, rdb <- Z*n<p>
*  COMPUTE a1 = (1+n)^d*rd^N mod N' and a2 = ((1+n)^(d*x2))*(rdb^N) mod N' and SET a = (a1,a2)".
* @param input MUST be an instance of SigmaDJProductProverInput.
* @return the computed message
* @throws IllegalArgumentException if input is not an instance of SigmaDJProductProverInput.
*/
shared_ptr<SigmaProtocolMsg> SigmaDJProductProverComputation::computeFirstMsg(const shared_ptr<SigmaProverInput> & input) {
	this->input = dynamic_pointer_cast<SigmaDJProductProverInput>(input);
	if (this->input == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaDJProductProverInput");
	}

	auto common = dynamic_pointer_cast<SigmaDJProductCommonInput>(this->input->getCommonInput());
	if (common == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaDJProductCommonInput");
	}
	n = common->getPublicKey().getModulus();
	
	//Check the soundness validity.
	if (!checkSoundnessParam(n)) {
		throw invalid_argument("t must be less than a third of the length of the public key n");
	}

	//Calculate N = n^s and N' = n^(s+1)
	N = mp::pow(n, lengthParameter);
	NTag = mp::pow(n, lengthParameter + 1);

	//Sample d <-[0, ..., N-1]
	d = getRandomInRange(0, N - 1, random.get());

	//Sample rd, rdb <-[1, ..., n-1]
	rd = getRandomInRange(1, n - 1, random.get());
	rdb = getRandomInRange(1, n - 1, random.get());

	//Calculate (1+n)^d
	biginteger nPlusOneToD = mp::powm(n + 1, d, NTag);
	//Calculate rd^N
	biginteger rdToN = mp::powm(rd, N, NTag);
	//Calculate a1=(1+n)^d*rd^N mod N'
	biginteger a1 = (nPlusOneToD * rdToN) % (NTag);

	//Calculate (1+n)^(d*x2)
	biginteger exponent = d * (this->input->getX2().getX());
	biginteger nPlusOnePow = mp::powm(n + 1, exponent, NTag);
	//Calculate rdb^N
	biginteger rdbToN = mp::powm(rdb, N, NTag);
	//Calculate a2 = ((1+n)^(d*x2))*(rdb^N) mod N'
	biginteger a2 = (nPlusOnePow * rdbToN) % (NTag);

	//Create and return SigmaDJProductFirstMsg with a1 and a2.
	return make_shared<SigmaDJProductFirstMsg>(a1, a2);

}

/**
* Computes the second message of the protocol.<p>
* "COMPUTE z1=e^x1+d mod N, z2 = r1^e*rd mod n, z3=(r2^z1)/(rdb*r3^e) mod n, and SET z=(z1,z2,z3)".
* @param challenge
* @return the computed message.
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
*/
shared_ptr<SigmaProtocolMsg> SigmaDJProductProverComputation::computeSecondMsg(const vector<byte> & challenge) {

	//check the challenge validity.
	if (!checkChallengeLength(challenge)) {
		throw new CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
	}

	//Compute z1 = e*x1+d mod N
	biginteger e = decodeBigInteger(challenge.data(), challenge.size());
	biginteger ex1 = e * (input->getX1().getX());
	biginteger z1 = (ex1 + d) % (N);

	//Compute z2 = r1^e*rd mod n
	biginteger r1Toe = mp::powm(input->getR1(), e, n);
	biginteger z2 = (r1Toe * rd) % (n);

	//Compute z3=(r2^z1)/(rdb*r3^e) mod n
	biginteger numerator = mp::powm(input->getR2(), z1, n);
	biginteger r3ToE = mp::powm(input->getR3(), e, n);
	biginteger denominator = rdb* r3ToE;
	biginteger denominatorInv = MathAlgorithms::modInverse(denominator, n);
	biginteger z3 = (numerator * denominatorInv) % (n);

	//Delete the random values
	d = 0;
	rd = 0;
	rdb = 0;

	//Create and return SigmaDJProductSecondMsg with z1, z2 and z3.
	return make_shared<SigmaDJProductSecondMsg>(z1, z2, z3);

}

/**
* Checks the validity of the given soundness parameter.
* t must be less than a third of the length of the public key n.
* @return true if the soundness parameter is valid; false, otherwise.
*/
bool SigmaDJProductProverComputation::checkSoundnessParam(const biginteger & modulus) {
	//If soundness parameter is not less than a third of the publicKey n, return false.
	int third = NumberOfBits(modulus) / 3;
	return (t < third);
}

/**
* Checks if the given challenge length is equal to the soundness parameter.
* @return true if the challenge length is t; false, otherwise.
*/
bool SigmaDJProductProverComputation::checkChallengeLength(const vector<byte> & challenge) {
	//If the challenge's length is equal to t, return true. else, return false.
	return ((int) challenge.size() == (t / 8) ? true : false);
}

/**
* Constructor that gets the soundness parameter, length parameter and SecureRandom.
* @param t Soundness parameter in BITS.
* @param lengthParameter length parameter in BITS.
* @param random
*/
SigmaDJProductVerifierComputation::SigmaDJProductVerifierComputation(int t, int lengthParameter, const shared_ptr<PrgFromOpenSSLAES> & random) {
	this->t = t;
	this->lengthParameter = lengthParameter;
	this->random = random;
}

/**
* Samples the challenge of the protocol.<p>
* 	"SAMPLE a random challenge e<-{0,1}^t".
*/
void SigmaDJProductVerifierComputation::sampleChallenge() {
	//make space for t/8 bytes and fill it with random values.
	e.resize(t / 8);
	random->getPRGBytes(e, 0, t / 8);
	//modify the challenge to be positive.
	e.data()[e.size() - 1] = e.data()[e.size() - 1] & 127;
}

/**
* Computes the verification of the protocol.<p>
* 	"ACC IFF c1,c2,c3,a1,a2,z1,z2,z3 are relatively prime to n <p>
AND c1^e*a1 = (1+n)^z1*z2^N mod N'<p>
AND (c2^z1)/(a2*c3^e) = z3^N mod N'".
* @param z second message from prover
* @return true if the proof has been verified; false, otherwise.
* @throws IllegalArgumentException if the first prover message is not an instance of SigmaDJProductFirstMsg
* @throws IllegalArgumentException if the second prover message is not an instance of SigmaDJProductSecondMsg
*/
bool SigmaDJProductVerifierComputation::verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) {
	checkInput(input, a, z);
	auto djInput = dynamic_cast<SigmaDJProductCommonInput*>(input);
	auto firstMsg = dynamic_cast<SigmaDJProductFirstMsg*>(a);
	auto secondMsg = dynamic_cast<SigmaDJProductSecondMsg*>(z);
	biginteger n = djInput->getPublicKey().getModulus();

	//Get the ciphertexts values from the input.
	biginteger c1 = djInput->getC1().getCipher();
	biginteger c2 = djInput->getC2().getCipher();
	biginteger c3 = djInput->getC3().getCipher();

	//Get values from the prover's first message.
	biginteger a1 = firstMsg->getA1();
	biginteger a2 = firstMsg->getA2();

	//Get values from the prover's first message.
	biginteger z1 = secondMsg->getZ1();
	biginteger z2 = secondMsg->getZ2();
	biginteger z3 = secondMsg->getZ3();

	//If one of the values is not relatively prime to n, set verified to false.
	bool verified = areRelativelyPrime(n, c1, c2, a1, a2, z1, z2, z3);

	//Calculate N = n^s and N' = n^(s+1)
	biginteger N = mp::pow(n, lengthParameter);
	biginteger NTag = mp::pow(n, lengthParameter + 1);
	//Convert e to BigInteger.
	biginteger eBI = decodeBigInteger(e.data(), e.size());

	//Check that c1^e*a1 = (1+n)^z1*z2^N mod N'
	biginteger c1ToE = mp::powm(c1, eBI, NTag);
	biginteger left = (c1ToE * a1) % (NTag);
	biginteger nPlusOneToZ1 = mp::powm(n + 1, z1, NTag);
	biginteger z2ToN = mp::powm(z2, N, NTag);
	biginteger right = (nPlusOneToZ1 * z2ToN) % (NTag);

	//If left and right sides of the equation are not equal, set verified to false.
	verified = verified && (left == right);

	//Check that (c2^z1)/(a2*c3^e) = z3^N mod N'
	biginteger numerator = mp::powm(c2, z1, NTag);
	biginteger c3ToE = mp::powm(c3, eBI, NTag);
	biginteger denominator = (a2 * c3ToE) % (NTag);
	biginteger denominatorInv = MathAlgorithms::modInverse(denominator, NTag);
	left = (numerator * denominatorInv) % (NTag);
	right = mp::powm(z3, N, NTag);

	//If left and right sides of the equation are not equal, set verified to false.
	verified = verified && (left == right);

	e.clear(); //Delete the random value e.

	//Return true if all checks returned true; false, otherwise.
	return verified;

}

void SigmaDJProductVerifierComputation::checkInput(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) {
	auto djInput = dynamic_cast<SigmaDJProductCommonInput*>(input);
	if (djInput == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaDJProductInput");
	}

	biginteger n = djInput->getPublicKey().getModulus();
	// Check the soundness validity.
	if (!checkSoundnessParam(n)) {
		throw invalid_argument("t must be less than a third of the length of the public key n");
	}

	//If one of the messages is illegal, throw exception.
	auto firstMsg = dynamic_cast<SigmaDJProductFirstMsg*>(a);
	auto secondMsg = dynamic_cast<SigmaDJProductSecondMsg*>(z);
	if (firstMsg == NULL) {
		throw invalid_argument("first message must be an instance of SigmaDJProductFirstMsg");
	}
	if (secondMsg == NULL) {
		throw invalid_argument("second message must be an instance of SigmaDJProductSecondMsg");
	}
}

bool SigmaDJProductVerifierComputation::areRelativelyPrime(const biginteger & n, const biginteger & c1, const biginteger & c2, const biginteger & a1,
	const biginteger & a2, const biginteger & z1, const biginteger & z2, const biginteger & z3) {

	//Check that the ciphertexts are relatively prime to n. 
	if ((mp::gcd(c1, n) != 1) || (mp::gcd(c2, n) != 1) || (mp::gcd(c2, n) != 1)) {
		return false;
	}

	//Check that the first message's values are relatively prime to n. 
	if ((mp::gcd(a1, n) != 1) || (mp::gcd(a2, n) != 1)) {
		return false;
	}

	//Check that the second message's values are relatively prime to n. 
	if ((mp::gcd(z1, n) != 1) || (mp::gcd(z2, n) != 1) || (mp::gcd(z3, n) != 1)) {
		return false;
	}

	return true;
}