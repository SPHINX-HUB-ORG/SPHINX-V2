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


#include "../../include/mid_layer/DamgardJurikEnc.hpp"

string DamgardJurikPublicKey::toString() {
	return modulus.str();
}

void DamgardJurikPublicKey::initFromString(const string & row) {
	modulus = biginteger(row);
}

DamgardJurikPrivateKey::DamgardJurikPrivateKey(RSAModulus & rsaMod) {

	this->p = rsaMod.p;
	this->q = rsaMod.q;

	//Computes t = lcm(p-1, q-1) where lcm is the least common multiple and can be computed as lcm(a,b) = a*b/gcd(a,b).
	biginteger pMinus1 = p - 1;
	biginteger qMinus1 = q - 1;
	biginteger gcdPMinus1QMinus1 = mp::gcd(pMinus1, qMinus1);
	t = (pMinus1 * qMinus1) / gcdPMinus1QMinus1;

	//Precalculate d for the case that s == 1
	dForS1 = generateD(rsaMod.n, t);
}

DamgardJurikPrivateKey::DamgardJurikPrivateKey(const biginteger & p, const biginteger & q, const biginteger & t, const biginteger & dForS1) {
	this->p = p;
	this->q = q;
	this->t = t;
	this->dForS1 = dForS1;
}

string DamgardJurikPrivateKey::toString() {
	biginteger t;
	biginteger dForS1; //Pre-calculated d in the case the s == 1
	biginteger p;
	biginteger q;
	return t.str() + ":" + dForS1.str() + ":" + p.str() + ":" + q.str();
}

void DamgardJurikPrivateKey::initFromString(const string & row) {
	auto str_vec = explode(row, ':');
	assert(str_vec.size() == 4);
	t = biginteger(str_vec[0]);
	dForS1 = biginteger(str_vec[1]);
	p = biginteger(str_vec[2]);
	q = biginteger(str_vec[3]);
}

biginteger DamgardJurikPrivateKey::generateD(biginteger & N, biginteger & t) {
	vector<biginteger> congruences;
	congruences.push_back(1);
	congruences.push_back(0);
	vector<biginteger> moduli;
	moduli.push_back(N);
	moduli.push_back(t);
	biginteger d = MathAlgorithms::chineseRemainderTheorem(congruences, moduli);
	return d;
}

/**
* Initializes this DamgardJurik encryption scheme with (public, private) key pair.
* After this initialization the user can encrypt and decrypt messages.
* @param publicKey should be DamgardJurikPublicKey.
* @param privateKey should be DamgardJurikPrivateKey.
* @throws InvalidKeyException if the given keys are not instances of DamgardJurik keys.
*/
void DamgardJurikEnc::setKey(const shared_ptr<PublicKey> & publicKey, const shared_ptr<PrivateKey> & privateKey) {
	this->publicKey = dynamic_pointer_cast<DamgardJurikPublicKey>(publicKey);
	//Public key should be Damgard Jurik public key.
	if (this->publicKey == NULL) {
		throw InvalidKeyException("The public key must be of type DamgardJurikPublicKey");
	}
	
	//Private key should be Damgard Jurik private key or null if we are only setting the public key.	
	if (privateKey != NULL) {
		this->privateKey = dynamic_pointer_cast<DamgardJurikPrivateKey>(privateKey);
		if (this->privateKey == NULL) {
			throw InvalidKeyException("The private key must be of type DamgardJurikPrivateKey");
		}
	}

	keySet = true;
}

/**
* Returns the PublicKey of this DamgardJurik encryption scheme.
* This function should not be use to check if the key has been set.
* To check if the key has been set use isKeySet function.
* @return the DamgardJurikPublicKey
* @throws IllegalStateException if no public key was set.
*/
shared_ptr<PublicKey> DamgardJurikEnc::getPublicKey() {
	if (!isKeySet()) {
		throw new IllegalStateException("no PublicKey was set");
	}

	return publicKey;
}

/**
* Generate an DamgardJurik key pair using the given parameters.
* @param keyParams MUST be an instance of DJKeyGenParameterSpec.
* @return KeyPair contains keys for this DamgardJurik encryption object.
* @throws InvalidParameterSpecException if keyParams is not instance of DJKeyGenParameterSpec.
*/
pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>> DamgardJurikEnc::generateKey(AlgorithmParameterSpec * keyParams) {

	auto params = dynamic_cast<DJKeyGenParameterSpec*>(keyParams);
	if (params == NULL) {
		throw invalid_argument("keyParams has to be an instance of DJKeyGenParameterSpec");
	}


	//Chooses an RSA modulus n = p*q of length k bits.
	//Let n be the Public Key.
	//Let rsaMod be the Private Key.

	RSAModulus rsaMod(params->getModulusLength(), params->getCertainty(), random.get());
	shared_ptr<PublicKey> publicKey = make_shared<DamgardJurikPublicKey>(rsaMod.n);
	shared_ptr<PrivateKey> privateKey = make_shared<DamgardJurikPrivateKey>(rsaMod);
	return pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>>(publicKey, privateKey);
}

/**
* This function performs the encryption of he given plain text
* @param plainText MUST be an instance of BigIntegerPlainText.
* @return an object of type BigIntegerCiphertext holding the encryption of the plaintext.
* @throws IllegalStateException if no public key was set.
* @throws IllegalArgumentException in the following cases:
* 		1. If the given plaintext is not instance of BigIntegerPlainText.
* 		2. If the BigInteger value in the given plaintext is not in ZN.
*/
shared_ptr<AsymmetricCiphertext> DamgardJurikEnc::encrypt(const shared_ptr<Plaintext> & plaintext) {
	/*
	* We use the notation N=n^s, and N' = n^(s+1).
	* Pseudo-Code:
	* 		COMPUTE s=(|x|/(|n|-1)) + 1.
	* 		CHOOSE a random r in ZN'*.
	*/
	auto plain = dynamic_pointer_cast<BigIntegerPlainText>(plaintext);
	if (plain == NULL) {
		throw invalid_argument("The plaintext has to be of type BigIntegerPlainText");
	}

	biginteger x = plain->getX();

	//Calculates the length parameter s.
	int s = (consts != -1) ? consts : ((NumberOfBits(x) / (NumberOfBits(publicKey->getModulus()) - 1)) + 1);

	biginteger Ntag = mp::pow(publicKey->getModulus(), s + 1);
	
	//Chooses a random r in ZNtag*, this can be done by choosing a random value between 1 and Ntag -1 
	//which is with overwhelming probability in Zntag*.
	biginteger r = getRandomInRange(1, Ntag - 1, random.get());

	return encrypt(plaintext, r);
}

/**
* Encrypts the given plaintext using this asymmetric encryption scheme and using the given random value.<p>
* There are cases when the random value is used after the encryption, for example, in sigma protocol.
* In these cases the random value should be known to the user. We decided not to have function that return it to the user
* since this can cause problems when more than one value is being encrypt.
* Instead, we decided to have an additional encrypt value that gets the random value from the user.
* @param plainText message to encrypt
* @param r The random value to use in the encryption.
* @param plainText MUST be an instance of BigIntegerPlainText.
* @return an object of type BigIntegerCiphertext holding the encryption of the plaintext.
* @throws IllegalStateException if no public key was set.
* @throws IllegalArgumentException in the following cases:
* 		1. If the given plaintext is not instance of BigIntegerPlainText.
* 		2. If the BigInteger value in the given plaintext is not in ZN.
*/
shared_ptr<AsymmetricCiphertext> DamgardJurikEnc::encrypt(const shared_ptr<Plaintext> & plaintext, const biginteger & r) {
	/*
	* We use the notation N=n^s, and N' = n^(s+1).
	* Pseudo-Code:
	* 		COMPUTE s=(|x|/(|n|-1)) + 1.
	* 		CHECK that x is in ZN.
	*		COMPUTE c = (1+n)^x * r^N mod N'.
	* 		OUTPUT c.
	*/

	// If there is no public key can not encrypt, throws exception.
	if (!isKeySet()) {
		throw IllegalStateException("in order to encrypt a message this object must be initialized with public key");
	}

	auto plain = dynamic_pointer_cast<BigIntegerPlainText>(plaintext);
	if (plain == NULL) {
		throw invalid_argument("The plaintext has to be of type BigIntegerPlainText");
	}

	biginteger x = plain->getX();
	
	//Calculates the length parameter s.
	int s = (consts != -1) ? consts : ((NumberOfBits(x) / (NumberOfBits(publicKey->getModulus()) - 1)) + 1);
	biginteger N = mp::pow(publicKey->getModulus(), s);
	
	//Makes sure the x belongs to ZN
	if (x < 0 || x >= N)
		throw invalid_argument("Message too big for encryption");
	
	biginteger Ntag = mp::pow(publicKey->getModulus(), s + 1);
	biginteger NtagMinus1 = Ntag - 1;

	//Check that the random value passed to this function is in Zq.
	if (!((r >= 0) && (r <= NtagMinus1))) {
		throw invalid_argument("r must be in Zq");
	}

	//Computes c = ((1 + n) ^x) * r ^N mod N'.
	biginteger mult1 = mp::powm(publicKey->getModulus() + 1, x, Ntag);
	biginteger mult2 = mp::powm(r, N, Ntag);
	biginteger c = (mult1 * mult2) % Ntag;
	
	//Wraps the BigInteger c with BigIntegerCiphertext and returns it.
	return make_shared<BigIntegerCiphertext>(c);

}

/**
* Decrypts the given ciphertext using DamgardJurik encryption scheme.
* @param cipher has to be an instance of BigIntegerCiphertext.
* @throws KeyException if the Private Key has not been set for this object.
* @throws IllegalArgumentException if cipher is not an instance of BigIntegerCiphertext.
*/
shared_ptr<Plaintext> DamgardJurikEnc::decrypt(AsymmetricCiphertext* cipher) {
	/*
	* We use the notation N=n^s, and N' = n^(s+1).
	* Pseudo-Code:
	* 		COMPUTE s=|c| / |n|
	* 		CHECK that c is in ZN'.
	* 		COMPUTE using the Chinese Remainder Theorem a value d, such that d = 1 mod N, and d=0 mod t.
	*		COMPUTE c^d mod N'.
	*		COMPUTE x as the discrete logarithm of c^d to the base (1+n) modulo N'. This is done by the following computation
	*	 	a=c^d
	*		x=0
	*		for j = 1 to s do
	*		begin
	*		   t1= ((a mod n^(j+1)) -  1) / n
	*		   t2 = x
	*		   for k = 2 to j do
	*		   begin
	*		      x = x - 1
	*		      t2 = t2 * x mod nj
	*		      t1 =  (t1 - (t2 * n^(k-1)) / factorial(k) )  mod n^j
	*		  end
	*		  x = t1
	*		end
	*		OUTPUT x
	*/

	//If there is no private key, throws exception.
	if (privateKey == NULL) {
		throw KeyException("in order to decrypt a message, this object must be initialized with private key");
	}
	//Ciphertext should be Damgard-Jurik ciphertext.
	auto djCipher = dynamic_cast<BigIntegerCiphertext*>(cipher);
	if (djCipher == NULL) {
		throw invalid_argument ("cipher should be instance of BigIntegerCiphertext");
	}

	//n is the modulus in the public key.
	biginteger n = publicKey->getModulus();
	//Calculates s = |cipher| / |n|
	int s = (consts != -1) ? consts : (NumberOfBits(djCipher->getCipher()) / NumberOfBits(n));
	
	//Calculates N and N' based on s: N = n^s, N' = n^(s+1)
	biginteger N = mp::pow(n, s);
	biginteger Ntag = mp::pow(n, s + 1);

	//Makes sure the cipher belongs to ZN'
	if (djCipher->getCipher() < 0 || djCipher->getCipher()>= Ntag)
		throw invalid_argument("The cipher is not in ZN'");
	biginteger d;
	//Optimization for the calculation of d:
	//If s == 1 used the pre-computed d which we have in the private key
	//else, compute d using the Chinese Remainder Theorem, such that d = 1 mod N, and d = 0 mod t.
	if (s == 1) {
		d = privateKey->getDForS1();
	} else {
		d = generateD(N, privateKey->getT());
	}
	
	//Computes (cipher ^ d) mod N'
	biginteger a = mp::powm(djCipher->getCipher(), d, Ntag);
	//Computes x as the discrete logarithm of c^d to the base (1+n) modulo N'. This is done by the algorithm shown above.
	biginteger x = 0;
	biginteger t1, t2;
	biginteger nPowJ, factorialK, temp;
	for (int j = 1; j <= s; j++) {
		t1 = ((a % mp::pow(n, j + 1)) - 1) / n;
		t2 = x;
		nPowJ = mp::pow(n, j);
		for (int k = 2; k <= j; k++) {
			x = x - 1;
			t2 =(t2 * x) % nPowJ;
			factorialK = MathAlgorithms::factorialBI(k);
			temp = (t2 * mp::pow(n, k - 1)) / factorialK;
			t1 = (t1 - temp) % nPowJ;
		}
		x = t1;
	}

	return make_shared<BigIntegerPlainText>(x);
}

/**
* Generates a byte array from the given plaintext.
* This function should be used when the user does not know the specific type of the Asymmetric encryption he has,
* and therefore he is working on byte array.
* @param plaintext to generates byte array from. MUST be an instance of BigIntegerPlainText.
* @return the byte array generated from the given plaintext.
* @throws IllegalArgumentException if the given plaintext is not an instance of BigIntegerPlainText.
*/
vector<byte> DamgardJurikEnc::generateBytesFromPlaintext(Plaintext* plaintext) {
	auto plain = dynamic_cast<BigIntegerPlainText*>(plaintext);
	if (plain == NULL) {
		throw invalid_argument("the given plaintext should be an instance of BigIntegerPlainText");
	}
	int size = bytesCount(plain->getX());
	byte* num = new byte[size];
	encodeBigInteger(plain->getX(), num, size);
	vector<byte> out;
	copy_byte_array_to_byte_vector(num, size, out, 0);
	return out;
}

/**
* This function takes an encryption of some plaintext (let's call it originalPlaintext) and returns a cipher that "looks" different but
* it is also an encryption of originalPlaintext.<p>
* The given ciphertext have to has been generated with the same public key as this encryption's public key.
* @throws IllegalStateException if no public key was set.
* @throws IllegalArgumentException in the following cases:
* 		1. If cipher is not an instance of BigIntegerCiphertext.
* 		2. If the BigInteger number in the given cipher is not in ZN'.
*/
shared_ptr<AsymmetricCiphertext> DamgardJurikEnc::reRandomize(AsymmetricCiphertext* cipher) {
	// If there is no public key can not operate the function, throws exception.
	if (!isKeySet()) {
		throw IllegalStateException("in order to reRandomize a ciphertext this object must be initialized with public key");
	}

	//Ciphertext should be Damgard-Jurik ciphertext.
	auto djCipher = dynamic_cast<BigIntegerCiphertext*>(cipher);
	if (djCipher == NULL) {
		throw invalid_argument("cipher should be instance of BigIntegerCiphertext");
	}

	//n is the modulus in the public key.
	//Calculates s = |cipher| / |n|.
	int s = (consts != -1) ? consts : (NumberOfBits(djCipher->getCipher()) / NumberOfBits(publicKey->getModulus()));

	//Calculates N and N' based on s: N = n^s, N' = n^(s+1).
	biginteger n = publicKey->getModulus();
	biginteger Ntag = mp::pow(n, s + 1);

	//Chooses a random r in ZNtag*, this can be done by choosing a random value between 1 and Ntag -1 
	//which is with overwhelming probability in Zntag*.
	biginteger r = getRandomInRange(1, Ntag - 1, random.get());

	return reRandomize(cipher, r);
}

/**
* This function takes an encryption of some plaintext (let's call it originalPlaintext) and returns a cipher that "looks" different but
* it is also an encryption of originalPlaintext. It uses the given BigInteger random value.<p>
* The given ciphertext have to has been generated with the same public key as this encryption's public key.
* @throws IllegalStateException if no public key was set.
* @throws IllegalArgumentException in the following cases:
* 		1. If cipher is not an instance of BigIntegerCiphertext.
* 		2. If the BigInteger number in the given cipher is not in ZN'.
*/
shared_ptr<AsymmetricCiphertext> DamgardJurikEnc::reRandomize(AsymmetricCiphertext* cipher, biginteger & r) {
	// If there is no public key can not operate the function, throws exception.
	if (!isKeySet()) {
		throw IllegalStateException("in order to reRandomize a ciphertext this object must be initialized with public key");
	}

	//Ciphertext should be Damgard-Jurik ciphertext.
	auto djCipher = dynamic_cast<BigIntegerCiphertext*>(cipher);
	if (djCipher == NULL) {
		throw invalid_argument("cipher should be instance of BigIntegerCiphertext");
	}

	//n is the modulus in the public key.
	//Calculates s = |cipher| / |n|.
	int s = (consts != -1) ? consts : (NumberOfBits(djCipher->getCipher()) / NumberOfBits(publicKey->getModulus()));

	//Calculates N and N' based on s: N = n^s, N' = n^(s+1).
	biginteger n = publicKey->getModulus();
	biginteger N = mp::pow(n, s);
	biginteger Ntag = mp::pow(n, s + 1);

	//Makes sure the cipher belongs to ZN'.
	if (djCipher->getCipher() < 0 || djCipher->getCipher() >= Ntag)
		throw invalid_argument("The cipher is not in ZN'");

	biginteger NtagMinus1 = Ntag - 1;
	//Check that the r random value passed to this function is in Zntag*.
	if (!((r >= 0) && (r <= NtagMinus1))) {
		throw invalid_argument("r must be in Zq");
	}

	biginteger temp = mp::powm(r, N, Ntag);
	biginteger c = (djCipher->getCipher() * temp) % Ntag;

	return make_shared<BigIntegerCiphertext>(c);
}

/**
* Given two ciphers c1 = Enc(p1)  and c2 = Enc(p2) this function return c1 + c2 = Enc(p1 +p2).
* Both ciphertext have to have been generated with the same public key as this encryption's public key.
* @throws IllegalStateException if no public key was set.
* @throws IllegalArgumentException in the following cases:
* 		1. If one or more of the given ciphertexts is not an instance of BigIntegerCiphertext.
* 		2. If the sizes of ciphertexts do not match.
* 		3. If one or more of the BigInteger numbers in the given ciphertexts is not in ZN'.
*/
shared_ptr<AsymmetricCiphertext> DamgardJurikEnc::add(AsymmetricCiphertext* cipher1, AsymmetricCiphertext* cipher2) {
	// If there is no public key can not encrypt, throws exception.
	if (!isKeySet()) {
		throw IllegalStateException("in order to add ciphertexts this object must be initialized with public key");
	}

	//Ciphertexts should be Damgard-Jurik ciphertexts.
	auto djCipher1 = dynamic_cast<BigIntegerCiphertext*>(cipher1);
	if (djCipher1 == NULL) {
		throw invalid_argument("cipher should be instance of BigIntegerCiphertext");
	}
	
	biginteger c = djCipher1->getCipher();

	//n is the modulus in the public key.
	//Calculates s = |cipher|/ |n|.
	int s = (consts != -1) ? consts : (NumberOfBits(c) / NumberOfBits(publicKey->getModulus()));

	//Calculates N and N' based on s: N = n^s, N' = n^(s+1).
	biginteger n = publicKey->getModulus();
	biginteger Ntag = mp::pow(n, s + 1);
	
	//Chooses a random r in ZNtag*, this can be done by choosing a random value between 1 and Ntag -1 
	//which is with overwhelming probability in Zntag*.
	biginteger r = getRandomInRange(1, Ntag - 1, random.get());

	return add(cipher1, cipher2, r);
}

/**
* Given two ciphers c1 = Enc(p1)  and c2 = Enc(p2) this function return c1 + c2 = Enc(p1 +p2).<p>
* Both ciphertext have to have been generated with the same public key as this encryption's public key.<p>
*
* There are cases when the random value is used after the function, for example, in sigma protocol.
* In these cases the random value should be known to the user. We decided not to have function that return it to the user
* since this can cause problems when the add function is called more than one time.
* Instead, we decided to have an additional add function that gets the random value from the user.
*
* @throws IllegalStateException if no public key was set.
* @throws IllegalArgumentException in the following cases:
* 		1. If one or more of the given ciphertexts is not an instance of BigIntegerCiphertext.
* 		2. If the sizes of ciphertexts do not match.
* 		3. If one or more of the BigInteger numbers in the given ciphertexts is not in ZN'.
*/
shared_ptr<AsymmetricCiphertext> DamgardJurikEnc::add(AsymmetricCiphertext* cipher1, AsymmetricCiphertext* cipher2, biginteger & r) {

	// If there is no public key can not operate the function, throws exception.
	if (!isKeySet()) {
		throw IllegalStateException("in order to add ciphertexts this object must be initialized with public key");
	}

	//Ciphertexts should be Damgard-Jurik ciphertexts.
	auto djCipher1 = dynamic_cast<BigIntegerCiphertext*>(cipher1);
	auto djCipher2 = dynamic_cast<BigIntegerCiphertext*>(cipher2);
	if (djCipher1 == NULL || djCipher2 == NULL) {
		throw invalid_argument("cipher should be instance of BigIntegerCiphertext");
	}
	
	biginteger c1 = djCipher1->getCipher();
	biginteger c2 = djCipher2->getCipher();
	biginteger n = publicKey->getModulus();

	//n is the modulus in the public key.
	//Calculates s = |cipher|/ |n|.
	int s1 = (consts != -1) ? consts : (NumberOfBits(c1) / NumberOfBits(n));
	int s2 = (consts != -1) ? consts : (NumberOfBits(c2) / NumberOfBits(n));
	if (s1 != s2) {
		throw invalid_argument("Sizes of ciphertexts do not match");
	}
	
	//Calculates N and N' based on s: N = n^s, N' = n^(s+1).
	biginteger N = mp::pow(n, s1);
	biginteger Ntag = mp::pow(n, s1 + 1);
	biginteger NtagMinus1 = Ntag - 1;

	//Check that the r random value passed to this function is in Zntag*.
	if (!((r >= 0) && (r<= NtagMinus1))) {
		throw invalid_argument("r must be in Zq");
	}

	//Checks that cipher1 and cipher2 belong to ZN'
	if (c1 < 0 || c1 >= Ntag)
		throw invalid_argument("cipher1 is not in ZN'");
	if (c2 < 0 || c2 >= Ntag)
		throw invalid_argument("cipher2 is not in ZN'");

	biginteger c = (c1 * c2) % Ntag;
	biginteger temp = mp::powm(r, N, Ntag);
	c = (c * temp) % Ntag;

	//Call the other function that computes the addition.
	return make_shared<BigIntegerCiphertext>(c);
}

/**
* This function calculates the homomorphic multiplication by a constant of a ciphertext<p>
* in the Damgard Jurik encryption scheme.
* @param cipher the cipher to operate on.
* @param constNumber the constant number by which to multiply the cipher.
* @throws IllegalStateException if no public key was set.
* @throws IllegalArgumentException in the following cases:
* 		1. If the given cipher is not an instance of BigIntegerCiphertext.
* 		2. If the BigInteger numbers in the given ciphertext is not in ZN'.
* 		3. If the constant number is not in ZN.
*/
shared_ptr<AsymmetricCiphertext> DamgardJurikEnc::multByConst(AsymmetricCiphertext* cipher, biginteger & constNumber) {
	// If there is no public key can not operate the function, throws exception.
	if (!isKeySet()) {
		throw IllegalStateException("in order to multiply a ciphertext this object must be initialized with public key");
	}

	//Ciphertext should be Damgard-Jurik ciphertext.
	auto djCipher = dynamic_cast<BigIntegerCiphertext*>(cipher);
	if (djCipher == NULL) {
		throw  invalid_argument("cipher should be instance of BigIntegerCiphertext");
	}

	biginteger n = publicKey->getModulus();
	//n is the modulus in the public key.
	//Calculates s = |cipher| / |n|.
	int s = (consts != -1) ? consts : (NumberOfBits(djCipher->getCipher()) / NumberOfBits(n));

	//Calculates N and N' based on s: N = n^s, N' = n^(s+1).
	biginteger Ntag = mp::pow(n, s + 1);
	
	//Chooses a random r in ZNtag*, this can be done by choosing a random value between 1 and Ntag -1 
	//which is with overwhelming probability in Zntag*.
	biginteger r = getRandomInRange(1, Ntag - 1, random.get());

	//Call the other function that computes the multiplication.
	return multByConst(cipher, constNumber, r);
}

/**
* This function calculates the homomorphic multiplication by a constant of a ciphertext
* in the Damgard Jurik encryption scheme.<p>
*
* There are cases when the random value is used after the function, for example, in sigma protocol.
* In these cases the random value should be known to the user. We decided not to have function that return it to the user
* since this can cause problems when the add function is called more than one time.
* Instead, we decided to have an additional add function that gets the random value from the user.
*
* @param cipher the cipher to operate on.
* @param constNumber the constant number by which to multiply the cipher.
* @param r The random value to use in the function.
*
* @throws IllegalStateException if no public key was set.
* @throws IllegalArgumentException in the following cases:
* 		1. If the given cipher is not an instance of BigIntegerCiphertext.
* 		2. If the BigInteger numbers in the given ciphertext is not in ZN'.
* 		3. If the constant number is not in ZN.
*/
shared_ptr<AsymmetricCiphertext> DamgardJurikEnc::multByConst(AsymmetricCiphertext* cipher, biginteger & constNumber, biginteger & r) {
	// If there is no public key can not operate the function, throws exception.
	if (!isKeySet()) {
		throw IllegalStateException("in order to multiply a ciphertext this object must be initialized with public key");
	}

	//Ciphertext should be Damgard-Jurik ciphertext.
	auto djCipher = dynamic_cast<BigIntegerCiphertext*>(cipher);
	if (djCipher == NULL) {
		throw  invalid_argument("cipher should be instance of BigIntegerCiphertext");
	}

	//n is the modulus in the public key.
	biginteger n = publicKey->getModulus();
	//Calculates s = |cipher| / |n|.
	int s = (consts != -1) ? consts : (NumberOfBits(djCipher->getCipher()) / NumberOfBits(n));
	
	//Calculates N and N' based on s: N = n^s, N' = n^(s+1).
	biginteger N = mp::pow(n, s);
	biginteger Ntag = mp::pow(n, s + 1);
	biginteger NtagMinus1 = Ntag - 1;

	//Check that the r random value passed to this function is in Zntag*.
	if (!((r>= 0) && (r <= NtagMinus1))) {
		throw invalid_argument("r must be in Zq");
	}

	//Makes sure the cipher belongs to ZN'.
	if (djCipher->getCipher() < 0 || djCipher->getCipher() >= Ntag)
		throw invalid_argument("The cipher is not in ZN'");

	//Makes sure the constant number belongs to ZN.
	if (constNumber < 0 || constNumber > N) 
		throw invalid_argument("The constant number is not in ZN");

	biginteger c = mp::powm(djCipher->getCipher(), constNumber, Ntag);
	biginteger temp = mp::powm(r, N, Ntag);
	c = (c * temp) % Ntag;

	return make_shared<BigIntegerCiphertext>(c);
}

biginteger DamgardJurikEnc::generateD(biginteger & N, const biginteger & t) {
	vector<biginteger> congruences;
	congruences.push_back(1);
	congruences.push_back(0);
	vector<biginteger> moduli;
	moduli.push_back(N);
	moduli.push_back(t);
	biginteger d = MathAlgorithms::chineseRemainderTheorem(congruences, moduli);
	return d;
}

shared_ptr<AsymmetricCiphertext> DamgardJurikEnc::reconstructCiphertext(AsymmetricCiphertextSendableData* data) {
	auto temp = dynamic_cast<BigIntegerCiphertext*>(data);
	if (temp == NULL)
		throw invalid_argument("The input data has to be of type BigIntegerCiphertext");

	return make_shared<BigIntegerCiphertext>(temp->getCipher());
}

shared_ptr<PublicKey> DamgardJurikEnc::reconstructPublicKey(KeySendableData* data) {
	auto temp = dynamic_cast<DamgardJurikPublicKey*>(data);
	if (temp == NULL)
		throw invalid_argument("To generate the key from sendable data, the data has to be of type DamgardJurikPublicKey");
	return make_shared<DamgardJurikPublicKey>(temp->getModulus());
}

shared_ptr<PrivateKey> DamgardJurikEnc::reconstructPrivateKey(KeySendableData* data)  {
	auto temp = dynamic_cast<DamgardJurikPrivateKey*>(data);
	if (temp == NULL)
		throw invalid_argument("To generate the key from sendable data, the data has to be of type DamgardJurikPrivateKey");
	return make_shared<DamgardJurikPrivateKey>(temp->getP(), temp->getQ(), temp->getT(), temp->getDForS1());
}
