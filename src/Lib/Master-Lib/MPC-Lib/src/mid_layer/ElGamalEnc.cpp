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


#include "../../include/mid_layer/ElGamalEnc.hpp"

void ElGamalOnGrElSendableData::initFromString(const string & row) {
	auto str_vec = explode(row, ':');
	if (str_vec.size() == 2) {

		cipher1->initFromString(str_vec[0]);
		cipher2->initFromString(str_vec[1]);
	} else if (str_vec.size() == 4) {
		cipher1->initFromString(str_vec[0] + ":" + str_vec[1]);
		cipher2->initFromString(str_vec[2] + ":" + str_vec[3]);
	}
}

string ElGamalOnByteArraySendableData::toString() {
	string output = cipher1->toString();
	output += ":";
	const byte * uc = &(cipher2[0]);
	output += string(reinterpret_cast<char const*>(uc), cipher2.size());
	return output;
}
void ElGamalOnByteArraySendableData::initFromString(const string & row) {
	auto str_vec = explode(row, ':');
	assert(str_vec.size() < 4);
	if (str_vec.size() == 2) {

		cipher1->initFromString(str_vec[0]);
		cipher2.assign(str_vec[1].begin(), str_vec[1].end());
	}
	else if (str_vec.size() == 3) {
		cipher1->initFromString(str_vec[0] + ":" + str_vec[1]);
		cipher2.assign(str_vec[2].begin(), str_vec[2].end());
	}
}

void ElGamalEnc::setMembers(const shared_ptr<DlogGroup> & dlogGroup, const shared_ptr<PrgFromOpenSSLAES> & random) {
	auto ddh = dynamic_pointer_cast<DDH>(dlogGroup);
	//The underlying dlog group must be DDH secure.
	if (ddh == NULL) {
		throw SecurityLevelException("DlogGroup should have DDH security level");
	}
	dlog = dlogGroup;
	qMinusOne = dlog->getOrder() - 1;
	this->random = random;
}

/**
* Default constructor. Uses the default implementations of DlogGroup, CryptographicHash and SecureRandom.
*/
ElGamalEnc::ElGamalEnc() {
	try {
		setMembers(make_shared<OpenSSLDlogECF2m>("K-233"));
	}
	catch (...) {
		setMembers(make_shared<OpenSSLDlogZpSafePrime>());
	}
}

/**
* Initializes this ElGamal encryption scheme with (public, private) key pair.
* After this initialization the user can encrypt and decrypt messages.
* @param publicKey should be ElGamalPublicKey.
* @param privateKey should be ElGamalPrivateKey.
* @throws InvalidKeyException if the given keys are not instances of ElGamal keys.
*/
void ElGamalEnc::setKey(const shared_ptr<PublicKey> & publicKey, const shared_ptr<PrivateKey> & privateKey) {
	this->publicKey = dynamic_pointer_cast<ElGamalPublicKey>(publicKey);
	//Key should be ElGamalPublicKey.
	if (this->publicKey == NULL) {
		throw new InvalidKeyException("public key should be an instance of ElGamal public key");
	}

	if (privateKey != NULL) {
		auto key = dynamic_pointer_cast<ElGamalPrivateKey>(privateKey);
		//Key should be ElGamalPrivateKey.
		if (key == NULL) {
			throw new InvalidKeyException("private key should be an instance of ElGamal private key");
		}

		//Computes an optimization of the private key.
		initPrivateKey(key);
	}
	keySet = true;
}

/**
* Generates a KeyPair containing a set of ElGamalPublicKEy and ElGamalPrivateKey using the source of randomness and the dlog specified upon construction.
* @return KeyPair contains keys for this ElGamal object.
*/
pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>> ElGamalEnc::generateKey() {

	//Chooses a random value in Zq.
	biginteger x = getRandomInRange(0, qMinusOne, random.get());
	auto generator = dlog->getGenerator();
	//Calculates h = g^x.
	auto h = dlog->exponentiate(generator.get(), x);
	//Creates an ElGamalPublicKey with h and ElGamalPrivateKey with x.
	auto publicKey = make_shared<ElGamalPublicKey>(h);
	auto privateKey = make_shared<ElGamalPrivateKey>(x);
	//Creates a KeyPair with the created keys.
	return pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>>(publicKey, privateKey);
}

shared_ptr<PublicKey> ElGamalEnc::reconstructPublicKey(KeySendableData* data) {
	auto data1 = dynamic_cast<ElGamalPublicKeySendableData*>(data);
	if (data1 == NULL)
		throw invalid_argument("To generate the key from sendable data, the data has to be of type ScElGamalPublicKeySendableData");
	
	auto h = dlog->reconstructElement(true, data1->getC().get());
	return make_shared<ElGamalPublicKey>(h);
}

shared_ptr<PrivateKey> ElGamalEnc::reconstructPrivateKey(KeySendableData* data) {
	auto data1 = dynamic_cast<ElGamalPrivateKey*>(data);
	if (data1 == NULL)
		throw invalid_argument("To generate the key from sendable data, the data has to be of type ElGamalPrivateKey");
	return make_shared<ElGamalPrivateKey>(data1->getX());
}

/**
* Encrypts the given message using ElGamal encryption scheme.
*
* @param plaintext contains message to encrypt. The given plaintext must match this ElGamal type.
* @return Ciphertext containing the encrypted message.
* @throws IllegalStateException if no public key was set.
* @throws IllegalArgumentException if the given Plaintext does not match this ElGamal type.
*/
shared_ptr<AsymmetricCiphertext> ElGamalEnc::encrypt(const shared_ptr<Plaintext> & plaintext) {
	// If there is no public key can not encrypt, throws exception.
	if (!isKeySet()) {
		throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
	}

	/*
	* Pseudo-code:
	* 		Choose a random  y <- Zq.
	*		Calculate c1 = g^y mod p //Mod p operation are performed automatically by the group.
	*		Calculate c2 = h^y * plaintext.getElement() mod p // For ElGamal on a GroupElement.
	*					OR KDF(h^y) XOR plaintext.getBytes()  // For ElGamal on a ByteArray.
	*/
	//Chooses a random value y<-Zq.
	biginteger y = getRandomInRange(0, qMinusOne, random.get());

	return encrypt(plaintext, y);
}

/**
* Encrypts the given plaintext using this asymmetric encryption scheme and using the given random value.<p>
* There are cases when the random value is used after the encryption, for example, in sigma protocol.
* In these cases the random value should be known to the user. We decided not to have function that return it to the user
* since this can cause problems when more than one value is being encrypt.
* Instead, we decided to have an additional encrypt value that gets the random value from the user.
*
* @param plaintext contains message to encrypt. The given plaintext must match this ElGamal type.
* @param r The random value to use in the encryption.
* @return Ciphertext containing the encrypted message.
* @throws IllegalStateException if no public key was set.
* @throws IllegalArgumentException if the given Plaintext does not match this ElGamal type.
*/
shared_ptr<AsymmetricCiphertext> ElGamalEnc::encrypt(const shared_ptr<Plaintext> & plaintext, const biginteger & r) {

	/*
	* Pseudo-code:
	*		Calculate c1 = g^r mod p //Mod p operation are performed automatically by the group.
	*		Calculate c2 = h^r * plaintext.getElement() mod p // For ElGamal on a GroupElement.
	*					OR KDF(h^r) XOR plaintext.getBytes()  // For ElGamal on a ByteArray.
	*/

	// If there is no public key can not encrypt, throws exception.
	if (!isKeySet()) {
		throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
	}

	//Check that the r random value passed to this function is in Zq.
	if (!((r >= 0) && (r <= qMinusOne))) {
		throw invalid_argument("r must be in Zq");
	}

	//Calculates c1 = g^y and c2 = msg * h^y.
	auto generator = dlog->getGenerator();
	auto c1 = dlog->exponentiate(generator.get(), r);
	auto hy = dlog->exponentiate(publicKey->getH().get(), r);

	return completeEncryption(c1, hy.get(), plaintext.get());
}

/**
* ElGamal decrypt function can be optimized if, instead of using the x value in the private key as is,
* we change it to be q-x, while q is the dlog group order.
* This function computes this changing and saves the new private value as the private key member.
* @param privateKey to change.
*/
void ElGamalOnGroupElementEnc::initPrivateKey(const shared_ptr<ElGamalPrivateKey> & privateKey) {

	//Gets the a value from the private key.
	biginteger x = privateKey->getX();
	//Gets the q-x value.
	biginteger xInv = dlog->getOrder() - x;
	//Sets the q-x value as the private key.
	this->privateKey = make_shared<ElGamalPrivateKey>(xInv);
}

shared_ptr<AsymmetricCiphertext> ElGamalOnGroupElementEnc::completeEncryption(const shared_ptr<GroupElement> & c1, GroupElement* hy, Plaintext* plaintext) {
	auto plain = dynamic_cast<GroupElementPlaintext*>(plaintext);
	if (plain == NULL) {
		throw invalid_argument("plaintext should be instance of GroupElementPlaintext");
	}

	//Gets the element.
	auto msgElement = plain->getElement();

	auto c2 = dlog->multiplyGroupElements(hy, msgElement.get());

	//Returns an ElGamalCiphertext with c1, c2.
	return make_shared<ElGamalOnGroupElementCiphertext>(c1, c2);
}

/**
* Generates a Plaintext suitable to ElGamal encryption scheme from the given message.
* @param text byte array to convert to a Plaintext object.
* @throws IllegalArgumentException if the given message's length is greater than the maximum.
*/
shared_ptr<Plaintext> ElGamalOnGroupElementEnc::generatePlaintext(vector<byte> & text) {
	if ((int) text.size() > getMaxLengthOfByteArrayForPlaintext()) {
		throw invalid_argument("the given text is too big for plaintext");
	}

	return make_shared<GroupElementPlaintext>(dlog->encodeByteArrayToGroupElement(text));
}

/**
* Decrypts the given ciphertext using ElGamal encryption scheme.
*
* @param cipher MUST be of type ElGamalOnGroupElementCiphertext contains the cipher to decrypt.
* @return Plaintext of type GroupElementPlaintext which containing the decrypted message.
* @throws KeyException if no private key was set.
* @throws IllegalArgumentException if the given cipher is not instance of ElGamalOnGroupElementCiphertext.
*/
shared_ptr<Plaintext> ElGamalOnGroupElementEnc::decrypt(AsymmetricCiphertext* cipher) {
	/*
	* Pseudo-code:
	* 		Calculate s = ciphertext.getC1() ^ x^(-1) //x^(-1) is kept in the private key because of the optimization computed in the function initPrivateKey.
	*		Calculate m = ciphertext.getC2() * s
	*/

	//If there is no private key, throws exception.
	if (privateKey == NULL) {
		throw KeyException("in order to decrypt a message, this object must be initialized with private key");
	}

	//Ciphertext should be ElGamal ciphertext.
	auto ciphertext = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher);
	if (ciphertext == NULL) {
		throw invalid_argument("ciphertext should be instance of ElGamalOnGroupElementCiphertext");
	}

	//Calculates sInv = ciphertext.getC1() ^ x.
	auto sInv = dlog->exponentiate(ciphertext->getC1().get(), privateKey->getX());
	//Calculates the plaintext element m = ciphertext.getC2() * sInv.
	auto m = dlog->multiplyGroupElements(ciphertext->getC2().get(), sInv.get());

	//Creates a plaintext object with the element and returns it.
	return make_shared<GroupElementPlaintext>(m);
}

/**
* Generates a byte array from the given plaintext.
* This function should be used when the user does not know the specific type of the Asymmetric encryption he has,
* and therefore he is working on byte array.
* @param plaintext to generates byte array from. MUST be an instance of GroupElementPlaintext.
* @return the byte array generated from the given plaintext.
* @throws IllegalArgumentException if the given plaintext is not an instance of GroupElementPlaintext.
*/
vector<byte> ElGamalOnGroupElementEnc::generateBytesFromPlaintext(Plaintext* plaintext) {
	
	auto plain = dynamic_cast<GroupElementPlaintext*>(plaintext);
	if (plain == NULL) {
		throw invalid_argument("plaintext should be an instance of GroupElementPlaintext");
	}
	auto el = plain->getElement();
	return dlog->decodeGroupElementToByteArray(el.get());
}

/**
* Calculates the ciphertext resulting of multiplying two given ciphertexts.
* Both ciphertexts have to have been generated with the same public key and DlogGroup as the underlying objects of this ElGamal object.
* @throws IllegalStateException if no public key was set.
* @throws IllegalArgumentException in the following cases:
* 		1. If one or more of the given ciphertexts is not instance of ElGamalOnGroupElementCiphertext.
* 		2. If one or more of the GroupElements in the given ciphertexts is not a member of the underlying DlogGroup of this ElGamal encryption scheme.
*/
shared_ptr<AsymmetricCiphertext> ElGamalOnGroupElementEnc::multiply(AsymmetricCiphertext* cipher1, AsymmetricCiphertext* cipher2) {

	//Choose a random value in Zq.
	biginteger w = getRandomInRange(0, qMinusOne, random.get());

	//Call the other function that computes the multiplication.
	return multiply(cipher1, cipher2, w);
}

/**
* Calculates the ciphertext resulting of multiplying two given ciphertexts.<P>
* Both ciphertexts have to have been generated with the same public key and DlogGroup as the underlying objects of this ElGamal object.<p>
*
* There are cases when the random value is used after the function, for example, in sigma protocol.
* In these cases the random value should be known to the user. We decided not to have function that return it to the user
* since this can cause problems when the multiply function is called more than one time.
* Instead, we decided to have an additional multiply function that gets the random value from the user.
*
* @throws IllegalStateException if no public key was set.
* @throws IllegalArgumentException in the following cases:
* 		1. If one or more of the given ciphertexts is not instance of ElGamalOnGroupElementCiphertext.
* 		2. If one or more of the GroupElements in the given ciphertexts is not a member of the underlying DlogGroup of this ElGamal encryption scheme.
*/
shared_ptr<AsymmetricCiphertext> ElGamalOnGroupElementEnc::multiply(AsymmetricCiphertext* cipher1, AsymmetricCiphertext* cipher2, biginteger & r) {
	/*
	* Pseudo-Code:
	* 	c1 = (u1, v1); c2 = (u2, v2)
	* 	COMPUTE u = g^w*u1*u2
	* 	COMPUTE v = h^w*v1*v2
	* 	OUTPUT c = (u,v)
	*/

	// If there is no public key can not encrypt, throws exception.
	if (!isKeySet()) {
		throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
	}

	auto c1 = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher1);
	auto c2 = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher2);

	// Cipher1 and cipher2 should be ElGamal ciphertexts.
	if (c1 == NULL || c2 == NULL) {
		throw invalid_argument("ciphertexts should be instance of ElGamalCiphertext");
	}
	
	//Gets the groupElements of the ciphers.
	auto u1 = c1->getC1().get();
	auto v1 = c1->getC2().get();
	auto u2 = c2->getC1().get();
	auto v2 = c2->getC2().get();

	if (!(dlog->isMember(u1)) || !(dlog->isMember(v1)) || !(dlog->isMember(u2)) || !(dlog->isMember(v2))) {
		throw invalid_argument("GroupElements in the given ciphertexts must be a members in the DlogGroup of type " + dlog->getGroupType());
	}

	//Check that the r random value passed to this function is in Zq.
	if (!((r >= 0) && (r <=qMinusOne))) {
		throw invalid_argument("the given random value must be in Zq");
	}

	//Calculates u = g^w*u1*u2.
	auto gExpW = dlog->exponentiate(dlog->getGenerator().get(), r);
	auto gExpWmultU1 = dlog->multiplyGroupElements(gExpW.get(), u1);
	auto u = dlog->multiplyGroupElements(gExpWmultU1.get(), u2);

	//Calculates v = h^w*v1*v2.
	auto hExpW = dlog->exponentiate(publicKey->getH().get(), r);
	auto hExpWmultV1 = dlog->multiplyGroupElements(hExpW.get(), v1);
	auto v = dlog->multiplyGroupElements(hExpWmultV1.get(), v2);

	return make_shared<ElGamalOnGroupElementCiphertext>(u, v);
}

shared_ptr<AsymmetricCiphertext> ElGamalOnGroupElementEnc::reconstructCiphertext(AsymmetricCiphertextSendableData* data) {
	auto data1 = dynamic_cast<ElGamalOnGrElSendableData*>(data);
	if (data1 == NULL)
		throw invalid_argument("The input data has to be of type ElGamalOnGrElSendableData");
	
	auto cipher1 = dlog->reconstructElement(true, data1->getCipher1().get());
	auto cipher2 = dlog->reconstructElement(true, data1->getCipher2().get());
	return make_shared<ElGamalOnGroupElementCiphertext>(cipher1, cipher2);
}

/**
* Completes the encryption operation.
* @param plaintext contains message to encrypt. MUST be of type ByteArrayPlaintext.
* @return Ciphertext of type ElGamalOnByteArrayCiphertext containing the encrypted message.
* @throws IllegalArgumentException if the given Plaintext is not an instance of ByteArrayPlaintext.
*/
shared_ptr<AsymmetricCiphertext> ElGamalOnByteArrayEnc::completeEncryption(const shared_ptr<GroupElement> & c1, GroupElement* hy, Plaintext* plaintext) {


	auto plain = dynamic_cast<ByteArrayPlaintext*>(plaintext);

	if (plain == NULL) {
		throw invalid_argument("plaintext should be instance of ByteArrayPlaintext");
	}

	//Gets the message.
	auto msg = plain->getText();
	int size = msg.size();
	auto hyBytes = dlog->mapAnyGroupElementToByteArray(hy);
	auto c2 = kdf->deriveKey(hyBytes, 0, hyBytes.size(), size).getEncoded();

	//Xores the result from the kdf with the plaintext.
	for (int i = 0; i<size; i++) {
		c2[i] = (byte)(c2[i] ^ msg[i]);
	}

	//Returns an ElGamalOnByteArrayCiphertext with c1, c2.
	return make_shared<ElGamalOnByteArrayCiphertext>(c1, c2);
}

/**
* Decrypts the given ciphertext using ElGamal encryption scheme.
*
* @param cipher MUST be of type ElGamalOnByteArrayCiphertext contains the cipher to decrypt.
* @return Plaintext of type ByteArrayPlaintext which containing the decrypted message.
* @throws KeyException if no private key was set.
* @throws IllegalArgumentException if the given cipher is not instance of ElGamalOnByteArrayCiphertext.
*/
shared_ptr<Plaintext> ElGamalOnByteArrayEnc::decrypt(AsymmetricCiphertext* cipher) {
	/*
	* Pseudo-code:
	* 		Calculate s = ciphertext.getC1() ^ x
	*		Calculate m = KDF(s) XOR ciphertext.getC2()
	*/

	//If there is no private key, throws exception.
	if (privateKey == NULL) {
		throw KeyException("in order to decrypt a message, this object must be initialized with private key");
	}

	auto ciphertext = dynamic_cast<ElGamalOnByteArrayCiphertext*>(cipher);
	//Ciphertext should be ElGamal ciphertext.
	if (ciphertext == NULL) {
		throw invalid_argument("ciphertext should be instance of ElGamalOnByteArrayCiphertext");
	}

	//Calculates s = ciphertext.getC1() ^ x.
	auto s = dlog->exponentiate(ciphertext->getC1().get(), privateKey->getX());
	auto sBytes = dlog->mapAnyGroupElementToByteArray(s.get());
	auto c2 = ciphertext->getC2();
	int len = c2.size();
	//Calculates the plaintext element m = KDF(s) ^ c2.
	auto m = kdf->deriveKey(sBytes, 0, sBytes.size(), len).getEncoded();

	//Xores the result from the kdf with the plaintext.
	for (int i = 0; i<len; i++) {
		m[i] = (byte)(m[i] ^ c2[i]);
	}

	//Creates a plaintext object with the element and returns it.
	return make_shared<ByteArrayPlaintext>(m);
}

/**
* Generates a byte array from the given plaintext.
* This function should be used when the user does not know the specific type of the Asymmetric encryption he has,
* and therefore he is working on byte array.
* @param plaintext to generates byte array from. MUST be an instance of ByteArrayPlaintext.
* @return the byte array generated from the given plaintext.
* @throws IllegalArgumentException if the given plaintext is not an instance of ByteArrayPlaintext.
*/
vector<byte> ElGamalOnByteArrayEnc::generateBytesFromPlaintext(Plaintext* plaintext) {
	auto plain = dynamic_cast<ByteArrayPlaintext*>(plaintext);
	if (plain == NULL) {
		throw invalid_argument("plaintext should be an instance of ByteArrayPlaintext");
	}

	return plain->getText();
}

/**
* @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
*/
shared_ptr<AsymmetricCiphertext> ElGamalOnByteArrayEnc::reconstructCiphertext(AsymmetricCiphertextSendableData* data) {
	auto data1 = dynamic_cast<ElGamalOnByteArraySendableData*>(data);
	if (data1 == NULL)
		throw invalid_argument("The input data has to be of type ElGamalOnByteArraySendableData");
	
	auto cipher1 = dlog->reconstructElement(true, data1->getCipher1().get());
	auto cipher2 = data1->getCipher2();
	return make_shared<ElGamalOnByteArrayCiphertext>(cipher1, cipher2);
}