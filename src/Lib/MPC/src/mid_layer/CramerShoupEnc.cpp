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


#include "../../include/mid_layer/CramerShoupEnc.hpp"

CramerShoupPublicKeySendableData::CramerShoupPublicKeySendableData(const shared_ptr<GroupElementSendableData> & c,
	const shared_ptr<GroupElementSendableData> & d, const shared_ptr<GroupElementSendableData> & h,
	const shared_ptr<GroupElementSendableData> & g1, const shared_ptr<GroupElementSendableData> & g2) {
	this->c = c;
	this->d = d;
	this->h = h;
	this->g1 = g1;
	this->g2 = g2;
}

string CramerShoupPublicKeySendableData::toString() {
	return c->toString() + ":" + d->toString() + ":" + h->toString() + ":" + g1->toString() + ":" + g2->toString();
}

void CramerShoupPublicKeySendableData::initFromString(const string & row) {
	auto str_vec = explode(row, ':');
	assert(str_vec.size() == 5);
	c->initFromString(str_vec[0]);
	d->initFromString(str_vec[1]);
	h->initFromString(str_vec[2]);
	g1->initFromString(str_vec[3]);
	g2->initFromString(str_vec[4]);
}

CramerShoupPublicKey::CramerShoupPublicKey(const shared_ptr<GroupElement> & c, const shared_ptr<GroupElement> & d, const shared_ptr<GroupElement> & h, 
	const shared_ptr<GroupElement> & g1, const shared_ptr<GroupElement> & g2) {
	this->c = c;
	this->d = d;
	this->h = h;
	this->g1 = g1;
	this->g2 = g2;
}

CramerShoupPrivateKey::CramerShoupPrivateKey(const biginteger & x1, const biginteger & x2, const biginteger & y1, const biginteger & y2, const biginteger & z) {
	this->x1 = x1;
	this->x2 = x2;
	this->y1 = y1;
	this->y2 = y2;
	this->z = z;
}

string CramerShoupPrivateKey::toString() {
	return x1.str() + ":" + x2.str() + ":" + y1.str() + ":" + y2.str() + ":" + z.str();
}

void CramerShoupPrivateKey::initFromString(const string & row) {
	auto str_vec = explode(row, ':');
	assert(str_vec.size() == 5);
	x1 = biginteger(str_vec[0]);
	x2 = biginteger(str_vec[1]);
	y1 = biginteger(str_vec[2]);
	y2 = biginteger(str_vec[3]);
	z = biginteger(str_vec[4]);
}

CrShOnGroupElSendableData::CrShOnGroupElSendableData(const shared_ptr<GroupElementSendableData> & u1,
        const shared_ptr<GroupElementSendableData> & u2,
	const shared_ptr<GroupElementSendableData> & v, const shared_ptr<GroupElementSendableData> & e) {
	this->u1 = u1;
	this->u2 = u2;
	this->v = v;
	this->e = e;
}

string CrShOnGroupElSendableData::toString() {
	return u1->toString() + ":" + u2->toString() + ":" + v->toString() + ":" + e->toString();
}

void CrShOnGroupElSendableData::initFromString(const string & row) {
	auto str_vec = explode(row, ':');
	assert(str_vec.size() == 4);
	u1->initFromString(str_vec[0]);
	u2->initFromString(str_vec[1]);
	v->initFromString(str_vec[2]);
	e->initFromString(str_vec[3]);
}

/**
* Constructor that lets the user choose the underlying dlog, hash and source of randomness.<p>
* The underlying Dlog group has to have DDH security level.<p>
* The underlying Hash function has to have CollisionResistant security level.
* @param dlogGroup underlying DlogGroup to use.
* @param hash underlying hash to use.
* @param random source of randomness.
* @throws SecurityLevelException if the Dlog Group or the Hash function do not meet the required Security Level
*/
CramerShoupOnGroupElementEnc::CramerShoupOnGroupElementEnc(const shared_ptr<DlogGroup> & dlogGroup, const shared_ptr<CryptographicHash> & hash, 
	const shared_ptr<PrgFromOpenSSLAES> & random) {
	//The Cramer-Shoup encryption scheme must work with a Dlog Group that has DDH security level
	//and a Hash function that has CollisionResistant security level. If any of this conditions is not 
	//met then cannot construct an object of type Cramer-Shoup encryption scheme; therefore throw exception.
	auto ddh = dynamic_pointer_cast<DDH>(dlogGroup);
	if (ddh == NULL) {
		throw SecurityLevelException("The Dlog group has to have DDH security level");
	}
	this->dlogGroup = dlogGroup;
	auto cr = dynamic_pointer_cast<CollisionResistant>(hash);
	if (cr == NULL) {
		throw SecurityLevelException("The hash function has to have CollisionResistant security level");
	}
	this->hash = hash;
	// Everything is correct, then sets the member variables and creates object.
	qMinusOne = dlogGroup->getOrder() - 1;
	this->random = random;
}

/**
* This function sets the Public\Private key.
* @param publicKey the public key has to be of type <link>CramerShoupPublicKey<link>.
* @param privateKey the private key has to be of type <link>CramerShoupPrivateKey<link>.
* @throws InvalidKeyException if the keys are not instances of CramerShoup keys.
*/
void CramerShoupOnGroupElementEnc::setKey(const shared_ptr<PublicKey> & publicKey, const shared_ptr<PrivateKey> & privateKey)  {
	this->publicKey = dynamic_pointer_cast<CramerShoupPublicKey>(publicKey);
	//Public key should be Cramer-Shoup public key.
	if (this->publicKey == NULL) {
		throw InvalidKeyException("The public key must be of type CramerShoupPublicKey");
	}
	
	//Private key should be Cramer Shoup private key.	
	if (privateKey != NULL) {
		auto key = dynamic_pointer_cast<CramerShoupPrivateKey>(privateKey);
		if (key == NULL) {
			throw InvalidKeyException("The private key must be of type CramerShoupPrivatKey");
		}
		//Gets the z value from the private key.
		biginteger z = key->getPrivateExp5();
		//Gets the q-z value.
		biginteger xInv = dlogGroup->getOrder() - z;
		//Sets the q-z value as the z in private key.
		this->privateKey = make_shared<CramerShoupPrivateKey>(key->getPrivateExp1(), key->getPrivateExp2(), key->getPrivateExp3(), key->getPrivateExp4(), xInv);
	}

	keySet = true;
}

/**
* Generates pair of CramerShoupPublicKey and CramerShoupPrivateKey.
* @return KeyPair holding the CramerShoup public and private keys
*/
pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>> CramerShoupOnGroupElementEnc::generateKey() {
	/*
	* 	Given a Dlog Group (G, q, g) do:
	Choose two distinct, random generators g1, g2. (how?)
	Choose five random values (x1, x2, y1, y2, z) in Zq.
	Compute c = g_1^(x1 ) g_2^(x2 ), d= g_1^(y1 ) g_2^(y2 ), h= g1^z.
	Set the public key part of the key pair to be c, d, h.
	Set the private key part of the key pair to be x1, x2, y1, y2, z.
	Return the key pair.
	*/
	shared_ptr<GroupElement> generator1, generator2;
	do {
		generator1 = dlogGroup->createRandomGenerator();
		generator2 = dlogGroup->createRandomGenerator();
	} while (*generator1 == *generator2);

	//Chooses five random values (x1, x2, y1, y2, z) in Zq.
	biginteger x1 = getRandomInRange(0, qMinusOne, random.get());
	biginteger x2 = getRandomInRange(0, qMinusOne, random.get());
	biginteger y1 = getRandomInRange(0, qMinusOne, random.get());
	biginteger y2 = getRandomInRange(0, qMinusOne, random.get());
	biginteger z = getRandomInRange(0, qMinusOne, random.get());


	//Calculates c, d and h:
	shared_ptr<GroupElement> c, d, h;

	c = dlogGroup->multiplyGroupElements(dlogGroup->exponentiate(generator1.get(), x1).get(), dlogGroup->exponentiate(generator2.get(), x2).get());
	d = dlogGroup->multiplyGroupElements(dlogGroup->exponentiate(generator1.get(), y1).get(), dlogGroup->exponentiate(generator2.get(), y2).get());
	h = dlogGroup->exponentiate(generator1.get(), z);
	
	auto publicKey = make_shared<CramerShoupPublicKey>(c, d, h, generator1, generator2);
	auto privateKey = make_shared<CramerShoupPrivateKey>(x1, x2, y1, y2, z);
	return pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>>(publicKey, privateKey);
}

shared_ptr<PrivateKey> CramerShoupOnGroupElementEnc::reconstructPrivateKey(KeySendableData* data) {
	auto data1 = dynamic_cast<CramerShoupPrivateKey*>(data);
	if (data1 == NULL)
		throw invalid_argument("To generate the key from sendable data, the data has to be of type CramerShoupPrivateKey");
	return make_shared<CramerShoupPrivateKey>(data1->getPrivateExp1(), data1->getPrivateExp2(), 
		data1->getPrivateExp3(), data1->getPrivateExp4(), data1->getPrivateExp5());
}

/**
* @data The KeySendableData object has to be of type ScCramerShoupPublicKeySendableData
*/
shared_ptr<PublicKey> CramerShoupOnGroupElementEnc::reconstructPublicKey(KeySendableData* data) {
	auto data1 = dynamic_cast<CramerShoupPublicKeySendableData*>(data);
	if (data1 == NULL)
		throw invalid_argument("To generate the key from sendable data, the data has to be of type ScCramerShoupPublicKeySendableData");
	
	auto c = dlogGroup->reconstructElement(true, data1->getC().get());
	auto d = dlogGroup->reconstructElement(true, data1->getD().get());
	auto h = dlogGroup->reconstructElement(true, data1->getH().get());
	auto g1 = dlogGroup->reconstructElement(true, data1->getG1().get());
	auto g2 = dlogGroup->reconstructElement(true, data1->getG2().get());

	return make_shared<CramerShoupPublicKey>(c, d, h, g1, g2);
}

/**
* Encrypts the given plaintext using this Cramer Shoup encryption scheme.
* @param plaintext message to encrypt. MUST be an instance of GroupElementPlaintext.
* @return Ciphertext the encrypted plaintext.
* @throws IllegalStateException if no public key was set.
* @throws IllegalArgumentException if the given Plaintext is not instance of GroupElementPlaintext.
*/
shared_ptr<AsymmetricCiphertext> CramerShoupOnGroupElementEnc::encrypt(const shared_ptr<Plaintext> & plaintext)  {
	// If there is no public key can not encrypt, throws exception.
	if (!isKeySet()) {
		throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
	}
	/*
	* 	Choose a random  r in Zq
	*	Calculate 	u1 = g1^r
	*         		u2 = g2^r
	*         		e = (h^r)*msgEl
	*	Convert u1, u2, e to byte[] using the dlogGroup
	*	Compute alpha  - the result of computing the hash function on the concatenation u1+ u2+ e.
	*	Calculate v = c^r * d^(r*alpha)
	*	Create and return an CramerShoupCiphertext object with u1, u2, e and v.
	*/

	//Choose the random r.
	biginteger r = getRandomInRange(0, qMinusOne, random.get());

	return encrypt(plaintext, r);
}

shared_ptr<AsymmetricCiphertext> CramerShoupOnGroupElementEnc::encrypt(const shared_ptr<Plaintext> & plaintext, const biginteger & r) {
	/*
	* 	Choose a random  r in Zq
	*	Calculate 	u1 = g1^r
	*         		u2 = g2^r
	*         		e = (h^r)*msgEl
	*	Convert u1, u2, e to byte[] using the dlogGroup
	*	Compute alpha  - the result of computing the hash function on the concatenation u1+ u2+ e.
	*	Calculate v = c^r * d^(r*alpha)
	*	Create and return an CramerShoupCiphertext object with u1, u2, e and v.
	*/
	if (!isKeySet()) {
		throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
	}
	auto plain = dynamic_pointer_cast<GroupElementPlaintext>(plaintext);
	if (plain == NULL) {
		throw invalid_argument("plaintext should be instance of GroupElementPlaintext");
	}
	auto msgElement = plain->getElement();

	//Check that the random value passed to this function is in Zq.
	if (!((r >= 0) && (r <= qMinusOne))) {
		throw invalid_argument("r must be in Zq");
	}

	auto u1 = dlogGroup->exponentiate(publicKey->getGenerator1().get(), r);
	auto u2 = dlogGroup->exponentiate(publicKey->getGenerator2().get(), r);
	auto hExpr = dlogGroup->exponentiate(publicKey->getH().get(), r);
	auto e = dlogGroup->multiplyGroupElements(hExpr.get(), msgElement.get());

	auto u1ToByteArray = dlogGroup->mapAnyGroupElementToByteArray(u1.get());
	auto u2ToByteArray = dlogGroup->mapAnyGroupElementToByteArray(u2.get());
	auto eToByteArray = dlogGroup->mapAnyGroupElementToByteArray(e.get());
	
	//Calculates the hash(u1 + u2 + e).
	auto alpha = calcAlpha(u1ToByteArray, u2ToByteArray, eToByteArray);
	
	//Calculates v = c^r * d^(r*alpha).
	auto v = calcV(r, alpha);
	
	//Creates and return an CramerShoupCiphertext object with u1, u2, e and v.
	return make_shared<CramerShoupOnGroupElementCiphertext>(u1, u2, e, v);
}

/**
* calculate the v value of the encryption.
* v = c^r * d^(r*alpha).
* @param r a random value
* @param alpha the value returned from the hash calculation.
* @return the calculated value v.
*/
shared_ptr<GroupElement> CramerShoupOnGroupElementEnc::calcV(const biginteger & r, vector<byte> & alpha) {
	auto cExpr = dlogGroup->exponentiate(publicKey->getC().get(), r);
	biginteger rAlphaModQ = (r * decodeBigInteger(alpha.data(), alpha.size())) % dlogGroup->getOrder();
	auto dExpRAlpha = dlogGroup->exponentiate(publicKey->getD().get(), rAlphaModQ);
	return dlogGroup->multiplyGroupElements(cExpr.get(), dExpRAlpha.get());
}

/**
* Recieves three byte arrays and calculates the hash function on their concatenation.
* @param u1ToByteArray
* @param u2ToByteArray
* @param eToByteArray
* @return the result of hash(u1ToByteArray+u2ToByteArray+eToByteArray)
*/
vector<byte> CramerShoupOnGroupElementEnc::calcAlpha(vector<byte> & u1ToByteArray, vector<byte> & u2ToByteArray, vector<byte> & eToByteArray) {
	//Concatenates u1, u2 and e into u1.
	u1ToByteArray.insert(u1ToByteArray.end(), u2ToByteArray.begin(), u2ToByteArray.end());
	u1ToByteArray.insert(u1ToByteArray.end(), eToByteArray.begin(), eToByteArray.end());

	//Calculates the hash of msgToHash.
	
	//Calls the update function in the Hash interface.
	hash->update(u1ToByteArray, 0, u1ToByteArray.size());

	//Gets the result of hashing the updated input.
	vector<byte> alpha;
	hash->hashFinal(alpha, 0);
	return alpha;
}

/**
* Generates a Plaintext suitable to CramerShoup encryption scheme from the given message.
* @param text byte array to convert to a Plaintext object.
* @throws IllegalArgumentException if the given message's length is greater than the maximum.
*/
shared_ptr<Plaintext> CramerShoupOnGroupElementEnc::generatePlaintext(vector<byte> & text) {
	if ((int) text.size() > getMaxLengthOfByteArrayForPlaintext()) {
		throw invalid_argument("the given text is too big for plaintext");
	}

	return make_shared<GroupElementPlaintext>(dlogGroup->encodeByteArrayToGroupElement(text));
}

/**
* Decrypts the given ciphertext using this Cramer-Shoup encryption scheme.
* @param ciphertext ciphertext to decrypt. MUST be an instance of CramerShoupCiphertext.
* @return Plaintext the decrypted cipher.
* @throws KeyException if no private key was set.
* @throws IllegalArgumentException if the given Ciphertext is not instance of CramerShoupCiphertext.
*/
shared_ptr<Plaintext> CramerShoupOnGroupElementEnc::decrypt(AsymmetricCiphertext* cipher) {
	/*
	If cipher is not instance of CramerShoupCiphertext, throw IllegalArgumentException.
	If private key is null, then cannot decrypt. Throw exception.
	Convert u1, u2, e to byte[] using the dlogGroup
	Compute alpha - the result of computing the hash function on the concatenation u1+ u2+ e.
	if u_1^(x1+y1*alpha) * u_2^(x2+y2*alpha) != v throw exception
	Calculate m = e*((u1^z)^-1)   // equal to m = e/u1^z . We don't have a divide operation in DlogGroup so we calculate it in equivalent way
	m is a groupElement. Use it to create and return msg an instance of GroupElementPlaintext.
	return msg
	*/
	//If there is no private key, throws exception.
	if (privateKey == NULL) {
		throw KeyException("in order to decrypt a message, this object must be initialized with private key");
	}
	//Ciphertext should be Cramer Shoup ciphertext.
	auto ciphertext = dynamic_cast<CramerShoupOnGroupElementCiphertext*>(cipher);
	if (ciphertext == NULL) {
		throw invalid_argument("ciphertext should be instance of CramerShoupCiphertext");
	}

	//Converts the u1, u2 and e elements to byte[].
	auto u1 = dlogGroup->mapAnyGroupElementToByteArray(ciphertext->getU1().get());
	auto u2 = dlogGroup->mapAnyGroupElementToByteArray(ciphertext->getU2().get());
	auto e = dlogGroup->mapAnyGroupElementToByteArray(ciphertext->getE().get());
	
	//Calculates the hash(u1 + u2 + e).
	auto alpha = calcAlpha(u1, u2, e);
	
	checkValidity(ciphertext, alpha);

	//Calculates m = e*((u1^z)^ -1). 
	//Instead of calculating (u1^z)^-1, we use the optimization that was calculated in initPrivateKey function and calculate u1^zInv.
	auto U1ExpInvZ = dlogGroup->exponentiate(ciphertext->getU1().get(), privateKey->getPrivateExp5());
	auto m = dlogGroup->multiplyGroupElements(ciphertext->getE().get(), U1ExpInvZ.get());

	//Creates a plaintext object with the group element and return it.
	return make_shared<GroupElementPlaintext>(m);
}

/**
* This function is called from the decrypt function. It Validates that the given cipher is correct.
* If the function find that the cipher is not valid, it throws a ScapiRuntimeException.
* @param cipher to validate.
* @param alpha parameter needs to validation.
* @throws ScapiRuntimeException if the given cipher is not valid.
*/
void CramerShoupOnGroupElementEnc::checkValidity(CramerShoupOnGroupElementCiphertext* cipher, vector<byte> & alpha) {

	//Calculates u1^(x1+y1*alpha).
	biginteger alphaBI = mp::abs(decodeBigInteger(alpha.data(), alpha.size()));
	biginteger exponent1 = (privateKey->getPrivateExp1() + (privateKey->getPrivateExp3() * alphaBI)) % dlogGroup->getOrder();
	auto t1 = dlogGroup->exponentiate(cipher->getU1().get(), exponent1);
	//Calculates u2^(x2+y2*alpha).
	biginteger exponent2 = (privateKey->getPrivateExp2() + (privateKey->getPrivateExp4() * alphaBI)) % dlogGroup->getOrder();
	auto t2 = dlogGroup->exponentiate(cipher->getU2().get(), exponent2);

	//Verifies that their multiplication is equal to v. If not, throws exception.
	auto mult = dlogGroup->multiplyGroupElements(t1.get(), t2.get());
	if (*mult != *cipher->getV()) {
		throw runtime_error("Error! Cannot proceed with decryption");
	}
}

/**
* Generates a byte array from the given plaintext.
* This function should be used when the user does not know the specific type of the Asymmetric encryption he has,
* and therefore he is working on byte array.
* @param plaintext to generates byte array from. MUST be an instance of GroupElementPlaintext.
* @return the byte array generated from the given plaintext.
* @throws IllegalArgumentException if the given plaintext is not an instance of GroupElementPlaintext.
*/
vector<byte> CramerShoupOnGroupElementEnc::generateBytesFromPlaintext(Plaintext* plaintext) {
	auto plain = dynamic_cast<GroupElementPlaintext*>(plaintext);
	if (plain == NULL) {
		throw invalid_argument("plaintext should be an instance of GroupElementPlaintext");
	}
	auto el = plain->getElement();
	return dlogGroup->decodeGroupElementToByteArray(el.get());
}

shared_ptr<AsymmetricCiphertext> CramerShoupOnGroupElementEnc::reconstructCiphertext(AsymmetricCiphertextSendableData* data){
	
	auto data1 = dynamic_cast<CrShOnGroupElSendableData*>(data);
	if (data1 == NULL)
		throw invalid_argument("The input data has to be of type CrShOnGroupElSendableData");
	
	auto u1 = dlogGroup->reconstructElement(true, data1->getU1().get());
	auto u2 = dlogGroup->reconstructElement(true, data1->getU2().get());
	auto v = dlogGroup->reconstructElement(true, data1->getV().get());
	auto e = dlogGroup->reconstructElement(true, data1->getE().get());

	return make_shared<CramerShoupOnGroupElementCiphertext>(u1, u2, v, e);
}