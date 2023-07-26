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
#include "AsymmetricEnc.hpp"
#include "../infra/Common.hpp"
#include "../cryptoInfra/SecurityLevel.hpp"
#include "../primitives/Dlog.hpp"
#include "../primitives/DlogOpenSSL.hpp"
#include "../primitives/Dlog.hpp"
#include "../primitives/Hash.hpp"
#include "../primitives/HashOpenSSL.hpp"

//Nested class that holds the sendable data of the outer class.
class CramerShoupPublicKeySendableData : public KeySendableData {

private:
	shared_ptr<GroupElementSendableData> c;
	shared_ptr<GroupElementSendableData> d;
	shared_ptr<GroupElementSendableData> h;
	shared_ptr<GroupElementSendableData> g1;
	shared_ptr<GroupElementSendableData> g2;

public:
	CramerShoupPublicKeySendableData(const shared_ptr<GroupElementSendableData> & c,
		const shared_ptr<GroupElementSendableData> & d, const shared_ptr<GroupElementSendableData> & h,
		const shared_ptr<GroupElementSendableData> & g1, const shared_ptr<GroupElementSendableData> & g2);

	shared_ptr<GroupElementSendableData> getC() { return c;	}

	shared_ptr<GroupElementSendableData> getD() { return d;	}

	shared_ptr<GroupElementSendableData> getH() { return h;	}

	shared_ptr<GroupElementSendableData> getG1() { return g1; }

	shared_ptr<GroupElementSendableData> getG2() { return g2; }

	string toString() override;
	
	void initFromString(const string & row) override;
};

/**
* This class represents a Public Key suitable for the Cramer Shoup Encryption Scheme. 
* Although the constructor is public, it should only be instantiated by the Encryption Scheme itself via the generateKey function.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CramerShoupPublicKey : public PublicKey {

private: 
	shared_ptr<GroupElement> c;
	shared_ptr<GroupElement> d;
	shared_ptr<GroupElement> h;
	shared_ptr<GroupElement> g1;
	shared_ptr<GroupElement> g2;

public:
	/**
	* This constructor is used by the Encryption Scheme as a result of a call to function generateKey.
	*/
	CramerShoupPublicKey(const shared_ptr<GroupElement> & c, const shared_ptr<GroupElement> & d, const shared_ptr<GroupElement> & h, 
		const shared_ptr<GroupElement> & g1, const shared_ptr<GroupElement> & g2);

	string getAlgorithm() override { return "CramerShoup"; }

	vector<byte> getEncoded() override { throw UnsupportedOperationException("cannot decode a group element to byte array"); }

	shared_ptr<GroupElement> getC() { return c;	}

	shared_ptr<GroupElement> getD() { return d;	}

	shared_ptr<GroupElement> getH() { return h;	}

	shared_ptr<GroupElement> getGenerator1() { return g1; }

	shared_ptr<GroupElement> getGenerator2() { return g2; }

	shared_ptr<KeySendableData> generateSendableData() {
		return make_shared<CramerShoupPublicKeySendableData>(c->generateSendableData(), d->generateSendableData(), h->generateSendableData(), g1->generateSendableData(), g2->generateSendableData());
	}
};

/**
* This class represents a Private Key suitable for the Cramer Shoup Encryption Scheme. 
* Although the constructor is public, it should only be instantiated by the Encryption Scheme itself via the generateKey function.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CramerShoupPrivateKey : public PrivateKey, KeySendableData {

private:
	biginteger x1;
	biginteger x2;
	biginteger y1;
	biginteger y2;
	biginteger z;

public:
	CramerShoupPrivateKey(const biginteger & x1, const biginteger & x2, const biginteger & y1, const biginteger & y2, const biginteger & z);

	string getAlgorithm() override { return "CramerShoup"; }

	vector<byte> getEncoded() { throw NotImplementedException(""); }
 
	biginteger getPrivateExp1() { return x1; }

	biginteger getPrivateExp2() { return x2; }

	biginteger getPrivateExp3() { return y1; }

	biginteger getPrivateExp4() { return y2; }

	biginteger getPrivateExp5() { return z; }

	string toString() override;

	void initFromString(const string & row) override;
};

class CrShOnGroupElSendableData : public AsymmetricCiphertextSendableData {

private:
	shared_ptr<GroupElementSendableData> u1;
	shared_ptr<GroupElementSendableData> u2;
	shared_ptr<GroupElementSendableData> v;
	shared_ptr<GroupElementSendableData> e;
	
public:
	CrShOnGroupElSendableData(const shared_ptr<GroupElementSendableData> & u1, const shared_ptr<GroupElementSendableData> & u2,
		const shared_ptr<GroupElementSendableData> & v, const shared_ptr<GroupElementSendableData> & e);

	shared_ptr<GroupElementSendableData> getE() { return e; }

	shared_ptr<GroupElementSendableData> getU1() { return u1; }

	shared_ptr<GroupElementSendableData> getU2() { return u2; }

	shared_ptr<GroupElementSendableData> getV() { return v; }

	string toString() override;

	void initFromString(const string & row) override;

};

/**
* This class is a container that encapsulates the cipher data resulting from applying the CramerShoupDDHOnGroupElement encryption.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CramerShoupOnGroupElementCiphertext : public AsymmetricCiphertext {

private:
	shared_ptr<GroupElement> u1;
	shared_ptr<GroupElement> u2;
	shared_ptr<GroupElement> v;
	shared_ptr<GroupElement> e;

public:
	CramerShoupOnGroupElementCiphertext(const shared_ptr<GroupElement> & u1, const shared_ptr<GroupElement> & u2, 
		const shared_ptr<GroupElement> & e, const shared_ptr<GroupElement> & v) {
		this->u1 = u1;
		this->u2 = u2;
		this->v = v;
		this->e = e;
	}

	shared_ptr<GroupElement> getU1() { return u1; }

	shared_ptr<GroupElement> getU2() { return u2; }

	shared_ptr<GroupElement> getV() { return v;	}

	shared_ptr<GroupElement> getE() { return e;	}

	shared_ptr<AsymmetricCiphertextSendableData> generateSendableData() override {
		return make_shared<CrShOnGroupElSendableData>(u1->generateSendableData(), u2->generateSendableData(), v->generateSendableData(), e->generateSendableData());
	}

	bool operator==(const AsymmetricCiphertext &other) const override {
		auto temp = dynamic_cast<const CramerShoupOnGroupElementCiphertext*>(&other);
		if (*u1 != *(temp->u1))
			return false;

		if (*u2 != *(temp->u2))
			return false;

		if (*v != *(temp->v))
			return false;

		return *e == *(temp->e);
	}

};

/**
* Concrete class that implement Cramer-Shoup encryption scheme.
* By definition, this encryption scheme is CCA-secure and NonMalleable.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CramerShoupOnGroupElementEnc :public AsymmetricEnc, Cca2 {
private:

	shared_ptr<DlogGroup> dlogGroup;				// Underlying DlogGroup.
	shared_ptr<CryptographicHash> hash;				// Underlying hash function.
	shared_ptr<CramerShoupPublicKey> publicKey;
	shared_ptr<CramerShoupPrivateKey> privateKey;
	shared_ptr<PrgFromOpenSSLAES> random;
	biginteger qMinusOne; 							// Saved to avoid many calculations.
	bool keySet;

 
	/**
	* Recieves three byte arrays and calculates the hash function on their concatenation.
	* @return the result of hash(u1ToByteArray+u2ToByteArray+eToByteArray)
	*/
	vector<byte> calcAlpha(vector<byte> & u1ToByteArray, vector<byte> & u2ToByteArray, vector<byte> & eToByteArray);

	/**
	* calculate the v value of the encryption.
	* v = c^r * d^(r*alpha).
	* @param r a random value
	* @param alpha the value returned from the hash calculation.
	* @return the calculated value v.
	*/
	shared_ptr<GroupElement> calcV(const biginteger & r, vector<byte> & alpha);

	/**
	* This function is called from the decrypt function. It Validates that the given cipher is correct.
	* If the function find that the cipher is not valid, it throws a ScapiRuntimeException.
	* @param cipher to validate.
	* @param alpha parameter needs to validation.
	* @throws runtime_error if the given cipher is not valid.
	*/
	void checkValidity(CramerShoupOnGroupElementCiphertext* cipher, vector<byte> & alpha);
 
public:
	/**
	* Constructor that lets the user choose the underlying dlog, hash and source of randomness.
	* The underlying Dlog group has to have DDH security level.<p>
	* The underlying Hash function has to have CollisionResistant security level.
	* @param dlogGroup underlying DlogGroup to use.
	* @param hash underlying hash to use.
	* @param random source of randomness.
	* @throws SecurityLevelException if the Dlog Group or the Hash function do not meet the required Security Level
	*/
	CramerShoupOnGroupElementEnc(const shared_ptr<DlogGroup> & dlogGroup = make_shared<OpenSSLDlogZpSafePrime>("1024"), 
		const shared_ptr<CryptographicHash> & hash = make_shared<OpenSSLSHA256>(), const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* This function sets the Public\Private key.
	* @param publicKey the public key has to be of type CramerShoupPublicKey.
	* @param privateKey the private key has to be of type CramerShoupPrivateKey.
	* @throws InvalidKeyException if the keys are not instances of CramerShoup keys.
	*/
	void setKey(const shared_ptr<PublicKey> & publicKey, const shared_ptr<PrivateKey> & privateKey) override;

	/**
	* This function sets only the Public key.
	* Setting only the public key the user can encrypt messages but can not decrypt messages.
	* @param publicKey the public key has to be of type CramerShoupPublicKey.
	* @throws InvalidKeyException if the key is not instance of CramerShoup key.
	*/
	void setKey(const shared_ptr<PublicKey> & publicKey) override { setKey(publicKey, NULL); }

	bool isKeySet() override { return keySet; }

	/**
	* Returns the PublicKey of this CramerShoup encryption scheme.
	* This function should not be used to check if the key has been set.
	* To check if the key has been set use isKeySet function.
	* @return the CramerShoupPublicKey
	* @throws IllegalStateException if no public key was set.
	*/
	shared_ptr<PublicKey> getPublicKey() override {
		if (!isKeySet()) {
			throw new IllegalStateException("no PublicKey was set");
		}

		return publicKey;
	}

	/**
	* @return the name of this AsymmetricEnc - CramerShoup and the underlying DlogGroup it uses.
	*/
	string getAlgorithmName() override { return "CramerShoup/" + dlogGroup->getGroupType(); }

	/**
	* Generates pair of CramerShoupPublicKey and CramerShoupPrivateKey.
	* @return KeyPair holding the CramerShoup public and private keys
	*/
	pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>> generateKey() override; 

	/**
	* This function is not supported for this encryption scheme, since there is no need for parameters to generate a CramerShoup key pair.
	* @throws UnsupportedOperationException
	*/
	pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>> generateKey(AlgorithmParameterSpec * keyParams) override {
		//No need for parameters to generate an Cramer-Shoup key pair. Therefore this operation is not supported.
		throw UnsupportedOperationException("To generate Cramer-Shoup keys use the generateKey() function");
	}

	/**
	* @data The KeySendableData object has to be of type CramerShoupPrivateKey
	*/
	shared_ptr<PrivateKey> reconstructPrivateKey(KeySendableData* data) override;

	/**
	* @data The KeySendableData object has to be of type CramerShoupPublicKeySendableData
	*/
	shared_ptr<PublicKey> reconstructPublicKey(KeySendableData* data) override;

	/**
	* Encrypts the given plaintext using this Cramer Shoup encryption scheme.
	* @param plaintext message to encrypt. MUST be an instance of GroupElementPlaintext.
	* @return Ciphertext the encrypted plaintext.
	* @throws IllegalStateException if no public key was set.
	* @throws invalid_argument if the given Plaintext is not instance of GroupElementPlaintext.
	*/
	shared_ptr<AsymmetricCiphertext> encrypt(const shared_ptr<Plaintext> & plaintext) override; 

	/**
	* Encrypts the given plaintext using this CramerShoup encryption scheme and using the given random value.
	* There are cases when the random value is used after the encryption, for example, in sigma protocol.
	* In these cases the random value should be known to the user. We decided not to have function that return it to the user
	* since this can cause problems when more than one value is being encrypt.
	* Instead, we decided to have an additional encrypt value that gets the random value from the user.
	* @param r The random value to use in the encryption.
	* @param plaintext message to encrypt. MUST be an instance of GroupElementPlaintext.
	* @return Ciphertext the encrypted plaintext.
	* @throws IllegalStateException if no public key was set.
	* @throws invalid_argument if the given Plaintext is not instance of GroupElementPlaintext.
	*/
	shared_ptr<AsymmetricCiphertext> encrypt(const shared_ptr<Plaintext> & plaintext, const biginteger & r) override; 

	/**
	* Cramer-Shoup on GroupElement encryption scheme has a limit of the byte array length to generate a plaintext from.
	* @return true.
	*/
	bool hasMaxByteArrayLengthForPlaintext() override { return true; }

	/**
	* Returns the maximum size of the byte array that can be passed to generatePlaintext function.
	* This is the maximum size of a byte array that can be converted to a Plaintext object suitable to this encryption scheme.
	*/
	int getMaxLengthOfByteArrayForPlaintext() override { return dlogGroup->getMaxLengthOfByteArrayForEncoding(); }

	/**
	* Generates a Plaintext suitable to CramerShoup encryption scheme from the given message.
	* @param text byte array to convert to a Plaintext object.
	* @throws invalid_argument if the given message's length is greater than the maximum.
	*/
	shared_ptr<Plaintext> generatePlaintext(vector<byte> & text) override; 

	/**
	* Decrypts the given ciphertext using this Cramer-Shoup encryption scheme.
	* @param ciphertext ciphertext to decrypt. MUST be an instance of CramerShoupCiphertext.
	* @return Plaintext the decrypted cipher.
	* @throws KeyException if no private key was set.
	* @throws invalid_argument if the given Ciphertext is not instance of CramerShoupCiphertext.
	*/
	shared_ptr<Plaintext> decrypt(AsymmetricCiphertext* cipher) override; 

	/**
	* Generates a byte array from the given plaintext.
	* This function should be used when the user does not know the specific type of the Asymmetric encryption he has,
	* and therefore he is working on byte array.
	* @param plaintext to generates byte array from. MUST be an instance of GroupElementPlaintext.
	* @return the byte array generated from the given plaintext.
	* @throws invalid_argument if the given plaintext is not an instance of GroupElementPlaintext.
	*/
	vector<byte> generateBytesFromPlaintext(Plaintext* plaintext) override;

	/**
	* @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
	*/
	shared_ptr<AsymmetricCiphertext> reconstructCiphertext(AsymmetricCiphertextSendableData* data) override; 
};
