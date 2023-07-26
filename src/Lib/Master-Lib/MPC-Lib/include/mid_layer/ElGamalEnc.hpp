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
#include "../primitives/Dlog.hpp"
#include "../primitives/DlogOpenSSL.hpp"
#include "../primitives/Kdf.hpp"
#include "../primitives/PrfOpenSSL.hpp"

class ElGamalPublicKeySendableData : public KeySendableData {
private:
	shared_ptr<GroupElementSendableData> c;

public:
	ElGamalPublicKeySendableData(const shared_ptr<GroupElementSendableData> & c) {
		this->c = c;
	}

	shared_ptr<GroupElementSendableData> getC() { return c; }

	string toString() override { return c->toString(); }
	void initFromString(const string & raw) override { c->initFromString(raw); }
};

/**
* This class represents a Public Key suitable for the El Gamal Encryption Scheme. 
* Although the constructor is public, it should only be instantiated by the Encryption Scheme itself via the generateKey function.
*
*/
class ElGamalPublicKey : public PublicKey {

private:
	shared_ptr<GroupElement> h;

public:
	ElGamalPublicKey(const shared_ptr<GroupElement> & h) {
		this->h = h;
	}

	shared_ptr<GroupElement> getH() { return h; }

	shared_ptr<KeySendableData> generateSendableData() {
		return make_shared<ElGamalPublicKeySendableData>(h->generateSendableData());
	}
	string getAlgorithm() override { return "ElGamal"; }
	vector<byte> getEncoded() override { throw UnsupportedOperationException("cannot decode a group element to byte array"); }
};

/**
* This class represents a Private Key suitable for the El Gamal Encryption Scheme. 
* Although the constructor is public, it should only be instantiated by the Encryption Scheme itself via the generateKey function.
*
*/
class ElGamalPrivateKey : public PrivateKey, KeySendableData {

private:
	biginteger x;

public:
	ElGamalPrivateKey(const biginteger & x) { this->x = x; }

	biginteger getX() {	return x; }

	string toString() override { return x.str(); }
	void initFromString(const string & row) override {	x = biginteger(row); }
	string getAlgorithm() override { return "ElGamal"; }
	vector<byte> getEncoded() override { throw NotImplementedException(""); }
};

//Holds the sendable data of ElGamalOnGroupElementCiphertext class.
class ElGamalOnGrElSendableData : public AsymmetricCiphertextSendableData {

private:
	shared_ptr<GroupElementSendableData> cipher1;
	shared_ptr<GroupElementSendableData> cipher2;

public:
	ElGamalOnGrElSendableData(const shared_ptr<GroupElementSendableData> & cipher1,
		const shared_ptr<GroupElementSendableData> & cipher2) {
		this->cipher1 = cipher1;
		this->cipher2 = cipher2;
	}
	shared_ptr<GroupElementSendableData> getCipher1() { return cipher1; }
	shared_ptr<GroupElementSendableData> getCipher2() { return cipher2; }
	string toString() override { return cipher1->toString() + ":" + cipher2->toString(); }
	void initFromString(const string & row) override;
};

/**
* This class is a container that encapsulates the cipher data resulting from applying the ElGamalOnGroupElement encryption.
*
*/
class ElGamalOnGroupElementCiphertext : public AsymmetricCiphertext {
private:
	//First part of the ciphertext.
	shared_ptr<GroupElement> cipher1;
	//Second part of the ciphertext.
	shared_ptr<GroupElement> cipher2;

public:
	/**
	* Create an instance of this container class.
	* This constructor is used by the Encryption Scheme as a result of a call to function encrypt.
	* @param c1 the first part of the cihertext
	* @param c2 the second part of the ciphertext
	*/
	ElGamalOnGroupElementCiphertext(const shared_ptr<GroupElement> & c1, const shared_ptr<GroupElement> & c2) {
		this->cipher1 = c1;
		this->cipher2 = c2;
	}

	/**
	*
	* @return the first part of the ciphertext
	*/
	shared_ptr<GroupElement> getC1() { return cipher1; }

	/**
	*
	* @return the second part of the ciphertext
	*/
	shared_ptr<GroupElement> getC2() { return cipher2; }

	shared_ptr<AsymmetricCiphertextSendableData> generateSendableData() override {
		return make_shared<ElGamalOnGrElSendableData>(cipher1->generateSendableData(), cipher2->generateSendableData());
	}

	bool operator==(const AsymmetricCiphertext &other) const override {
		auto temp = dynamic_cast<const ElGamalOnGroupElementCiphertext*>(&other);
		if (*cipher1 != *(temp->cipher1)) 
			return false;
		
		return *cipher2 == *(temp->cipher2);
	}
};

//Holds the sendable data of ElGamalOnByteArrayCiphertext class.
class ElGamalOnByteArraySendableData : public AsymmetricCiphertextSendableData {

private:
	//First part of the ciphertext.
	shared_ptr<GroupElementSendableData> cipher1;
	//Second part of the ciphertext.
	vector<byte> cipher2;

public:
	ElGamalOnByteArraySendableData(const shared_ptr<GroupElementSendableData> & cipher1, vector<byte> & cipher2) {
		this->cipher1 = cipher1;
		this->cipher2 = cipher2;
	}

	shared_ptr<GroupElementSendableData> getCipher1() {	return cipher1;	}

	vector<byte> getCipher2() { return cipher2; }

	string toString() override;
	void initFromString(const string & row) override;
};

/**
* This class is a container that encapsulates the cipher data resulting from applying the ElGamalOnByteArray encryption.
*
*/
class ElGamalOnByteArrayCiphertext : public AsymmetricCiphertext {

private:
	//First part of the ciphertext.
	shared_ptr<GroupElement> cipher1;
	//Second part of the ciphertext.
	vector<byte> cipher2;

public:
	/**
	* Create an instance of this container class.
	* This constructor is used by the Encryption Scheme as a result of a call to function encrypt.
	* @param c1 the first part of the cihertext
	* @param c2 the second part of the ciphertext
	*/
	ElGamalOnByteArrayCiphertext(const shared_ptr<GroupElement> & c1, vector<byte> & c2) {
		cipher1 = c1;
		cipher2 = c2;
	}

	/**
	* @return the first part of the ciphertext
	*/
	shared_ptr<GroupElement> getC1() { return cipher1; }

	/**
	* @return the second part of the ciphertext
	*/
	vector<byte> getC2() { return cipher2; }

	shared_ptr<AsymmetricCiphertextSendableData> generateSendableData() override {
		return make_shared<ElGamalOnByteArraySendableData>(cipher1->generateSendableData(), cipher2);
	}

	bool operator==(const AsymmetricCiphertext &other) const override {
		auto obj = dynamic_cast<const ElGamalOnByteArrayCiphertext*>(&other);
		if (this == obj)
			return true;
		if (obj == NULL)
			return false;
		if (*cipher1 != *obj->cipher1) {
				return false;
		}
		return cipher2 == obj->cipher2;
	}
};


/**
* Abstract class that implements some common functionality to all ElGamal types.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class ElGamalEnc : public AsymmetricEnc {
private:
	bool keySet;
protected:
	shared_ptr<DlogGroup> dlog;						//The underlying DlogGroup
	shared_ptr<ElGamalPrivateKey> privateKey;		//ElGamal private key (contains x)
	shared_ptr<ElGamalPublicKey> publicKey;			//ElGamal public key (contains h)
	shared_ptr<PrgFromOpenSSLAES> random;			//Source of randomness
	biginteger qMinusOne;							//We keep this value to save unnecessary calculations.

	void setMembers(const shared_ptr<DlogGroup> & dlogGroup, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	virtual void initPrivateKey(const shared_ptr<ElGamalPrivateKey> & privateKey) = 0;
	
	virtual shared_ptr<AsymmetricCiphertext> completeEncryption(const shared_ptr<GroupElement> & c1, GroupElement* hy, Plaintext* plaintext) = 0;
	
public:
	/**
	* Default constructor. Uses the default implementations of DlogGroup and SecureRandom.
	*/
	ElGamalEnc();

	/**
	* Constructor that gets a DlogGroup and sets it to the underlying group.
	* It lets SCAPI choose and source of randomness.
	* @param dlogGroup underlying DlogGroup to use, it has to have DDH security level
	* @throws SecurityLevelException if the Dlog Group is not DDH secure
	*/
	ElGamalEnc(const shared_ptr<DlogGroup> & dlogGroup, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) {
		setMembers(dlogGroup, random);
	}

	/**
	* Initializes this ElGamal encryption scheme with (public, private) key pair.
	* After this initialization the user can encrypt and decrypt messages.
	* @param publicKey should be ElGamalPublicKey.
	* @param privateKey should be ElGamalPrivateKey.
	* @throws InvalidKeyException if the given keys are not instances of ElGamal keys.
	*/
	void setKey(const shared_ptr<PublicKey> & publicKey, const shared_ptr<PrivateKey> & privateKey) override;

	/**
	* Initializes this ElGamal encryption scheme with public key.
	* Setting only the public key the user can encrypt messages but can not decrypt messages.
	* @param publicKey should be ElGamalPublicKey
	* @throws InvalidKeyException if the given key is not instances of ElGamalPuclicKey.
	*/
	void setKey(const shared_ptr<PublicKey> & publicKey) override { setKey(publicKey, NULL); }

	bool isKeySet() override { return keySet; }

	/**
	* Returns the PublicKey of this ElGamal encryption scheme.
	* This function should not be use to check if the key has been set.
	* To check if the key has been set use isKeySet function.
	* @return the ElGamalPublicKey
	* @throws IllegalStateException if no public key was set.
	*/
	shared_ptr<PublicKey> getPublicKey() override {
		if (!isKeySet()) {
			throw new IllegalStateException("no PublicKey was set");
		}

		return publicKey;
	}

	/**
	* @return the name of this AsymmetricEnc - ElGamal and the underlying dlog group type
	*/
	string getAlgorithmName() override { return "ElGamal/" + dlog->getGroupType(); }

	/**
	* Generates a KeyPair containing a set of ElGamalPublicKEy and ElGamalPrivateKey using the source of randomness and the dlog specified upon construction.
	* @return KeyPair contains keys for this ElGamal object.
	*/
	pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>> generateKey() override;

	/**
	* This function is not supported for this encryption scheme, since there is no need for parameters to generate an ElGamal key pair.
	* @throws UnsupportedOperationException
	*/
	pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>> generateKey(AlgorithmParameterSpec * keyParams) override {
		//No need for parameters to generate an El Gamal key pair. 
		throw UnsupportedOperationException("To Generate ElGamal keys use the generateKey() function");
	}

	shared_ptr<PublicKey> reconstructPublicKey(KeySendableData* data) override;

	shared_ptr<PrivateKey> reconstructPrivateKey(KeySendableData* data) override;

	/**
	* Encrypts the given message using ElGamal encryption scheme.
	*
	* @param plaintext contains message to encrypt. The given plaintext must match this ElGamal type.
	* @return Ciphertext containing the encrypted message.
	* @throws IllegalStateException if no public key was set.
	* @throws invalid_argument if the given Plaintext does not match this ElGamal type.
	*/
	shared_ptr<AsymmetricCiphertext> encrypt(const shared_ptr<Plaintext> & plaintext) override;

	/**
	* Encrypts the given plaintext using this asymmetric encryption scheme and using the given random value.
	* There are cases when the random value is used after the encryption, for example, in sigma protocol.
	* In these cases the random value should be known to the user. We decided not to have function that return it to the user
	* since this can cause problems when more than one value is being encrypt.
	* Instead, we decided to have an additional encrypt value that gets the random value from the user.
	*
	* @param plaintext contains message to encrypt. The given plaintext must match this ElGamal type.
	* @param r The random value to use in the encryption.
	* @return Ciphertext containing the encrypted message.
	* @throws IllegalStateException if no public key was set.
	* @throws invalid_argument if the given Plaintext does not match this ElGamal type.
	*/
	shared_ptr<AsymmetricCiphertext> encrypt(const shared_ptr<Plaintext> & plaintext, const biginteger & r) override;
};


/**
* This class performs the El Gamal encryption scheme that perform the encryption on a GroupElement. 
* In some cases there are protocols that do multiple calculations and might want to keep working on a close group.
* For those cases we provide encryption on a group element. 
*
* By definition, this encryption scheme is CPA-secure and Indistinguishable.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class ElGamalOnGroupElementEnc : public ElGamalEnc, public AsymMultiplicativeHomomorphicEnc {
protected:
	/**
	* ElGamal decrypt function can be optimized if, instead of using the x value in the private key as is,
	* we change it to be q-x, while q is the dlog group order.
	* This function computes this changing and saves the new private value as the private key member.
	* @param privateKey to change.
	*/
	void initPrivateKey(const shared_ptr<ElGamalPrivateKey> & privateKey) override;

	shared_ptr<AsymmetricCiphertext> completeEncryption(const shared_ptr<GroupElement> & c1, GroupElement* hy, Plaintext* plaintext) override;

public:
	ElGamalOnGroupElementEnc() {}

	/**
	* Constructor that gets a DlogGroup and sets it to the underlying group.
	* It lets SCAPI choose and source of randomness.
	* @param dlogGroup underlying DlogGroup to use, it has to have DDH security level
	* @throws SecurityLevelException if the Dlog Group is not DDH secure
	*/
	ElGamalOnGroupElementEnc(const shared_ptr<DlogGroup> & dlogGroup, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) : ElGamalEnc(dlogGroup, random) {}

	
	/**
	* El-Gamal encryption scheme has a limit of the byte array length to generate a plaintext from.
	* @return true.
	*/
	bool hasMaxByteArrayLengthForPlaintext() override { return true; }

	/**
	* Returns the maximum size of the byte array that can be passed to generatePlaintext function.
	* This is the maximum size of a byte array that can be converted to a Plaintext object suitable to this encryption scheme.
	*/
	int getMaxLengthOfByteArrayForPlaintext() override { return dlog->getMaxLengthOfByteArrayForEncoding(); }

	/**
	* Generates a Plaintext suitable to ElGamal encryption scheme from the given message.
	* @param text byte array to convert to a Plaintext object.
	* @throws invalid_argument if the given message's length is greater than the maximum.
	*/
	shared_ptr<Plaintext> generatePlaintext(vector<byte> & text) override;

	/**
	* Decrypts the given ciphertext using ElGamal encryption scheme.
	*
	* @param cipher MUST be of type ElGamalOnGroupElementCiphertext contains the cipher to decrypt.
	* @return Plaintext of type GroupElementPlaintext which containing the decrypted message.
	* @throws KeyException if no private key was set.
	* @throws invalid_argument if the given cipher is not instance of ElGamalOnGroupElementCiphertext.
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
	* Calculates the ciphertext resulting of multiplying two given ciphertexts.
	* Both ciphertexts have to have been generated with the same public key and DlogGroup as the underlying objects of this ElGamal object.
	* @throws IllegalStateException if no public key was set.
	* @throws invalid_argument in the following cases:
	* 		1. If one or more of the given ciphertexts is not instance of ElGamalOnGroupElementCiphertext.
	* 		2. If one or more of the GroupElements in the given ciphertexts is not a member of the underlying DlogGroup of this ElGamal encryption scheme.
	*/
	shared_ptr<AsymmetricCiphertext> multiply(AsymmetricCiphertext* cipher1, AsymmetricCiphertext* cipher2) override;

	/**
	* Calculates the ciphertext resulting of multiplying two given ciphertexts.
	* Both ciphertexts have to have been generated with the same public key and DlogGroup as the underlying objects of this ElGamal object.
	*
	* There are cases when the random value is used after the function, for example, in sigma protocol.
	* In these cases the random value should be known to the user. We decided not to have function that return it to the user
	* since this can cause problems when the multiply function is called more than one time.
	* Instead, we decided to have an additional multiply function that gets the random value from the user.
	*
	* @throws IllegalStateException if no public key was set.
	* @throws invalid_argument in the following cases:
	* 		1. If one or more of the given ciphertexts is not instance of ElGamalOnGroupElementCiphertext.
	* 		2. If one or more of the GroupElements in the given ciphertexts is not a member of the underlying DlogGroup of this ElGamal encryption scheme.
	*/
	shared_ptr<AsymmetricCiphertext> multiply(AsymmetricCiphertext* cipher1, AsymmetricCiphertext* cipher2, biginteger & r) override;

	
	/**
	* @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
	*/
	shared_ptr<AsymmetricCiphertext> reconstructCiphertext(AsymmetricCiphertextSendableData* data) override;
};

/**
* This class performs the El Gamal encryption scheme that perform the encryption on a ByteArray.
* The general encryption of a message usually uses this type of encryption. 
*
* By definition, this encryption scheme is CPA-secure and Indistinguishable.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class ElGamalOnByteArrayEnc : public ElGamalEnc {

private:
	shared_ptr<KeyDerivationFunction> kdf; 	// The underlying KDF to use in the encryption.

protected:
	/**
	* Sets the private key.
	*/
	void initPrivateKey(const shared_ptr<ElGamalPrivateKey> & privateKey) override	{
		//Sets the given PrivateKey.
		this->privateKey = privateKey;
	}

	/**
	* Completes the encryption operation.
	* @param plaintext contains message to encrypt. MUST be of type ByteArrayPlaintext.
	* @return Ciphertext of type ElGamalOnByteArrayCiphertext containing the encrypted message.
	* @throws invalid_argument if the given Plaintext is not an instance of ByteArrayPlaintext.
	*/
	shared_ptr<AsymmetricCiphertext> completeEncryption(const shared_ptr<GroupElement> & c1, GroupElement* hy, Plaintext* plaintext) override;
									
public:
	/**
	* Default constructor. Uses the default implementations of DlogGroup, kdf and SecureRandom.
	*/
	ElGamalOnByteArrayEnc() : ElGamalEnc() {
		//Creates a default implementation of KDF.
		this->kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>());
	}

	/**
	* Constructor that gets a DlogGroup and sets it to the underlying group.
	* It lets SCAPI choose and source of randomness.
	* @param dlogGroup must be DDH secure.
	* @throws SecurityLevelException if the given dlog group does not have DDH security level.
	*/
	ElGamalOnByteArrayEnc(const shared_ptr<DlogGroup> & dlogGroup, const shared_ptr<KeyDerivationFunction> & kdf, 
						  const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) : ElGamalEnc(dlogGroup, random) {
		this->kdf = kdf;
	}
	
	/**
	* ElGamalOnByteArray encryption scheme has no limit of the byte array length to generate a plaintext from.
	* @return false.
	*/
	bool hasMaxByteArrayLengthForPlaintext() override { return false; }

	/**
	* ElGamalOnByteArray encryption can get any plaintext length.
	* @throws runtime_error.
	*/
	int getMaxLengthOfByteArrayForPlaintext() override {
		throw runtime_error("ElGamalOnByteArray encryption can get any plaintext length");
	}

	/**
	* Generates a Plaintext suitable to ElGamal encryption scheme from the given message.
	* @param text byte array to convert to a Plaintext object.
	*/
	shared_ptr<Plaintext> generatePlaintext(vector<byte> & text) override {
		return make_shared<ByteArrayPlaintext>(text);
	}

	/**
	* Decrypts the given ciphertext using ElGamal encryption scheme.
	*
	* @param cipher MUST be of type ElGamalOnByteArrayCiphertext contains the cipher to decrypt.
	* @return Plaintext of type ByteArrayPlaintext which containing the decrypted message.
	* @throws KeyException if no private key was set.
	* @throws invalid_argument if the given cipher is not instance of ElGamalOnByteArrayCiphertext.
	*/
	shared_ptr<Plaintext> decrypt(AsymmetricCiphertext* cipher) override; 

	/**
	* Generates a byte array from the given plaintext.
	* This function should be used when the user does not know the specific type of the Asymmetric encryption he has,
	* and therefore he is working on byte array.
	* @param plaintext to generates byte array from. MUST be an instance of ByteArrayPlaintext.
	* @return the byte array generated from the given plaintext.
	* @throws invalid_argument if the given plaintext is not an instance of ByteArrayPlaintext.
	*/
	vector<byte> generateBytesFromPlaintext(Plaintext* plaintext) override; 

	/**
	* @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
	*/
	shared_ptr<AsymmetricCiphertext> reconstructCiphertext(AsymmetricCiphertextSendableData* data) override; 
};
