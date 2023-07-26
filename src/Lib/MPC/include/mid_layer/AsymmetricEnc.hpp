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
#include "../cryptoInfra/SecurityLevel.hpp"
#include "../cryptoInfra/Key.hpp"
#include "../cryptoInfra/PlainText.hpp"

/**
* Abstract class for asymmetric encryption. Each class of this family must derive rhis class. 
*
* Asymmetric encryption refers to a cryptographic system requiring two separate keys, one to encrypt the plaintext, and one to decrypt the ciphertext.
* Neither key will do both functions.
* One of these keys is public and the other is kept private.
* If the encryption key is the one published then the system enables private communication from the public to the decryption key's owner.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class AsymmetricEnc : public Cpa, Indistinguishable {

public:
	/**
	* Sets this asymmetric encryption with public key and private key.
	* @throws InvalidKeyException if the given keys don't match this encryption scheme.
	*/
	virtual void setKey(const shared_ptr<PublicKey> & publicKey, const shared_ptr<PrivateKey> & privateKey) = 0;

	/**
	* Sets this asymmetric encryption with a public key.
	* In this case the encryption object can be used only for encryption.
	* @throws InvalidKeyException if the given key doesn't match this encryption scheme.
	*/
	virtual void setKey(const shared_ptr<PublicKey> & publicKey) = 0;

	/**
	* Checks if this AsymmetricEnc object has been previously initialized with corresponding keys.
	* @return true if either the Public Key has been set or the key pair (Public Key, Private Key) has been set;
	* 		  false otherwise.
	*/
	virtual bool isKeySet() = 0;

	/**
	* Returns the PublicKey of this encryption scheme. 
	* This function should not be use to check if the key has been set.
	* To check if the key has been set use isKeySet function.
	* @throws IllegalStateException if no public key was set.
	*/
	virtual shared_ptr<PublicKey> getPublicKey() = 0;


	/**
	* @return the name of this AsymmetricEnc.
	*/
	virtual string getAlgorithmName() = 0;

	/**
	* There are some encryption schemes that have a limit of the byte array that can be passed to the generatePlaintext.
	* This function indicates whether or not there is a limit.
	* Its helps the user know if he needs to pass an array with specific length or not.
	* @return true if this encryption scheme has a maximum byte array length to generate a plaintext from; false, otherwise.
	*/
	virtual bool hasMaxByteArrayLengthForPlaintext() = 0;

	/**
	* Returns the maximum size of the byte array that can be passed to generatePlaintext function.
	* This is the maximum size of a byte array that can be converted to a Plaintext object suitable to this encryption scheme.
	* @throws runtime_error if this encryption scheme has no limit on the plaintext input.
	*/
	virtual int getMaxLengthOfByteArrayForPlaintext() = 0;

	/**
	* Generates a Plaintext suitable for this encryption scheme from the given message.
	* A Plaintext object is needed in order to use the encrypt function. Each encryption scheme might generate a different type of Plaintext
	* according to what it needs for encryption. The encryption function receives as argument an object of type Plaintext in order to allow a protocol
	* holding the encryption scheme to be oblivious to the exact type of data that needs to be passed for encryption.
	* @param text byte array to convert to a Plaintext object.
	* @throws invalid_argument if the given message's length is greater than the maximum.
	*/
	virtual shared_ptr<Plaintext> generatePlaintext(vector<byte> & text) = 0;

	/**
	* Reconstructs a suitable AsymmetricCiphertext from data that was probably obtained via a Channel or any other means of sending data
	* (including serialization).
	* We emphasize that this is NOT in any way an encryption function, it just receives ENCRYPTED DATA and places it in a ciphertext object.
	* @param data contains all the necessary information to construct a suitable ciphertext.
	* @return the AsymmetricCiphertext that corresponds to the implementing encryption scheme, for ex: CramerShoupCiphertext
	*/
	virtual shared_ptr<AsymmetricCiphertext> reconstructCiphertext(AsymmetricCiphertextSendableData* data) = 0;

	/**
	* Encrypts the given plaintext using this asymmetric encryption scheme.
	* @param plainText message to encrypt
	* @return Ciphertext the encrypted plaintext
	* @throws invalid_argument if the given Plaintext doesn't match this encryption type.
	* @throws IllegalStateException if no public key was set.
	*/
	virtual shared_ptr<AsymmetricCiphertext> encrypt(const shared_ptr<Plaintext> & plainText) = 0;

	/**
	* Encrypts the given plaintext using this asymmetric encryption scheme and using the given random value.
	* There are cases when the random value is used after the encryption, for example, in sigma protocol.
	* In these cases the random value should be known to the user. We decided not to have function that return it to the user
	* since this can cause problems when more than one value is being encrypt.
	* Instead, we decided to have an additional encrypt function that gets the random value from the user.
	* @param plainText message to encrypt
	* @param r The random value to use in the encryption.
	* @return Ciphertext the encrypted plaintext
	* @throws invalid_argument if the given Plaintext doesn't match this encryption type.
	* @throws IllegalStateException if no public key was set.
	*/
	virtual shared_ptr<AsymmetricCiphertext> encrypt(const shared_ptr<Plaintext> & plainText, const biginteger & r) = 0;

	/**
	* Decrypts the given ciphertext using this asymmetric encryption scheme.
	* @param cipher ciphertext to decrypt
	* @return Plaintext the decrypted cipher
	* @throws KeyException if there is no private key
	* @throws invalid_argument if the given Ciphertext doesn't march this encryption type.
	*/
	virtual shared_ptr<Plaintext> decrypt(AsymmetricCiphertext* cipher) = 0;

	/**
	* Generates a byte array from the given plaintext.
	* This function should be used when the user does not know the specific type of the Asymmetric encryption he has,
	* and therefore he is working on byte array.
	* @param plaintext to generates byte array from.
	* @return the byte array generated from the given plaintext.
	*/
	virtual vector<byte> generateBytesFromPlaintext(Plaintext* plaintext) = 0;

	/**
	* Generates public and private keys for this asymmetric encryption.
	* @param keyParams hold the required parameters to generate the encryption scheme's keys
	* @return KeyPair holding the public and private keys relevant to the encryption scheme
	* @throws invalid_argument if the given parameters don't match this encryption scheme.
	* @throws UnsupportedOperationException if the encryption scheme do not use AlgorithmParameterSpec in order to generate key.
	*/
	virtual pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>> generateKey(AlgorithmParameterSpec * keyParams) = 0;

	/**
	* Generates public and private keys for this asymmetric encryption.
	* @return KeyPair holding the public and private keys
	* @throws UnsupportedOperationException if the encryption scheme use AlgorithmParameterSpec in order to generate key.
	*/
	virtual pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>> generateKey() = 0;

	/**
	* Reconstructs a suitable PublicKey from data that was probably obtained via a Channel or any other means of sending data.
	* We emphasize that this function does NOT in any way generate a key, it just receives data and recreates a PublicKey object.
	* @param data a invalid_argument The actual type of KeySendableData has to be suitable to the actual encryption scheme used, otherwise it throws an invalid_argument
	* @return a new PublicKey with the data obtained as argument
	*/
	virtual shared_ptr<PublicKey> reconstructPublicKey(KeySendableData* data) = 0;

	/**
	* Reconstructs a suitable PrivateKey from data that was probably obtained via a Channel or any other means of sending data.
	* We emphasize that this function does NOT in any way generate a key, it just receives data and recreates a PrivateKey object.
	* @param data a invalid_argument The actual type of KeySendableData has to be suitable to the actual encryption scheme used, otherwise it throws an invalid_argument
	* @return a new PrivateKey with the data obtained as argument
	*/
	virtual shared_ptr<PrivateKey> reconstructPrivateKey(KeySendableData* data) = 0;

};

/**
* Abstract class for asymmetric multiplicative homomorphic encryption.
* Such encryption schemes can compute the encryption of m1*m2, given only the public key and the encryptions of m1 and m2.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class AsymMultiplicativeHomomorphicEnc {

public:
	/**
	* Receives two ciphertexts and return their multiplication.
	* @return the multiplication result.
	* @throws IllegalStateException if no public key was set.
	* @throws invalid_argument if the given ciphertexts do not match this asymmetric encryption.
	*/
	virtual shared_ptr<AsymmetricCiphertext> multiply(AsymmetricCiphertext* cipher1, AsymmetricCiphertext* cipher2) = 0;

	/**
	* Receives two ciphertexts and return their multiplication.
	* There are cases when the random value is used after the function, for example, in sigma protocol.
	* In these cases the random value should be known to the user. We decided not to have function that return it to the user
	* since this can cause problems when the multiply function is called more than one time.
	* Instead, we decided to have an additional multiply function that gets the random value from the user.
	* @param r The random value used in the function.
	* @return the multiplication result
	* @throws IllegalStateException if no public key was set.
	* @throws invalid_argument if the given ciphertexts do not match this asymmetric encryption.
	*/
	virtual shared_ptr<AsymmetricCiphertext> multiply(AsymmetricCiphertext* cipher1, AsymmetricCiphertext* cipher2, biginteger & r) = 0;
};

/**
* Abstract class for asymmetric additive homomorphic encryption.
* Such encryption schemes can compute the encryption of m1+m2, given only the public key and the encryptions of m1 and m2.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class AsymAdditiveHomomorphicEnc : public AsymmetricEnc {
	
public:
	/**
	* Receives two ciphertexts and return their addition.
	* @return the addition result
	* @throws IllegalStateException if no public key was set.
	* @throws invalid_argument if the given ciphertexts do not match this asymmetric encryption.
	*/
	virtual shared_ptr<AsymmetricCiphertext> add(AsymmetricCiphertext* cipher1, AsymmetricCiphertext* cipher2) = 0;

	/**
	* Receives two ciphertexts and return their addition.
	* There are cases when the random value is used after the function, for example, in sigma protocol.
	* In these cases the random value should be known to the user. We decided not to have function that return it to the user
	* since this can cause problems when the add function is called more than one time.
	* Instead, we decided to have an additional add function that gets the random value from the user.
	* @param r The random value to use in the function.
	* @return the addition result
	* @throws IllegalStateException if no public key was set.
	* @throws invalid_argument if the given ciphertexts do not match this asymmetric encryption.
	*/
	virtual shared_ptr<AsymmetricCiphertext> add(AsymmetricCiphertext* cipher1, AsymmetricCiphertext* cipher2, biginteger & r) = 0;

	/**
	* Receives a cipher and a constant number and returns their multiplication.
	* @return the multiplication result.
	* @throws IllegalStateException if no public key was set.
	* @throws invalid_argument if the given ciphertext does not match this asymmetric encryption.
	*/
	virtual shared_ptr<AsymmetricCiphertext> multByConst(AsymmetricCiphertext* cipher, biginteger & constNumber) = 0;

	/**
	* Receives a cipher and a constant number and returns their multiplication.<p>
	* There are cases when the random value is used after the function, for example, in sigma protocol.
	* In these cases the random value should be known to the user. We decided not to have function that return it to the user
	* since this can cause problems when the multByConst function is called more than one time.
	* Instead, we decided to have an additional multByConst function that gets the random value from the user.
	* @param cipher
	* @param constNumber
	* @param r The random value to use in the function.
	* @return the multiplication result.
	* @throws IllegalStateException if no public key was set.
	* @throws invalid_argument if the given ciphertext does not match this asymmetric encryption.
	*/
	virtual shared_ptr<AsymmetricCiphertext> multByConst(AsymmetricCiphertext* cipher, biginteger & constNumber, biginteger & r) = 0;
};