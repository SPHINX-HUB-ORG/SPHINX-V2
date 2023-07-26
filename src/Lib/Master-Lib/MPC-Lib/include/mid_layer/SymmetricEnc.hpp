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
* This is the main interface for the Symmetric Encryption family.
* The symmetric encryption family of classes implements three main functionalities that correspond to the cryptographer's language
* in which an encryption scheme is composed of three algorithms:<p>
* 	1.	Generation of the key.
*	2.	Encryption of the plaintext.
*	3.	Decryption of the ciphertext.
*
* Any symmetric encryption scheme belongs by default at least to the Eavsdropper Security Level and to the Indistinguishable Security Level.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class SymmetricEnc : public Eav, public Indistinguishable {
protected:
	bool keySet = false;
	
public:
	/**
	* Sets the secret key for this symmetric encryption.
	* The key can be changed at any time.
	* @param secretKey secret key.
	* @throws InvalidKeyException if the given key does not match this encryption scheme.
	*/
	virtual void setKey(SecretKey & secretKey) = 0;

	/**
	* An object trying to use an instance of symmetric encryption needs to check if it has already been initialized.
	* @return true if the object was initialized by calling the function setKey.
	*/
	bool isKeySet() { return keySet; }

	/**
	* Returns the name of this symmetric encryption.
	*/
	virtual string getAlgorithmName() = 0;

	/**
	* Generates a secret key to initialize this symmetric encryption.
	* @param keyParams algorithmParameterSpec contains  parameters for the key generation of this symmetric encryption.
	* @return the generated secret key.
	*/
	virtual SecretKey generateKey(AlgorithmParameterSpec& keyParams) = 0;

	/**
	* Generates a secret key to initialize this symmetric encryption.
	* @param keySize is the required secret key size in bits.
	* @return the generated secret key.
	*/
	virtual SecretKey generateKey(int keySize) = 0;

	/**
	* Encrypts a plaintext. It lets the system choose the random IV.
	* @param plaintext
	* @return  an IVCiphertext, which contains the IV used and the encrypted data.
	* @throws IllegalStateException if no secret key was set.
	* @throws invalid_argument if the given plaintext does not match this encryption scheme.
	*/
	virtual shared_ptr<SymmetricCiphertext> encrypt(Plaintext* plaintext) = 0;

	/**
	* This function encrypts a plaintext. It lets the user choose the random IV.
	* @param plaintext
	* @param iv random bytes to use in the encryption pf the message.
	* @return an IVCiphertext, which contains the IV used and the encrypted data.
	* @throws IllegalStateException if no secret key was set.
	* @throws invalid_argument if the given plaintext does not match this encryption scheme.
	*/
	virtual shared_ptr<SymmetricCiphertext> encrypt(Plaintext* plaintext, vector<byte> & iv) = 0;

	/**
	* This function performs the decryption of a ciphertext returning the corresponding decrypted plaintext.
	* @param ciphertext The Ciphertext to decrypt.
	* @return the decrypted plaintext.
	* @throws invalid_argument if the given ciphertext does not match this encryption scheme.
	* @throws IllegalStateException if no secret key was set.
	*/
	virtual shared_ptr<Plaintext> decrypt(SymmetricCiphertext* ciphertext) = 0;
};

/**
* Any implementation of Symmetric encryption in Counter-Mode ash to implement this class.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CTREnc : public virtual SymmetricEnc, public Cpa {};


