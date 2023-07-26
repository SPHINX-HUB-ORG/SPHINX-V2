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


#ifndef SCAPI_HASH_OPENSSL_H
#define SCAPI_HASH_OPENSSL_H

#include "Hash.hpp"
#include <openssl/evp.h>
#include <set>

/**
* A general adapter class of hash for OpenSSL. <p>
* This class implements all the functionality by passing requests to the adaptee OpenSSL functions,
* like int SHA1_Update(SHA_CTX *c, const void *data, unsigned long len);.
*
* A concrete hash function such as SHA1 represented by the class OpenSSLSHA1 only passes the name of the hash in the constructor
* to this base class.
*/
class OpenSSLHash : public virtual CryptographicHash {
private:
	int hashSize;
protected:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	shared_ptr<EVP_MD_CTX> hash; //Pointer to the OpenSSL hash object.
#else
    EVP_MD_CTX *hash;
#endif
public:
	/**
	* Constructs the OpenSSL hash object.
	* @param hashName - the name of the hash. This will be passed to the jni dll function createHash so it will know which hash to create.
	*/
	OpenSSLHash(string hashName);

	/**
	* @return the size of the hashed massage in bytes.
	*/
	int getHashedMsgSize() override { return hashSize;};

	string getAlgorithmName() override;

	/**
	* Adds the byte vector to the existing message to hash.
	* @param in input byte vector.
	* @param inOffset the offset within the byte array.
	* @param inLen the length. The number of bytes to take after the offset.
	* */
	void update(const vector<byte> &in, int inOffset, int inLen) override;

	/**
	* Completes the hash computation and puts the result in the out vector.
	* @param out the output in byte vector.
	* @param outOffset the offset which to put the result bytes from.
	*/
	void hashFinal(vector<byte> &out, int outOffset) override;
};

/************************************************************
* Concrete classed of cryptographicHash for different SHA. 
* These classes wraps OpenSSL implementation of SHA*.
*************************************************************/

class OpenSSLSHA1 : public OpenSSLHash , public SHA1 {
public:
	OpenSSLSHA1() : OpenSSLHash("SHA1") {};
};

class OpenSSLSHA224 : public OpenSSLHash, public SHA224 {
public:
	OpenSSLSHA224() : OpenSSLHash("SHA224") {};
};

class OpenSSLSHA256 : public OpenSSLHash, public SHA256{
public:
	OpenSSLSHA256() : OpenSSLHash("SHA256") {};
};

class OpenSSLSHA384 : public OpenSSLHash, public SHA384 {
public:
	OpenSSLSHA384() : OpenSSLHash("SHA384") {};
};

class OpenSSLSHA512 : public OpenSSLHash, public SHA512 {
public:
	OpenSSLSHA512() : OpenSSLHash("SHA512") {};
};

#endif