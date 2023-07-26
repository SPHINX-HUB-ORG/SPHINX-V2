#pragma once

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


#ifndef SCAPI_HASH_BLAKE2_H
#define SCAPI_HASH_BLAKE2_H

#include "Hash.hpp"
#include <BLAKE2/sse/blake2.h>

/**
* An abstract class of hash for Blake 2.
* This class implements all the functionality by passing requests to the adaptee library.
*
*/
class Blake2Hash : public virtual CryptographicHash {
private:
	blake2b_state S[1]; // An underlying Blake2 object.
	int hashSize;
public:
	/**
	* Constructs the underlying hash function using BLAKE2 library.
	* @param hashBytesSize the output size of the hash function, in bytes.
	*/
	Blake2Hash(int hashBytesSize);

	/**
	* @return the size of the hashed massage in bytes.
	*/
	int getHashedMsgSize() override { return hashSize; }

	string getAlgorithmName() override { return "BLAKE2"; }

	/**
	* Adds the byte vector to the existing message to hash.
	* @param in input byte vector.
	* @param inOffset the offset within the byte array.
	* @param inLen the length. The number of bytes to take after the offset.
	*/
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

class Blake2SHA1 : public Blake2Hash , public SHA1 {
public:
	Blake2SHA1() : Blake2Hash(20) {};
};

class Blake2SHA224 : public Blake2Hash, public SHA224 {
public:
	Blake2SHA224() : Blake2Hash(28) {};
};

class Blake2SHA256 : public Blake2Hash, public SHA256{
public:
	Blake2SHA256() : Blake2Hash(32) {};
};

class Blake2SHA384 : public Blake2Hash, public SHA384 {
public:
	Blake2SHA384() : Blake2Hash(48) {};
};

class Blake2SHA512 : public Blake2Hash, public SHA512 {
public:
	Blake2SHA512() : Blake2Hash(64) {};
};


#endif
