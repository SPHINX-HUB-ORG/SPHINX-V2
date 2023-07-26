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
#include "HashOpenSSL.hpp"
#include "Kdf.hpp"

/**
* This is an abstract class of Random Oracle. Every class in this family should iderive this class.
* A random oracle is an oracle (a theoretical black box) that responds to every unique query with a (truly) random
* response chosen uniformly from its output domain, except that for any specific query, it responds the same way
* every time it receives that query.
*/
class RandomOracle {
public:	
	/**
	* @return the name of this Random Oracle algorithm.
	*/
	virtual string getAlgorithmName()=0;

	/**
	* Computes the random oracle function on the given input.
	* @param input input to compute the random oracle function on.
	* @param inOffset offset within the input to take the bytes from.
	* @param inLen length of the input.
	* @param outLen required output length IN BYTES.
	* @return a string with the required length.
	*/
	virtual void compute(const vector<byte> & input, int inOffset, int inLen, vector<byte> & output, int outLen) = 0;
};

/**
* Concrete class of random oracle based on CryptographicHash.
*/
class HashBasedRO : public RandomOracle {
private:
	shared_ptr<CryptographicHash> hash; //The underlying object used to compute the random oracle function.
public:
	HashBasedRO(const shared_ptr<CryptographicHash> & hash = make_shared<OpenSSLSHA256>()) { this->hash = hash; };
	HashBasedRO(string hashName) : HashBasedRO(CryptographicHash::get_new_cryptographic_hash(hashName)) {};
	
	/**
	* Computes the random oracle function on the given input.
	* @param input input to compute the random oracle function on.
	* @param inOffset offset within the input to take the bytes from.
	* @param inLen length of the input.
	* @param outLen required output length IN BYTES.
	* @return a string with the required length.
	*/
	void compute(const vector<byte> & input, int inOffset, int inLen, vector<byte> & output, int outLen) override;
	string getAlgorithmName() override { return "HashBasedRO"; };
};

/**
* Concrete class of random oracle based on HKDF.
*/
class HKDFBasedRO : public RandomOracle {
private:
	shared_ptr<HKDF> hkdf; //The underlying object used to compute the random oracle function.

public:	
	HKDFBasedRO(const shared_ptr<HKDF> & hkdf = make_shared<HKDF>()) { this->hkdf = hkdf; };
	
	/**
	* Computes the random oracle function on the given input.
	* @param input input to compute the random oracle function on.
	* @param inOffset offset within the input to take the bytes from.
	* @param inLen length of the input.
	* @param outLen required output length IN BYTES.
	* @return a string with the required length.
	*/
	void compute(const vector<byte> & input, int inOffset, int inLen, vector<byte> & output, int outLen) override;
	string getAlgorithmName() override { return "HKDFBasedRO"; };
};
