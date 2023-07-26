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


#include "../../include/primitives/TrapdoorPermutation.hpp"

/*************************************************/
/*TrapdoorPermutationAbs                         */
/*************************************************/
byte TrapdoorPermutation::hardCorePredicate(TPElement * tpEl) {
	if (!isKeySet())
		throw IllegalStateException("keys aren't set");
	/*
	*  We use this implementation both in RSA permutation and in Rabin permutation.
	* Thus, We implement it in TrapdoorPermutationAbs and let derived classes override it if needed.
	*/
	//Get the element value as byte array
	biginteger elementValue = tpEl->getElement();
	size_t bytesSize = bytesCount(elementValue);
	std::shared_ptr<byte> bytesValue(new byte[bytesSize], std::default_delete<byte[]>());
	encodeBigInteger(elementValue, bytesValue.get(), bytesSize);

	// Return the least significant bit (byte, as we said above)
	byte res = bytesValue.get()[bytesSize - 1];
	return res;
}

vector<byte> TrapdoorPermutation::hardCoreFunction(TPElement * tpEl) {
	if (!isKeySet())
		throw IllegalStateException("keys aren't set");
	/*
	* We use this implementation both in RSA permutation and in Rabin permutation.
	* Thus, We implement it in TrapdoorPermutationAbs and let derived classes override it if needed.
	*/
	// Get the element value as byte array
	biginteger elementValue = tpEl->getElement();
	int bytesSize = bytesCount(elementValue);
	std::shared_ptr<byte> bytesValue(new byte[bytesSize], std::default_delete<byte[]>());
	encodeBigInteger(elementValue, bytesValue.get(), bytesSize);
	
	// The number of bytes to get the log (N) least significant bits
	
	double logBits = NumberOfBits(modulus) / 2.0;  //log N bits
	int logBytes = (int)ceil(logBits / 8); //log N bites in bytes

	// If the element length is less than log(N), the return byte[] should be all the element bytes
	int size = min(logBytes, bytesSize);
	vector<byte> leastSignificantBytes(size);
	
	// Copy the bytes to the output array
	for (int i = 0; i < size; i++)
		leastSignificantBytes[i] = bytesValue.get()[bytesSize - size + i];
	return leastSignificantBytes;
}

/*************************************************/
/*RSAElement                                     */
/*************************************************/

RSAElement::RSAElement(const biginteger & modN, const shared_ptr<PrgFromOpenSSLAES> & generator){
	/*
	* Sample a number between 1 to n-1
	*/
	biginteger randNumber;
	int numbit = NumberOfBits(modN);
	biginteger expo = mp::pow(biginteger(2), numbit-1);
	do {
		// Sample a random BigInteger with modN.bitLength()+1 bits
		randNumber = getRandomInRange(0, expo, generator.get()); 
	} while (randNumber > (modN - 2)); // drops the element if it's bigger than mod(N)-2
	// Get a random biginteger between 1 to modN-1
	randNumber += 1;
	// Set it to be the element
	element = randNumber;
}

RSAElement::RSAElement(const biginteger & modN, const biginteger & x, bool check) {
	if (!check)
		element = x;
	else {
		/*
		* Check if the value is valid (between 1 to (mod n) - 1).
		* if valid - sets it to be the element
		* if not valid - throw exception
		*/
		if (x > 0 && x < modN)
			element = x;
		else 
			throw invalid_argument("element out of range");
	}
}

RSAModulus::RSAModulus(size_t length, int certainty, PrgFromOpenSSLAES* random) {

	int pbitlength = (length + 1) / 2;
	int qbitlength = length - pbitlength;
	size_t mindiffbits = length / 3;


	// Generate p prime
	p = getRandomPrime(pbitlength, certainty, random);
	for (;;) {
		do {
			q = getRandomPrime(qbitlength, certainty, random);
		} while ((bytesCount(mp::abs(q - p)) * 8) < mindiffbits);

		// Calculate the modulus
		n = p * q;

		if ((bytesCount(n) * 8) == length)
		{
			break;
		}

		//
		// If we get here our primes aren't big enough, make the largest
		// of the two p and try again
		//
		p = (p > q) ? p : q;
	}
}


