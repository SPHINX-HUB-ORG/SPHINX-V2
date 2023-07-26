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
#include "Common.hpp"

/**
* This class holds general math algorithms needed by cryptographic algorithms.<p>
* Each algorithm is represented by a static function that can be called independently from the other algorithms.
*/

class MathAlgorithms {
public:
	static biginteger modInverse(biginteger a, biginteger m);
	/**
	* Computes the integer x that is expressed through the given primes and the
	* congruences with the chinese remainder theorem (CRT).
	*
	* @param congruences
	*            the congruences c_i
	* @param moduli
	*            the primes p_i
	* @return an integer x for that x % p_i == c_i
	*/
	static biginteger chineseRemainderTheorem(const vector<biginteger> & congruences, const vector<biginteger> & moduli);

	/**
	* Computes n!  (n factorial)
	* @param n
	* @return n!
	*/
	static int factorial(int n);

	/**
	* Computes n!  (n factorial)
	* @param n
	* @return n! as a BigInteger
	*/
	static biginteger factorialBI(int n);

	/*-------------------------------------------------------------*/
	/**
	* This class holds the result of calculating the square root of a BigInteger.
	* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
	*
	*/
	class SquareRootResults {
		biginteger root1;
		biginteger root2;
	public:
		SquareRootResults(const biginteger & root1, const biginteger & root2) {
			this->root1 = root1;
			this->root2 = root2;
		}
		biginteger getRoot1() {
			return root1;
		}
		biginteger getRoot2() {
			return root2;
		}
	};

	/**
	* This function calculates the square root of z mod p if and only if p is a prime such that p = 3 mod 4.
	* This function assumes that p is a prime and does not perform the primality check for efficiency reasons.
	* @param z the number for which we calculate the square root
	* @param p the mod
	* @throws IllegalArgumentException if p != 3 mod 4
	* @return SquareRootResults which is a pair of BigIntegers x and -x such that z = x^2  and z = -x^2
	*/
	static SquareRootResults sqrtModP_3_4(const biginteger & z, const biginteger & p);
};