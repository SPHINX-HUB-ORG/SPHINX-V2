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


#include "../../include/infra/MathAlgorithms.hpp"

biginteger MathAlgorithms::modInverse(biginteger a, biginteger m)
{
	biginteger b0 = m, t, q;
	biginteger x0 = 0, x1 = 1;
	if (m == 1) return 1;
	while (a > 1) {
		q = a / m;
		t = m, m = a % m, a = t;
		t = x0, x0 = x1 - q * x0, x1 = t;
	}
	if (x1 < 0) x1 += b0;
	return x1;
}

biginteger MathAlgorithms::chineseRemainderTheorem(const vector<biginteger> & congruences, const vector<biginteger> & moduli)
{
	biginteger retval = 0;
	biginteger all = 1;
	for (size_t i = 0; i < moduli.size(); i++)
		all *= moduli[i];
	for (size_t i = 0; i < moduli.size(); i++)
	{
		biginteger a = moduli[i];
		biginteger b = all / a; 
		biginteger b_ = modInverse(b, a);
		biginteger tmp = b*b_; 
		tmp *= congruences[i]; 
		retval += tmp; 	
	}
	return retval % all; 
}

int MathAlgorithms::factorial(int n) {
	int fact = 1; // this  will be the result 
	for (int i = 1; i <= n; i++)
		fact *= i;
	return fact;
}


biginteger MathAlgorithms::factorialBI(int n) {
	biginteger fact = 1 ; // this  will be the result 
	for (int i = 1; i <= n; i++)
		fact *= i;
	return fact;
}

MathAlgorithms::SquareRootResults MathAlgorithms::sqrtModP_3_4(const biginteger & z, const biginteger & p) {
	//We assume here (and we do not check for efficiency reasons) that p is a prime
	//We do check that the prime p = 3 mod 4, if not throw exception 
	if (p%4 != 3)
		throw invalid_argument("p has to be a prime such that p = 3 mod 4");

	biginteger exponent = (p + 1) / 4;
	biginteger x = mp::powm(z, exponent, p);  // z.modPow(exponent, p);
	return SquareRootResults(x, (-x + p) % p); // we want to avoid negative modolus
}

/*-------------------------------------------------------------*/
//}