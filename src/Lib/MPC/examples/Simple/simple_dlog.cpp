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


#include "../../include/primitives/DlogOpenSSL.hpp"
#include <iostream>

int mainDlog(){
	// initiate a discrete log group
	// (in this case the OpenSSL implementation of the elliptic curve group K-233)
	auto dlog = make_shared<OpenSSLDlogZpSafePrime>(128);

	// get the group generator and order
	auto g = dlog->getGenerator();
	biginteger q = dlog->getOrder();

	// create a random exponent r
	auto gen = get_seeded_prg();
	biginteger r = getRandomInRange(0, q - 1, gen.get());

	// exponentiate g in r to receive a new group element
	auto g1 = dlog->exponentiate(g.get(), r);
	// create a random group element
	auto h = dlog->createRandomElement();
	// multiply elements
	auto gMult = dlog->multiplyGroupElements(g1.get(), h.get());

	cout << "genrator value is:              " << ((OpenSSLZpSafePrimeElement *)g.get())->getElementValue() << endl;
	cout << "exponentiate value is:          " << r << endl;
	cout << "exponentiation result is:       " << ((OpenSSLZpSafePrimeElement *)g1.get())->getElementValue() << endl;
	cout << "random element chosen is:       " << ((OpenSSLZpSafePrimeElement *)h.get())->getElementValue() << endl;
	cout << "element multplied by expresult: " << ((OpenSSLZpSafePrimeElement *)gMult.get())->getElementValue() << endl;
	return 0;
}

