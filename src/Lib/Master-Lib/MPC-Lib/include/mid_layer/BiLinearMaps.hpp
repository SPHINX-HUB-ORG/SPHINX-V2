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
#include "../infra/Common.hpp"

// must define these before the include - TODO make this dynamic
#define MR_PAIRING_BLS    // AES-256 security
#define AES_SECURITY 256
//#define MR_PAIRING_MNT
//#define AES_SECURITY 80

#ifndef _WIN32
#include <miracl/pairing_3.h>
#else
#include <Miracl/pairing_3.h>
#endif


string bigToString(Big x);
class G1Element; //forward decleration
class G2Element; //forward decleration
class GTElement; //forward decleration

class BiLinearMapWrapper {
public:
	PFC pfc;
	BiLinearMapWrapper() : pfc(AES_SECURITY) {}
	GTElement doBilinearMapping(G1Element& g1, G2Element& g2);
};


class BMGroupElement {
	friend class BiLinearMapWrapper;
public:
	virtual void hashAndMap(string strToHash, BiLinearMapWrapper & mapper)       = 0;
	virtual void exponent(biginteger bi, BiLinearMapWrapper & mapper)            = 0;
	virtual vector<string> toStrings()              = 0;
	virtual void fromStrings(vector<string> & data) = 0;
};

class G1Element : public BMGroupElement {
	friend class BiLinearMapWrapper;
private:
	G1 mirElement;
public:
	G1Element() {};
	virtual vector<string> toStrings() override;
	virtual void fromStrings(vector<string> & data) override;
	virtual void hashAndMap(string strToHash, BiLinearMapWrapper & mapper) override;
	virtual void exponent(biginteger bi, BiLinearMapWrapper & mapper) override;
};

class G2Element : public BMGroupElement {
	friend class BiLinearMapWrapper;
private:
	G2 mirElement;
public:
	G2Element(){};
	virtual vector<string> toStrings() override;
	virtual void fromStrings(vector<string> & data) override;
	virtual void hashAndMap(string strToHash, BiLinearMapWrapper & mapper) override;
	virtual void exponent(biginteger bi, BiLinearMapWrapper & mapper) override;
};

class GTElement : public BMGroupElement {
	friend class BiLinearMapWrapper;
private:
	GT mirElement;
public:
	GTElement() {};
	virtual vector<string> toStrings() override { return vector<string>(); };
	virtual void fromStrings(vector<string> & data) override {};
	virtual void hashAndMap(string strToHash, BiLinearMapWrapper & mapper) override {};
	virtual void exponent(biginteger bi, BiLinearMapWrapper & mapper) override {};
	bool operator==(const GTElement &other) const {
		return mirElement == other.mirElement;
	}
};

