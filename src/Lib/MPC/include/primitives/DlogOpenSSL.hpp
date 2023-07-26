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

#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include "Dlog.hpp"
#include "Prg.hpp"


/**********************/
/**** Helpers *********/
/**********************/
biginteger opensslbignum_to_biginteger(BIGNUM* bint);
BIGNUM* biginteger_to_opensslbignum(biginteger bi);

class OpenSSLDlogZpSafePrime;
/**
* This class is an adapter to ZpElement in OpenSSL library.
* It holds a pointer to an OpenSSL's Zp element and implements all the functionality of a Zp element.
*/
class OpenSSLZpSafePrimeElement : public ZpSafePrimeElement {
private:
	shared_ptr<BIGNUM> openSSLElement;
	void createOpenSSLElement() { openSSLElement = shared_ptr<BIGNUM>(biginteger_to_opensslbignum(element), BN_free); }

	//These constructors are private beacause only the Dlog Group (whitch is a friend class) should create the element.

	/**
	 * Gets the element value and creates the underlying OpenSSL object.
	 */
	OpenSSLZpSafePrimeElement(const biginteger & x, const biginteger & p, bool bCheckMembership) :
		ZpSafePrimeElement(x, p, bCheckMembership) { createOpenSSLElement(); };
	
	/**
	* Creates a random element in the group.
	*/
	OpenSSLZpSafePrimeElement(const biginteger & p, PrgFromOpenSSLAES* prg) : ZpSafePrimeElement(p, prg) { createOpenSSLElement(); };
	OpenSSLZpSafePrimeElement(const biginteger & elementValue) : ZpSafePrimeElement(elementValue) { createOpenSSLElement(); };
public:
	virtual string toString() {
		return "OpenSSLZpSafePrimeElement  [element value=" + element.str() + "]";
	};
	shared_ptr<BIGNUM> getOpenSSLElement() { return openSSLElement; }

	friend OpenSSLDlogZpSafePrime; //The corresponding Dlog group is a friend class in order to be able to create elements.
};

/**
* This class implements a Dlog group over Zp* utilizing OpenSSL's implementation.
*/
class OpenSSLDlogZpSafePrime : public DlogZpSafePrime, public DDH {
private:
//#if OPENSSL_VERSION_NUMBER < 0x10100000L
	shared_ptr<DH> _dlog;		// Underlying OpenSSL group object.
	shared_ptr<BN_CTX> _ctx;
//#else
//    DH *dlog;
//    BN_CTX *ctx;
//#endif
	void createOpenSSLDlogZp(const biginteger & p, const biginteger & q, const biginteger & g);
	void createRandomOpenSSLDlogZp(int numBits);

	bool validateElement(BIGNUM* element);
	int calcK(const biginteger & p);

public:
	//virtual ~OpenSSLDlogZpSafePrime();
	/**
	* Initializes the OpenSSL implementation of Dlog over Zp* with the given groupParams.
	*/
	OpenSSLDlogZpSafePrime(const std::shared_ptr<ZpGroupParams> & groupParams, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());
	OpenSSLDlogZpSafePrime(string q, string g, string p) : OpenSSLDlogZpSafePrime(
		make_shared<ZpGroupParams>(biginteger(q), biginteger(g), biginteger(p))) {};
	/**
	* Default constructor. Initializes this object with 1024 bit size.
	*/
	OpenSSLDlogZpSafePrime(int numBits = 1024, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());
	OpenSSLDlogZpSafePrime(string numBits) : OpenSSLDlogZpSafePrime(stoi(numBits)) {};
	
	string getGroupType() override { return "Zp*"; }
	shared_ptr<GroupElement> getIdentity() override;
	shared_ptr<GroupElement> createRandomElement() override;
	bool isMember(GroupElement* element) override;
	bool isGenerator() override;
	bool validateGroup() override;
	shared_ptr<GroupElement> getInverse(GroupElement* groupElement) override;
	shared_ptr<GroupElement> exponentiate(GroupElement* base, const biginteger & exponent) override;
	shared_ptr<GroupElement> exponentiateWithPreComputedValues(const shared_ptr<GroupElement> & groupElement, 
		const biginteger & exponent) override { return exponentiate(groupElement.get(), exponent); };
	shared_ptr<GroupElement> multiplyGroupElements(GroupElement* groupElement1, 
		GroupElement* groupElement2) override;
	shared_ptr<GroupElement> simultaneousMultipleExponentiations(vector<shared_ptr<GroupElement>> & groupElements,
		vector<biginteger> & exponentiations) override;
	shared_ptr<GroupElement> generateElement(bool bCheckMembership, vector<biginteger> & values) override;
	shared_ptr<GroupElement> reconstructElement(bool bCheckMembership, GroupElementSendableData* data) override;
	const vector<byte> decodeGroupElementToByteArray(GroupElement* groupElement) override;
	shared_ptr<GroupElement> encodeByteArrayToGroupElement(const vector<unsigned char> & binaryString) override;
	virtual const vector<byte>  mapAnyGroupElementToByteArray(GroupElement* groupElement) override;
};

/**
 * This class is an abstract class that implements  common functionality of EC Dlog group using OpenSSL library.
 */
class OpenSSLDlogEC : public DlogEllipticCurve{
	
protected:
	shared_ptr<EC_GROUP> curve;	// The underlying OpenSSL group
	shared_ptr<BN_CTX> ctx;
	virtual shared_ptr<ECElement> createPoint(const shared_ptr<EC_POINT> &) = 0;
	shared_ptr<EC_GROUP> getCurve() { return curve; }
	shared_ptr<BN_CTX> getCTX() { return ctx; }

public:
	OpenSSLDlogEC(string fileName, string curveName, const shared_ptr<PrgFromOpenSSLAES> & random) : DlogEllipticCurve(fileName, curveName, random) { }

	OpenSSLDlogEC(string curveName, const shared_ptr<PrgFromOpenSSLAES> & random) : DlogEllipticCurve(curveName, random) { }

	bool validateGroup() override;

	shared_ptr<GroupElement> getInverse(GroupElement* groupElement) override;

	shared_ptr<GroupElement> exponentiate(GroupElement* base, const biginteger & exponent) override;

	shared_ptr<GroupElement> multiplyGroupElements(GroupElement* groupElement1,
		GroupElement* groupElement2) override;

	shared_ptr<GroupElement> exponentiateWithPreComputedValues(
		const shared_ptr<GroupElement> & base, const biginteger & exponent) override;

	shared_ptr<GroupElement> simultaneousMultipleExponentiations(
		vector<shared_ptr<GroupElement>> & groupElements, vector<biginteger> & exponentiations) override;

	const vector<byte> mapAnyGroupElementToByteArray(GroupElement* groupElement) override;

	shared_ptr<ECElement> getInfinity() override;

};


class OpenSSLECFpPoint;

/*
 * Concrete class of elliptic curve over Fp field. This implementation uses OpenSSL library.
 */
class OpenSSLDlogECFp : public OpenSSLDlogEC, public DDH {
private:
	shared_ptr<PrgFromOpenSSLAES> random;

	int calcK(biginteger & p);
	void createCurve(const biginteger & p, const biginteger & a, const biginteger & b);
	void initCurve(const biginteger & q);
	bool checkSubGroupMembership(OpenSSLECFpPoint* point);
	

protected:
	shared_ptr<ECElement> createPoint(const shared_ptr<EC_POINT> &) override;
	void init(string fileName, string curveName, const shared_ptr<PrgFromOpenSSLAES> & random) override;

public:
	OpenSSLDlogECFp() : OpenSSLDlogECFp("P-192") { }

	OpenSSLDlogECFp(string fileName, string curveName, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) : OpenSSLDlogEC(fileName, curveName, random) { init(fileName, curveName, random); }

	OpenSSLDlogECFp(string curveName, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) : OpenSSLDlogEC(curveName, random)  { init(NISTEC_PROPERTIES_FILE, curveName, random); }

	string getGroupType() override;

	bool isMember(GroupElement* element) override;

	shared_ptr<GroupElement> generateElement(bool bCheckMembership, vector<biginteger> & values) override;

	shared_ptr<GroupElement> encodeByteArrayToGroupElement(const vector<unsigned char> & binaryString) override;

	const vector<unsigned char> decodeGroupElementToByteArray(GroupElement* groupElement) override;

	shared_ptr<GroupElement> reconstructElement(bool bCheckMembership, GroupElementSendableData* data) override;
	
	friend class OpenSSLECFpPoint; //The corresponding group element is a friend class in order to use the private methods.
};

class OpenSSLECF2mPoint;

/*
* Concrete class of elliptic curve over F2m field. This implementation uses OpenSSL library.
*/
class OpenSSLDlogECF2m : public OpenSSLDlogEC, public DDH {
private:
	void createGroupParams();
	void createCurve();
	bool checkSubGroupMembership(OpenSSLECF2mPoint*  point);
protected:
	void init(string fileName, string curveName, const shared_ptr<PrgFromOpenSSLAES> & random) override;
	shared_ptr<ECElement> createPoint(const shared_ptr<EC_POINT> &) override;

public:

	OpenSSLDlogECF2m() : OpenSSLDlogECF2m("K-163") {}

	OpenSSLDlogECF2m(string fileName, string curveName, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()): OpenSSLDlogEC(fileName, curveName, random) { init(fileName, curveName, random); }

	OpenSSLDlogECF2m(string curveName, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) : OpenSSLDlogEC(curveName, random) { init(NISTEC_PROPERTIES_FILE, curveName, random); }

	string getGroupType() override;

	bool isMember(GroupElement* element) override;

	shared_ptr<GroupElement> generateElement(bool bCheckMembership, vector<biginteger> & values) override;

	//shared_ptr<GroupElement> simultaneousMultipleExponentiations(
		//vector<shared_ptr<GroupElement>> & groupElements, vector<biginteger> & exponentiations) override;

	shared_ptr<GroupElement> encodeByteArrayToGroupElement(const vector<unsigned char> & binaryString) override;

	const vector<unsigned char> decodeGroupElementToByteArray(GroupElement* groupElement) override;

	shared_ptr<GroupElement> reconstructElement(bool bCheckMembership, GroupElementSendableData* data) override;

	friend class OpenSSLECF2mPoint; //The corresponding group element is a friend class in order to use the private methods.
};

/*
 * Abstract class for elliptic curve elements using OpenSSL library.
 */
class OpenSSLPoint :public ECElement {
protected:
	shared_ptr<EC_POINT> point; // The underlying OpenSSL point.
	shared_ptr<EC_POINT> getPoint() { return point; }

	//We hols both the point and its values in order to be efficient.
	biginteger x;
	biginteger y;
public:
	bool isInfinity() override;
	biginteger getX() override { return x; }
	biginteger getY() override { return y; }
	friend class OpenSSLDlogEC;  
};

/*
 * Concrete class of Fp point using OpenSSL library.
 */
class OpenSSLECFpPoint : public OpenSSLPoint {
private:

	//The constructors are private because only the Dlog group should create instances of this class.
	//Notice that OpenSSLDlogECFp class is a friend, in order to enable the creation from there.
	OpenSSLECFpPoint(const biginteger & x, const biginteger & y, OpenSSLDlogECFp* curve, bool bCheckMembership);
	OpenSSLECFpPoint(const shared_ptr<EC_POINT> & point, OpenSSLDlogECFp* curve);

	bool checkCurveMembership(ECFpGroupParams* params, const biginteger & x, const biginteger & y);
public:
	friend class OpenSSLDlogECFp;
};

/*
* Concrete class of F2m point using OpenSSL library.
*/
class OpenSSLECF2mPoint : public OpenSSLPoint, public enable_shared_from_this<OpenSSLECF2mPoint> {
private:

	//The constructors are private because only the Dlog group should create instances of this class.
	//Notice that OpenSSLDlogECF2m class is a friend, in order to enable the creation from there.
	OpenSSLECF2mPoint(const biginteger & x, const biginteger & y, OpenSSLDlogECF2m* curve, bool bCheckMembership);
	OpenSSLECF2mPoint(const shared_ptr<EC_POINT> & point, OpenSSLDlogECF2m* curve);
public:
	friend class OpenSSLDlogECF2m;
};
