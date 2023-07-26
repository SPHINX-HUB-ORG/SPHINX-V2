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

biginteger opensslbignum_to_biginteger(BIGNUM* bint)
{
	char * s = BN_bn2dec(bint);
	auto temp = biginteger(s);
	free(s);
	return temp;
}

BIGNUM* biginteger_to_opensslbignum(biginteger bi)
{
	BIGNUM *bn = NULL;
	BN_dec2bn(&bn, bi.str().c_str());
	return bn;
}

/*************************************************/
/**** OpenSSLDlogZpSafePrime ***/
/*************************************************/
void OpenSSLDlogZpSafePrime::createOpenSSLDlogZp(const biginteger & p, const biginteger & q, const biginteger & g)
{
	// Create OpenSSL Dlog group with p, , q, g.
	// The validity of g will be checked after the creation of the group because the check need the pointer to the group
    _dlog = shared_ptr<DH> (DH_new(), DH_free);
    // Set up the BN_CTX.
    _ctx = shared_ptr<BN_CTX> (BN_CTX_new(), BN_CTX_free);
    if (_dlog == nullptr || _ctx == nullptr)
        throw runtime_error("failed to create OpenSSL Dlog group");

    #if OPENSSL_VERSION_NUMBER < 0x10100000L
	_dlog->p = biginteger_to_opensslbignum(p);
	_dlog->q = biginteger_to_opensslbignum(q);
	_dlog->g = biginteger_to_opensslbignum(g);
	if ((_dlog->p == NULL) || (_dlog->q == NULL) || (_dlog->g == NULL))
		throw runtime_error("failed to create OpenSSL Dlog group");
#else
	int success = DH_set0_pqg(_dlog.get(),biginteger_to_opensslbignum(p), biginteger_to_opensslbignum(q),
	        biginteger_to_opensslbignum(g));
	if (success == 0)
        throw runtime_error("failed to create OpenSSL Dlog group");

#endif
}

void OpenSSLDlogZpSafePrime::createRandomOpenSSLDlogZp(int numBits) {

    _dlog = shared_ptr<DH> (DH_new(), DH_free);
    // Set up the BN_CTX.
    _ctx = shared_ptr<BN_CTX> (BN_CTX_new(), BN_CTX_free);
    if (_dlog == nullptr || _ctx == nullptr)
        throw runtime_error("failed to create OpenSSL Dlog group");
    //Seed the random geneartor.
    RAND_poll(); // reseeds using hardware state (clock, interrupts, etc).

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	//Sample a random safe prime with the requested number of bits.
	_dlog->p = BN_new();
	if (0 == (BN_generate_prime_ex(_dlog->p, numBits, 1, NULL, NULL, NULL))) {
		throw runtime_error("failed to create OpenSSL Dlog");
	}

	//Calculates q from p, such that p = 2q + 1.
	_dlog->q = BN_new();
	if (0 == (BN_rshift1(_dlog->q, _dlog->p))) {
		throw runtime_error("failed to create OpenSSL Dlog");
	}

	//Sample a generator to the group.
	//Each element in the group, except the identity, is a generator.
	//The elements in the group are elements that have a quadratic residue modulus p.
	//Algorithm:
	//	g <- 0
	//	while g == 0 or g == 1:
	//		Sample a number between 0 to p, set it to g
	//		calculate g = g^2 nod p
	_dlog->g = BN_new();
	while (BN_is_zero(_dlog->g) || BN_is_one(_dlog->g)) {
		BN_rand_range(_dlog->g, _dlog->p);
		BN_mod_sqr(_dlog->g, _dlog->g, _dlog->p, _ctx.get());
	}
#else
	BIGNUM *p = BN_new();
	if (0 == (BN_generate_prime_ex(p, numBits, 1, NULL, NULL, NULL)))
        throw runtime_error("failed to create OpenSSL Dlog");

	BIGNUM *q = BN_new();;
    if (0 == (BN_rshift1(q, p)))
        throw runtime_error("failed to create OpenSSL Dlog");
    BIGNUM *g = BN_new();
    while (BN_is_zero(g) || BN_is_one(g))
    {
        BN_rand_range(g, p);
        BN_mod_sqr(g, g, p, _ctx.get());
    }

    DH_set0_pqg(_dlog.get(), p, q, g);

#endif
}

OpenSSLDlogZpSafePrime::OpenSSLDlogZpSafePrime(const shared_ptr<ZpGroupParams> & groupParams,
        const shared_ptr<PrgFromOpenSSLAES> & random)
{
	biginteger p = groupParams->getP();
	biginteger q = groupParams->getQ();
	biginteger g = groupParams->getXg();

	if (!(q * 2 + 1 == p)) // if p is not 2q+1 throw exception
		throw invalid_argument("p must be equal to 2q+1");
	if (!isPrime(p)) // if p is not a prime throw exception
		throw invalid_argument("p must be a prime");
	if (!isPrime(q)) // if q is not a prime throw exception
		throw invalid_argument("q must be a prime");

	// set the inner parameters
	this->groupParams = groupParams;
	this->random_element_gen = random;

	//Create a native Dlog object with dh and ctx.
	createOpenSSLDlogZp(p, q, g);

	//If the generator is not valid, delete the allocated memory and throw exception.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	if (!validateElement(_dlog->g))
		throw invalid_argument("generator value is not valid");
#else
    BIGNUM **p_temp, **q_temp, **g_temp;
    DH_get0_pqg(_dlog.get(), (const BIGNUM**)p_temp, (const BIGNUM**)q_temp, (const BIGNUM**)g_temp);

    if(!validateElement(*g_temp))
        throw invalid_argument("generator value is not valid");
#endif

	//Create the  generator with the pointer that return from the native function.
	OpenSSLZpSafePrimeElement* temp = new OpenSSLZpSafePrimeElement(g, p, false);
	generator = shared_ptr<OpenSSLZpSafePrimeElement>(temp);
	
	//Now that we have p, we can calculate k which is the maximum length of a string to be converted to a Group Element of this group.
	k = calcK(p);
}

OpenSSLDlogZpSafePrime::OpenSSLDlogZpSafePrime(int numBits, const shared_ptr<PrgFromOpenSSLAES> & random) {

	this->random_element_gen = random;

	// Create random Zp dlog group.
	createRandomOpenSSLDlogZp(numBits);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	// Get the generator value.
	biginteger pGenerator = opensslbignum_to_biginteger(_dlog->g);
    //Get the generated parameters.
    biginteger p = opensslbignum_to_biginteger(_dlog->p);
    biginteger q = opensslbignum_to_biginteger(_dlog->q);
#else
    BIGNUM *p_temp, *q_temp, *g_temp;
    DH_get0_pqg(_dlog.get(), (const BIGNUM**)&p_temp, (const BIGNUM**)&q_temp, (const BIGNUM**)&g_temp);
    // Get the generator value.
    biginteger pGenerator = opensslbignum_to_biginteger(g_temp);
    //Get the generated parameters.
    biginteger p = opensslbignum_to_biginteger(p_temp);
    biginteger q = opensslbignum_to_biginteger(q_temp);
#endif

	//Create the GroupElement - generator with the pointer that returned from the native function.
	OpenSSLZpSafePrimeElement* temp = new OpenSSLZpSafePrimeElement(pGenerator);

    //create a ZpGroupParams object
    generator = shared_ptr<OpenSSLZpSafePrimeElement>(temp);
    auto zShared = std::dynamic_pointer_cast<ZpElement>(generator);
	biginteger xG = zShared->getElementValue();
	groupParams = make_shared<ZpGroupParams>(q, xG, p);

	// Now that we have p, we can calculate k which is the maximum length in bytes of a 
	// string to be converted to a Group Element of this group. 
	k = calcK(p);

}

bool OpenSSLDlogZpSafePrime::validateElement(BIGNUM* el) {
	//A valid element in the grou pshould satisfy the following:
	//	1. 0 < el < p.
	//	2. el ^ q = 1 mod p.
	bool result = true;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	BIGNUM* p = _dlog->p;
	BIGNUM* q = _dlog->q;
#else
    BIGNUM *p, *q, *g;
    DH_get0_pqg(_dlog.get(), (const BIGNUM**)&p, (const BIGNUM**)&q, (const BIGNUM**)&g);
#endif

	BIGNUM* zero = BN_new();
	BN_zero(zero);
    auto exp = BN_new();
    //Check that the element is bigger than 0.
    if (BN_cmp(el, zero) <= 0) result = false;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	//Check that the element is smaller than p.
	if (BN_cmp(el, p) > 0) result = false;

	//Check that the element raised to q is 1 mod p.
	BN_mod_exp(exp, el, q, p, _ctx.get());
#else
    //Check that the element is smaller than p.
    if (BN_cmp(el, p) > 0) result = false;

    //Check that the element raised to q is 1 mod p.
    BN_mod_exp(exp, el, q, p, _ctx.get());
#endif

	if (!BN_is_one(exp)) result = false;

	// Release the allocated memory.
	BN_free(zero);
	BN_free(exp);

	return result;
}

int OpenSSLDlogZpSafePrime::calcK(const biginteger & p) {
	int bitsInp = NumberOfBits(p);
	// Any string of length k has a numeric value that is less than (p-1)/2 - 1.
	int k = (bitsInp - 3) / 8;
	// The actual k that we allow is one byte less. This will give us an extra byte to pad the binary string passed to encode to a group element with a 01 byte
	// and at decoding we will remove that extra byte. This way, even if the original string translates to a negative BigInteger the encode and decode functions
	// always work with positive numbers. The encoding will be responsible for padding and the decoding will be responsible for removing the pad.
	k--;
	// For technical reasons of how we chose to do the padding for encoding and decoding (the least significant byte of the encoded string contains the size of the 
	// the original binary string sent for encoding, which is used to remove the padding when decoding) k has to be <= 255 bytes so that the size can be encoded in the padding.
	if (k > 255) {
		k = 255;
	}
	return k;
}

shared_ptr<GroupElement> OpenSSLDlogZpSafePrime::getIdentity() {
	OpenSSLZpSafePrimeElement * el = new OpenSSLZpSafePrimeElement(1,
	        ((ZpGroupParams *)groupParams.get())->getP(), false);
	return shared_ptr<OpenSSLZpSafePrimeElement>(el);
	
}

shared_ptr<GroupElement> OpenSSLDlogZpSafePrime::createRandomElement() {
	OpenSSLZpSafePrimeElement * el = new OpenSSLZpSafePrimeElement(((ZpGroupParams*)groupParams.get())->getP(),
	        random_element_gen.get());
	return shared_ptr<OpenSSLZpSafePrimeElement>(el);
}


bool OpenSSLDlogZpSafePrime::isMember(GroupElement* element) {
	OpenSSLZpSafePrimeElement * zp_element = dynamic_cast<OpenSSLZpSafePrimeElement *>(element);
	// check if element is ZpElementCryptoPp
	if (!zp_element)
		throw invalid_argument("type doesn't match the group type");
	return validateElement(zp_element->getOpenSSLElement().get());
}

bool OpenSSLDlogZpSafePrime::isGenerator() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return validateElement(_dlog->g);
#else
    BIGNUM **p, **q, **g;
    DH_get0_pqg(_dlog.get(), (const BIGNUM**)p, (const BIGNUM**)q, (const BIGNUM**)g);
    return validateElement(*g);
#endif

}

bool OpenSSLDlogZpSafePrime::validateGroup() {
	int result;
	// Run a check of the group.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	DH_check(_dlog.get(), &result);
#else
	DH_check(_dlog.get(), &result);
#endif

	//In case the generator is 2, OpenSSL checks the prime is congruent to 11.
	//while the IETF's primes are congruent to 23 when g = 2.
	// Without the next check, the IETF parameters would fail validation.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	if (BN_is_word(_dlog->g, DH_GENERATOR_2))
#else
    BIGNUM **p, **q, **g;
    DH_get0_pqg(_dlog.get(), (const BIGNUM**)p, (const BIGNUM**)q, (const BIGNUM**)g);
    if (BN_is_word(*g, DH_GENERATOR_2))
#endif
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		long residue = BN_mod_word(_dlog->p, 24);
#else
		long residue = BN_mod_word(*p, 24);
#endif
		if (residue == 11 || residue == 23) {
			result &= ~DH_NOT_SUITABLE_GENERATOR;
		}
	}

	// in case the generator is not 2 or 5, openssl does not check it and returns result == 4 in DH_check function.
	// we check it directly.
	if (result == 4)
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        result = !validateElement(_dlog->g);
#else
        result = !validateElement(*g);
#endif
    }
	return result == 0;

}

shared_ptr<GroupElement> OpenSSLDlogZpSafePrime::getInverse(GroupElement* groupElement) {
	OpenSSLZpSafePrimeElement * zp_element = dynamic_cast<OpenSSLZpSafePrimeElement*>(groupElement);
	// check if element is ZpElementCryptoPp
	if (!zp_element)
		throw invalid_argument("type doesn't match the group type");

	BIGNUM* result = BN_new();
	BIGNUM* elem = zp_element->getOpenSSLElement().get();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	BN_mod_inverse(result, elem, _dlog->p, _ctx.get());
#else
    BIGNUM *p, *q, *g;
    DH_get0_pqg(_dlog.get(), (const BIGNUM**)&p, (const BIGNUM**)&q, (const BIGNUM**)&g);
    BN_mod_inverse(result, elem, p, _ctx.get());
#endif

	auto temp = new OpenSSLZpSafePrimeElement(opensslbignum_to_biginteger(result));
	auto inverseElement = shared_ptr<OpenSSLZpSafePrimeElement>(temp);

	BN_free(result);
	return inverseElement;
}

shared_ptr<GroupElement> OpenSSLDlogZpSafePrime::exponentiate(GroupElement* base,
	const biginteger & exponent) {
	OpenSSLZpSafePrimeElement * zp_element = dynamic_cast<OpenSSLZpSafePrimeElement *>(base);
	// check if element is ZpElementCryptoPp
	if (!zp_element)
		throw invalid_argument("type doesn't match the group type");

	// Convert to OpenSSL objects.
	auto expBN = biginteger_to_opensslbignum(exponent);
	auto baseBN = zp_element->getOpenSSLElement();
	BIGNUM* resultBN = BN_new(); 	//Prepare a result element.

	//Raise the given element and put the result in resultBN.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	BN_mod_exp(resultBN, baseBN.get(), expBN, _dlog->p, _ctx.get());
#else
    BIGNUM *p, *q, *g;
    DH_get0_pqg(_dlog.get(), (const BIGNUM**)&p, (const BIGNUM**)&q, (const BIGNUM**)&g);
    BN_mod_exp(resultBN, baseBN.get(), expBN, p, _ctx.get());
#endif
	biginteger bi_res = opensslbignum_to_biginteger(resultBN);

	//Release the allocated memory.
	BN_free(expBN);
	BN_free(resultBN);

	// build an OpenSSLZpSafePrimeElement element with the result value.
	auto temp = new OpenSSLZpSafePrimeElement(bi_res);
	return shared_ptr<OpenSSLZpSafePrimeElement>(temp);
}

shared_ptr<GroupElement> OpenSSLDlogZpSafePrime::multiplyGroupElements(GroupElement* groupElement1, GroupElement* groupElement2) {
	OpenSSLZpSafePrimeElement * zp1 = dynamic_cast<OpenSSLZpSafePrimeElement *>(groupElement1);
	OpenSSLZpSafePrimeElement * zp2 = dynamic_cast<OpenSSLZpSafePrimeElement *>(groupElement2);
	if (!zp1 || !zp2)
		throw invalid_argument("element type doesn't match the group type");

	// Convert to OpenSSL objects.
	BIGNUM* result = BN_new();
	BIGNUM* elem1 = zp1->getOpenSSLElement().get();
	BIGNUM* elem2 = zp2->getOpenSSLElement().get();

	//Call the OpenSSL's multiply function

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    BN_mod_mul(result, elem1, elem2, _dlog->p, _ctx.get());
#else
    BIGNUM *p, *q, *g;
    DH_get0_pqg(_dlog.get(), (const BIGNUM**)&p, (const BIGNUM**)&q, (const BIGNUM**)&g);
    BN_mod_mul(result, elem1, elem2, p, _ctx.get());
#endif

	auto temp = new OpenSSLZpSafePrimeElement(opensslbignum_to_biginteger(result));
	auto mulElement = shared_ptr<OpenSSLZpSafePrimeElement>(temp);

	BN_free(result);
	return mulElement;
}

shared_ptr<GroupElement> OpenSSLDlogZpSafePrime::simultaneousMultipleExponentiations(
	vector<shared_ptr<GroupElement>> & groupElements, vector<biginteger> & exponentiations) {
	for (size_t i = 0; i < groupElements.size(); i++) {
		OpenSSLZpSafePrimeElement * zp_element = dynamic_cast<OpenSSLZpSafePrimeElement *>(groupElements[i].get());
		if (!zp_element)
			throw invalid_argument("groupElement doesn't match the DlogGroup");
	}
	
	//currently, in OpenSSLDlogZpSafePrime the native algorithm is faster than the optimized one.
	//Thus, we operate the naive algorithm. In the future we may change this.
	// TODO - THIS IS NOT TRUE ANYMORE. NEED TO FIX THIS.
	return computeNaive(groupElements, exponentiations);
}

shared_ptr<GroupElement> OpenSSLDlogZpSafePrime::generateElement(bool bCheckMembership, vector<biginteger> & values) {
	if (values.size() != 1)
		throw invalid_argument("To generate an ZpElement you should pass the x value of the point");
	auto temp = new OpenSSLZpSafePrimeElement(values[0], ((ZpGroupParams *)groupParams.get())->getP(), bCheckMembership);
	return shared_ptr<OpenSSLZpSafePrimeElement>(temp);
}

shared_ptr<GroupElement> OpenSSLDlogZpSafePrime::reconstructElement(bool bCheckMembership, 
	GroupElementSendableData* data) {
	
	ZpElementSendableData * zp_data = dynamic_cast<ZpElementSendableData *>(data);		
	if (!zp_data) 
		throw invalid_argument("groupElement doesn't match the group type");		
	vector<biginteger> values = { zp_data->getX() };		
	return generateElement(bCheckMembership, values);		
}

shared_ptr<GroupElement> OpenSSLDlogZpSafePrime::encodeByteArrayToGroupElement(
	const vector<unsigned char> & binaryString) {

	// any string of length up to k has numeric value that is less than (p-1)/2 - 1.
	// if longer than k then throw exception.
	int bs_size = binaryString.size();
	if (bs_size > k) {
		throw length_error("The binary array to encode is too long.");
	}

	//Pad the binaryString with a x01 byte in the most significant byte to ensure that the 
	//encoding and decoding always work with positive numbers.
	list<unsigned char> newString(binaryString.begin(), binaryString.end());
	newString.push_front(1);

	std::shared_ptr<byte> bstr(new byte[bs_size + 1], std::default_delete<byte[]>());
	for (auto it = newString.begin(); it != newString.end(); ++it) {
		int index = std::distance(newString.begin(), it);
		bstr.get()[index] = *it;
	}
	biginteger s = decodeBigInteger(bstr.get(), bs_size+1);

	//Denote the string of length k by s.
	//Set the group element to be y=(s+1)^2 (this ensures that the result is not 0 and is a square)
	biginteger y = boost::multiprecision::powm((s + 1), 2, ((ZpGroupParams *)groupParams.get())->getP());

	//There is no need to check membership since the "element" was generated so that it is always an element.
	auto temp = new OpenSSLZpSafePrimeElement(y, ((ZpGroupParams *)groupParams.get())->getP(), false);
	auto element = shared_ptr<OpenSSLZpSafePrimeElement>(temp);
	return element;
}

const vector<byte> OpenSSLDlogZpSafePrime::decodeGroupElementToByteArray(GroupElement* groupElement) {
	OpenSSLZpSafePrimeElement * zp_element = dynamic_cast<OpenSSLZpSafePrimeElement *>(groupElement);
	if (!(zp_element))
		throw invalid_argument("element type doesn't match the group type");

	//Given a group element y, find the two inverses z,-z. Take z to be the value between 1 and (p-1)/2. Return s=z-1
	biginteger y = zp_element->getElementValue();
	biginteger p = ((ZpGroupParams *)groupParams.get())->getP();
	MathAlgorithms::SquareRootResults roots = MathAlgorithms::sqrtModP_3_4(y, p);

	biginteger goodRoot;
	biginteger halfP = (p - 1) / 2;
	if (roots.getRoot1()>1 && roots.getRoot1() < halfP)
		goodRoot = roots.getRoot1();
	else
		goodRoot = roots.getRoot2();
	goodRoot -= 1;

	int len = bytesCount(goodRoot);
	std::shared_ptr<byte> output(new byte[len], std::default_delete<byte[]>());
	encodeBigInteger(goodRoot, output.get(), len);
	vector<byte> res;

	// Remove the padding byte at the most significant position (that was added while encoding)
	for (int i = 1; i < len; ++i)
		res.push_back(output.get()[i]);
	return res;
}

const vector<byte> OpenSSLDlogZpSafePrime::mapAnyGroupElementToByteArray(GroupElement* groupElement) {
	OpenSSLZpSafePrimeElement * zp_element = dynamic_cast<OpenSSLZpSafePrimeElement *>(groupElement);
	if (!(zp_element))
		throw invalid_argument("element type doesn't match the group type");
	string res = zp_element->getElementValue().str();
	return vector<unsigned char>(res.begin(), res.end());
}


/********************************************************/
/*******************OpenSSL EC classes*******************/
/********************************************************/

bool OpenSSLDlogEC::validateGroup() {
	//call the openssl's function that validate the group.
	return EC_GROUP_check(curve.get(), ctx.get());
}

shared_ptr<GroupElement> OpenSSLDlogEC::getInverse(GroupElement* groupElement) {

	OpenSSLPoint* element = dynamic_cast<OpenSSLPoint*>(groupElement);
	if (!(element))
		throw invalid_argument("element type doesn't match the group type");
	
	// The inverse of infinity point is infinity.
	if (element->isInfinity()) {
		return createPoint(element->getPoint());
	}

	//Create an inverse point and copy the given point to it.
	//create the result point.
	shared_ptr<EC_POINT> inverse(EC_POINT_new(curve.get()), EC_POINT_free);
	if (NULL == inverse) return NULL;

	if (0 == (EC_POINT_copy(inverse.get(), element->getPoint().get()))) {
		return NULL;
	}

	//Inverse the given value and set the inversed value instead.
	if (0 == (EC_POINT_invert(curve.get(), inverse.get(), ctx.get()))) {
		return NULL;
	}

	//Create the concrete OpenSSl point using the result value.
	return createPoint(inverse); 
}

shared_ptr<GroupElement> OpenSSLDlogEC::exponentiate(GroupElement* base, const biginteger & exponent) {
	
	OpenSSLPoint* basePoint = dynamic_cast<OpenSSLPoint*>(base);
	if (!(basePoint))
		throw invalid_argument("element type doesn't match the group type");

	// The inverse of infinity point is infinity.
	if (basePoint->isInfinity()) {
		return createPoint(basePoint->getPoint());
	}

	//If the exponent is negative, convert it to be the exponent modulus q.
	biginteger modExp;
	if (exponent < 0) {
		modExp = exponent % getOrder();
	} else {
		modExp = exponent;
	}

	//create the result point.
	shared_ptr<EC_POINT> result(EC_POINT_new(curve.get()), EC_POINT_free);
	if (NULL == result) return NULL;

	//Compute the exponentiate.
	BIGNUM* exp = biginteger_to_opensslbignum(modExp);
	if (0 == (EC_POINT_mul(curve.get(), result.get(), NULL, basePoint->getPoint().get(), exp, ctx.get()))) {
		return NULL;
	}

	BN_free(exp);
	//Create the concrete OpenSSl point using the result value.
	return createPoint(result); 
}

shared_ptr<GroupElement> OpenSSLDlogEC::multiplyGroupElements(GroupElement* groupElement1,	GroupElement* groupElement2) {

	OpenSSLPoint* point1 = dynamic_cast<OpenSSLPoint*>(groupElement1);
	OpenSSLPoint* point2 = dynamic_cast<OpenSSLPoint*>(groupElement2);
	if (!(point1) || !(point2))
		throw invalid_argument("element type doesn't match the group type");


	//If one of the points is the infinity point, the second one is the multiplication result.
	if (point1->isInfinity()) {
		return createPoint(point2->getPoint());
	}
	if (point2->isInfinity()) {
		return createPoint(point1->getPoint());
	}

	//create the result point.
	shared_ptr<EC_POINT> result(EC_POINT_new(curve.get()), EC_POINT_free);
	if (NULL == result) return NULL;

	//Compute the multiplication.
	if (0 == (EC_POINT_add(curve.get(), result.get(), point1->getPoint().get(), point2->getPoint().get(), ctx.get()))) {
		return NULL;
	}

	//Create the concrete OpenSSl point using the result value.
	return createPoint(result); 
}

std::shared_ptr<GroupElement> OpenSSLDlogEC::exponentiateWithPreComputedValues(
	const shared_ptr<GroupElement> & base, const biginteger & exponent){
	//The exponentiate with pre computed values implemented by OpenSSL deals only with the group generator.
	if (base != getGenerator()) {
		return exponentiate(base.get(), exponent);
	}

	//If the exponent is negative, convert it to be the exponent modulus q.
	biginteger modExp;
	if (exponent < 0) {
		modExp = exponent % getOrder();
	} else {
		modExp = exponent;
	}

	//create the point.
	shared_ptr<EC_POINT> result(EC_POINT_new(curve.get()), EC_POINT_free);
	if (NULL == result) return NULL;

	//If there are no pre computes values, calculate them.
	if (EC_GROUP_have_precompute_mult(curve.get()) == 0) {
		if (0 == (EC_GROUP_precompute_mult(curve.get(), ctx.get()))) {
			return NULL;
		}
	}

	//Calculate the exponentiate with the pre computed values.
	BIGNUM* exp = biginteger_to_opensslbignum(modExp);
	if (0 == (EC_POINT_mul(curve.get(), result.get(), exp, NULL, NULL, ctx.get()))) {
		return NULL;
	}

	//Create the concrete OpenSSl point using the result value.
	return createPoint(result);
}

shared_ptr<GroupElement> OpenSSLDlogEC::simultaneousMultipleExponentiations(
	vector<shared_ptr<GroupElement>> & groupElements, vector<biginteger> & exponentiations) {
	int size = groupElements.size(); //Number of points.
	vector<BIGNUM*> exponentsArr;//Create an array to hold the exponents.
	vector<EC_POINT*> pointsArr;
	
	//Convert each exponent bytes to a BIGNUM object.
	for (int i = 0; i<size; i++) {
		//Convert to BIGNUM.
		pointsArr.push_back((dynamic_pointer_cast<OpenSSLPoint>(groupElements[i]))->getPoint().get());
		BIGNUM* exponent = biginteger_to_opensslbignum(exponentiations[i]);
		if (NULL == exponent) 
			return NULL;
		exponentsArr.push_back(exponent);
	}

	//Prepare a point that will contain the multiplication result.
	shared_ptr<EC_POINT> result(EC_POINT_new(curve.get()), EC_POINT_free);
	if (NULL == result) return NULL;

	//Computes the simultaneous multiply.
	if (0 == (EC_POINTs_mul(curve.get(), result.get(), NULL, size, (const EC_POINT**)pointsArr.data(), (const BIGNUM **)exponentsArr.data(), ctx.get()))) {
		return NULL;
	}

	for (int i = 0; i<size; i++) {

		BN_free(exponentsArr[i]);
	}
	//Create the concrete OpenSSL point using the result value.
	return createPoint(result);
}

const vector<byte> OpenSSLDlogEC::mapAnyGroupElementToByteArray(GroupElement* groupElement) {
	//This function simply returns an array which is the result of concatenating 
	//the byte array representation of x with the byte array representation of y.
	ECElement * element = dynamic_cast<ECElement*>(groupElement);
	if (!(element))
		throw invalid_argument("element type doesn't match the group type");

	biginteger x = element->getX();
	biginteger y = element->getY();

	int xBytesSize = bytesCount(x);
	int yBytesSize = bytesCount(y);
	shared_ptr<byte> result(new byte[xBytesSize + yBytesSize], default_delete<byte[]>());
	encodeBigInteger(x, result.get(), xBytesSize);
	encodeBigInteger(y, result.get()+xBytesSize, yBytesSize);
	
	return vector<byte>(result.get(), result.get() + xBytesSize + yBytesSize - 1);
}

shared_ptr<ECElement> OpenSSLDlogEC::getInfinity() {
	//create the point.
	shared_ptr<EC_POINT> point(EC_POINT_new(curve.get()), EC_POINT_free);
	if (NULL == point) return NULL;

	//Set the point to be the infinity.
	if (0 == (EC_POINT_set_to_infinity(curve.get(), point.get()))) {
		return NULL;
	}

	//Create the concrete OpenSSl point using the result value.
	return createPoint(point);
}

/************************concrete classes***********************/
void OpenSSLDlogECFp::init(string fileName, string curveName, const shared_ptr<PrgFromOpenSSLAES> & random) {
	// check that the given curve is in the field that matches the group.
	size_t index = curveName.find("P-");
	if (index != 0) {
		throw invalid_argument("curveName is not a curve over Fp field and doesn't match the DlogGroup type");
	}

	// get the curve parameters
	biginteger p(ecConfig->Value(curveName, curveName));
	biginteger a(ecConfig->Value(curveName,"a"));
	biginteger b = convert_hex_to_biginteger(ecConfig->Value(curveName, "b"));
	biginteger x = convert_hex_to_biginteger(ecConfig->Value(curveName, "x"));
	biginteger y = convert_hex_to_biginteger(ecConfig->Value(curveName, "y"));
	biginteger q(ecConfig->Value(curveName, "r"));
	biginteger h(ecConfig->Value(curveName, "h"));

	// create the GroupParams
	auto fpParams = make_shared<ECFpGroupParams>(q, x, y, p, a, b, h);
	
	//Now that we have p, we can calculate k which is the maximum length in bytes of a string to be converted to a Group Element of this group. 
	k = calcK(p);

	// Create the ECCurve.
	createCurve(p, a, b);
	
	groupParams = fpParams;
	this->random = random;
	// Create the generator.
	OpenSSLECFpPoint* temp = new OpenSSLECFpPoint(fpParams->getXg(), fpParams->getYg(), this, true);
	generator = shared_ptr<OpenSSLECFpPoint>(temp);
	groupParams = fpParams;
	//Initialize the curve with the generator and order.
	initCurve(q);
}

void OpenSSLDlogECFp::initCurve(const biginteger & q) {
	//Convert the order into BIGNUM object.
	BIGNUM *order = biginteger_to_opensslbignum(q);
	if (order == NULL)
		throw runtime_error("failed to create OpenSSL Dlog group");

	// Set the generator and the order.
	if (1 != EC_GROUP_set_generator(curve.get(), (dynamic_pointer_cast<OpenSSLECFpPoint>(generator))->getPoint().get(), order, NULL)) {
		throw runtime_error("failed to create OpenSSL Dlog group");
	}
	BN_free(order);
}

void OpenSSLDlogECFp::createCurve(const biginteger & p, const biginteger & a, const biginteger & b) {
	ctx = shared_ptr<BN_CTX>(BN_CTX_new(), BN_CTX_free);
	if (ctx == NULL)
		throw runtime_error("failed to create OpenSSL Dlog group");

	BIGNUM * pOssl = biginteger_to_opensslbignum(p);
	BIGNUM * aOssl = biginteger_to_opensslbignum(a);
	BIGNUM * bOssl = biginteger_to_opensslbignum(b);
	if (pOssl == NULL || aOssl == NULL || bOssl == NULL)
		throw runtime_error("failed to create OpenSSL Dlog group");

	curve = shared_ptr<EC_GROUP>(EC_GROUP_new_curve_GFp(pOssl, aOssl, bOssl, ctx.get()), EC_GROUP_free);
	if (curve == NULL)
		throw runtime_error("failed to create OpenSSL Dlog group");

	BN_free(pOssl);
	BN_free(aOssl);
	BN_free(bOssl);

}

int OpenSSLDlogECFp::calcK(biginteger & p){
	int bitsInp = NumberOfBits(p);
	int k = floor((0.4 * bitsInp) / 8) - 1;
	//For technical reasons of how we chose to do the padding for encoding and decoding (the least significant byte of the encoded string contains the size of the 
	//the original binary string sent for encoding, which is used to remove the padding when decoding) k has to be <= 255 bytes so that the size can be encoded in the padding.
	if (k > 255) {
		k = 255;
	}
	return k;
}

shared_ptr<ECElement> OpenSSLDlogECFp::createPoint(const shared_ptr<EC_POINT> & point) {
	OpenSSLECFpPoint* newPoint = new OpenSSLECFpPoint(point, this);
	return shared_ptr<OpenSSLECFpPoint>(newPoint);
}

string OpenSSLDlogECFp::getGroupType() {
	return "ECFp";
}

bool OpenSSLDlogECFp::isMember(GroupElement* element) {
	// Checks that the element is the correct object.
	auto point = dynamic_cast<OpenSSLECFpPoint*>(element);
	if (point == NULL) {
		throw invalid_argument("groupElement doesn't match the DlogGroup");
	}

	// Infinity point is a valid member.
	if (point->isInfinity()) {
		return true;
	}

	// A point (x, y) is a member of a Dlog group with prime order q over an Elliptic Curve if it meets the following two conditions:
	// 1)	P = (x,y) is a point in the Elliptic curve, i.e (x,y) is a solution of the curves equation.
	// 2)	P = (x,y) is a point in the q-order group which is a sub-group of the Elliptic Curve.
	// Those two checks are done in two steps:
	// 1.	Checking that the point is on the curve, performed by EC_POINT_is_on_curve.
	// 2.	Checking that the point is in the Dlog group,performed by checkSubGroupMembership.
	bool valid = EC_POINT_is_on_curve(curve.get(), point->getPoint().get(), ctx.get());

	//The second check is implemented in ECFpUtility since it is independent of the underlying library (BC, Miracl, or other)
	//If we ever decide to change the implementation there will only be one place to change it.
	valid = valid && checkSubGroupMembership(point);

	return valid;
}

/**
* checks if the given point is in the given dlog group with the q prime order.
* A point is in the group if it in the q-order group which is a sub-group of the Elliptic Curve.
* Base assumption of this function is that checkCurveMembership function is already been called and returned true.
* @param curve
* @param point
* @return true if the given point is in the given dlog group.
*/
bool OpenSSLDlogECFp::checkSubGroupMembership(OpenSSLECFpPoint* point) {
	//we assume that the point is on the curve group
	//get the cofactor of the group
	biginteger h = (dynamic_pointer_cast<ECGroupParams>(groupParams))->getCofactor();

	//if the cofactor is 1 the sub-group is same as the elliptic curve equation which the point is in.
	if (h == 1) {
		return true;
	}

	biginteger y = point->getY();

	//if the cofactor is greater than 1, the point must have order q (same as the order of the group)

	//if the cofactor is 2 and the y coefficient is 0, the point has order 2 and is not in the group
	if (h == 2) {
		if (y == 0) return false;
		else return true;
	}

	// if the cofactor is 3 and p^2 = p^(-1), the point has order 3 and is not in the group
	if (h == 3) {
		auto power = exponentiate(point, 2);
		auto inverse = getInverse(point);
		if (power == inverse) return false;
		else return true;
	}

	// if the cofactor is 4, the point has order 2 if the y coefficient of the point is 0, 
	// or the the point has order 4 if the y coefficient of the point raised to two is 0.
	// in both cases the point is not in the group.
	if (h == 4) {
		if (y == 0) {
			return false;
		}
		auto power = exponentiate(point, 2);
		auto powerY = (dynamic_pointer_cast<ECElement>(power))->getY();
		if (powerY == 0) return false;
		else return true;
	}

	// if the cofactor is bigger than 4, there is no optimized way to check the order, so we operates the naive:
	// if the point raised to q (order of the group) is the identity, the point has order q too and is in the group. 
	// else, it is not in the group
	auto r = (dynamic_pointer_cast<ECGroupParams>(groupParams))->getQ();
	auto pointPowR = exponentiate(point, r);
	if (pointPowR->isIdentity()) return true;
	else return false;	
}

shared_ptr<GroupElement> OpenSSLDlogECFp::generateElement(bool bCheckMembership, vector<biginteger> & values) {
	if (values.size() != 2) {
		throw invalid_argument("To generate an ECElement you should pass the x and y coordinates of the point");
	}
	OpenSSLECFpPoint* point = new OpenSSLECFpPoint(values[0], values[1], this, bCheckMembership);
	return shared_ptr<OpenSSLECFpPoint>(point);
}

shared_ptr<GroupElement> OpenSSLDlogECFp::encodeByteArrayToGroupElement(const vector<unsigned char> & binaryString) {
	//Pseudo-code:
	/*If the length of binaryString exceeds k then return null.

	Let L be the length in bytes of p

	Choose a random byte array r of length L � k � 2 bytes

	Prepare a string newString of the following form: r || binaryString || binaryString.length (where || denotes concatenation) (i.e., the least significant byte of newString is the length of binaryString in bytes)

	Convert the result to a BigInteger (bIString)

	Compute the elliptic curve equation for this x and see if there exists a y such that (x,y) satisfies the equation.

	If yes, return (x,y)

	Else, go back to step 3 (choose a random r etc.) up to 80 times (This is an arbitrary hard-coded number).

	If did not find y such that (x,y) satisfies the equation after 80 trials then return null.
	*/

	int len = binaryString.size();
	if (len > k) return NULL;

	biginteger p = (dynamic_pointer_cast<ECFpGroupParams>(groupParams))->getP();
	int l = bytesCount(p);

	//std::shared_ptr<char> randomArray(new char[l - k - 2], default_delete<char[]>());
	vector<byte> randomArray(l - k - 2);
	std::shared_ptr<char> newString(new char[l - k - 1 + len], default_delete<char[]>());
	//copy the given string into the right place within the new string and put it length at the end of the new string.
	memcpy(newString.get() + l - k - 2, binaryString.data(), len);
	newString.get()[l - k - 2 + len] = (char)len;
	randomArray[0] = 1; // we fix the first bytes in the random array in order to fix the x value to be positive.
	//Create the openssl point. This point should contain the calculated value according to the given input.
	shared_ptr<EC_POINT> point(EC_POINT_new(curve.get()), EC_POINT_free);
	if (NULL == point) {
		return NULL;
	}

	int counter = 0;
	bool success = 0;
	BIGNUM * x = BN_new();
	do {
		//RAND_bytes((unsigned char*)randomArray.get() +1, l - k - 3);
		random->getPRGBytes(randomArray, 1, l - k - 3);
		memcpy(newString.get(), randomArray.data(), l - k - 2);

		//Convert the result to a BigInteger (bIString)
		if (NULL == (x = BN_bin2bn((unsigned char*)newString.get(), l - k - 1 + len, NULL))) break;

		//Try to create a point aith the generated x value.
		//if failed, go back to choose a random r etc.
		success = EC_POINT_set_compressed_coordinates_GFp(curve.get(), point.get(), x, 0, ctx.get());
		counter++;
	} while ((!success) && (counter <= 80)); //we limit the amount of times we try to 80 which is an arbitrary number.

											 //Delete the allocated memory.
	BN_free(x);
	
	//If a point could not be created, return 0;
	if (!success) return NULL;

	//Return the created point.
	return createPoint(point);
}

const vector<unsigned char> OpenSSLDlogECFp::decodeGroupElementToByteArray(GroupElement* groupElement) {
	auto point = dynamic_cast<OpenSSLECFpPoint*>(groupElement);
	// Checks that the element is the correct object.
	if (point == NULL) {
		throw invalid_argument("element type doesn't match the group type");
	}
	
	int size = bytesCount(point->getX());
	shared_ptr<byte> xByteArray(new byte[size], default_delete<byte[]>());
	auto tmp = biginteger_to_opensslbignum(point->getX());
	BN_bn2bin(tmp, xByteArray.get());
	BN_free(tmp);
	
	//The original size is placed in the last byte of x.
	int bOriginalSize = (int)(xByteArray.get()[size - 1]);
	std::shared_ptr<byte> b2(new byte[bOriginalSize], std::default_delete<byte[]>());

	//Copy the original byte array.
	memcpy(b2.get(), xByteArray.get() + size - 1 - bOriginalSize, bOriginalSize);
	return vector<byte>(b2.get(), b2.get()+ bOriginalSize);
}

shared_ptr<GroupElement> OpenSSLDlogECFp::reconstructElement(bool bCheckMembership, GroupElementSendableData* data) {
	ECElementSendableData* pointData = dynamic_cast<ECElementSendableData*> (data);
	OpenSSLECFpPoint* point = new OpenSSLECFpPoint(pointData->getX(), pointData->getY(), this, bCheckMembership);
	return shared_ptr<OpenSSLECFpPoint>(point);
}


void OpenSSLDlogECF2m::init(string fileName, string curveName, const shared_ptr<PrgFromOpenSSLAES> & random) {
	//Get the parameters of the group from the config file and create the groupParams member.
	createGroupParams();

	//Create the openSSL curve using the given curve parameters.
	createCurve();

	//Create the generator.
	OpenSSLECF2mPoint* temp = new OpenSSLECF2mPoint(dynamic_pointer_cast<ECF2mGroupParams>(groupParams)->getXg(), dynamic_pointer_cast<ECF2mGroupParams>(groupParams)->getYg(), this, true);
	generator = shared_ptr<OpenSSLECF2mPoint>(temp);

	this->random_element_gen = random;

	//Convert the order and cofactor into BIGNUM objects.
	BIGNUM *order, *cofactor;
	order = biginteger_to_opensslbignum(groupParams->getQ());
	cofactor = biginteger_to_opensslbignum(dynamic_pointer_cast<ECF2mGroupParams>(groupParams)->getCofactor());
	if (order == NULL || cofactor == NULL)
		throw runtime_error("failed to create OpenSSL Dlog group");

	// Initialize the OpenSSL's curve with the generator, order and cofactor.
	if (1 != EC_GROUP_set_generator(curve.get(), (dynamic_pointer_cast<OpenSSLECF2mPoint>(generator))->getPoint().get(), order, cofactor)) {
		BN_free(order);
		BN_free(cofactor);
		throw runtime_error("failed to create OpenSSL Dlog group");
	}
	//Release the allocated memory.
	BN_free(order);
	BN_free(cofactor);
}

void OpenSSLDlogECF2m::createCurve() {
	shared_ptr<ECGroupParams> params = dynamic_pointer_cast<ECF2mGroupParams>(groupParams);

	if (dynamic_pointer_cast<ECF2mKoblitz>(params)) {
		params = dynamic_pointer_cast<ECF2mKoblitz>(params)->getCurve();
	}
	// Open SSL accepts p, a, b to create the curve. 
	// In this case p represents the irreducible polynomial - each bit represents a term in the polynomial x^m + x^k3 + x^k2 + x^k1 + 1.
	BIGNUM* p = BN_new();
	BN_set_bit(p, 0);
	BN_set_bit(p, dynamic_pointer_cast<ECF2mGroupParams>(params)->getM());
	BN_set_bit(p, dynamic_pointer_cast<ECF2mGroupParams>(params)->getK1());
	
	if (dynamic_pointer_cast<ECF2mPentanomialBasis>(params)) {
		//In case of trinomial basis, set the bits in k2 and k3 indexes.
		BN_set_bit(p, dynamic_pointer_cast<ECF2mPentanomialBasis>(params)->getK2());
		BN_set_bit(p, dynamic_pointer_cast<ECF2mPentanomialBasis>(params)->getK3());
	}
	//Create the OpenSSL's curve.
	ctx = shared_ptr<BN_CTX>(BN_CTX_new(), BN_CTX_free);
	if (ctx == NULL)
		throw runtime_error("failed to create OpenSSL Dlog group");
	
	BIGNUM *a, *b;
	a = biginteger_to_opensslbignum(params->getA());
	b = biginteger_to_opensslbignum(params->getB());
	if (a == NULL || b == NULL || p == NULL)
		throw runtime_error("failed to create OpenSSL Dlog group");
	
	// Create the curve using a, b, p.
	curve = shared_ptr<EC_GROUP>(EC_GROUP_new_curve_GF2m(p, a, b, ctx.get()), EC_GROUP_free);
	if (curve == NULL)
		throw runtime_error("failed to create OpenSSL Dlog group");
	//Release the allocated memory.
	BN_free(p);
	BN_free(b);
	BN_free(a);
}

void OpenSSLDlogECF2m::createGroupParams() {
	// check that the given curve is in the field that matches the group.
	size_t index1 = curveName.find("B-");
	size_t index2 = curveName.find("K-");
	if (index1 != 0 && index2 != 0) {
		throw invalid_argument("curveName is not a curve over F2m field and doesn't match the DlogGroup type");
	}
	/* Get the curve parameters*/
	// The degree of the field.
	int m = stoi(ecConfig->Value(curveName, curveName));
	//If an irreducible trinomial t^m + t^k + 1 exists over GF(2), then the field polynomial p(t) is chosen to be the irreducible 
	//trinomial with the lowest degree middle term t^k. 
	//If no irreducible trinomial exists, then one selects instead a pentanomial t^m+t^k+t^k2+t^k3+1. The particular pentanomial 
	//chosen has the following properties: the second term t^k has the lowest degree among all irreducible pentanomials of degree m; 
	//the third term t^k2 has the lowest degree among all irreducible pentanomials of degree m and second term t^k; 
	//and the fourth term t^k3 has the lowest degree among all irreducible pentanomials of degree m, second term t^k, and third term t^k2.
	int k = stoi(ecConfig->Value(curveName, "k"));
	int k2 = 0;
	int k3 = 0;
	bool trinomialBasis = false;
	try {
		k2 = stoi(ecConfig->Value(curveName, "k2")); //we hold that as a string an not as int because is can be null.
		k3 = stoi(ecConfig->Value(curveName, "k3"));
	}
	catch (...) {
		trinomialBasis = true;
	}

	//Coefficients of the curve equaltion.
	biginteger a(ecConfig->Value(curveName, "a"));
	biginteger b = convert_hex_to_biginteger(ecConfig->Value(curveName, "b"));

	//Coordinates x, y, of the base point (generator).
	biginteger x = convert_hex_to_biginteger(ecConfig->Value(curveName, "x"));
	biginteger y = convert_hex_to_biginteger(ecConfig->Value(curveName, "y"));

	//The order of the group.
	biginteger q(ecConfig->Value(curveName, "r"));

	//the cofactor of the curve.
	biginteger h(ecConfig->Value(curveName, "h"));
	// for trinomial basis, where there is just one value represents the irreducible polynomial.
	if (trinomialBasis) {
		groupParams = make_shared<ECF2mTrinomialBasis>(q, x, y, m, k, a, b, h);

	}
	else { // pentanomial basis must have three k values.
		groupParams = make_shared<ECF2mPentanomialBasis>(q, x, y, m, k, k2, k3, a, b, h);
	}

	// koblitz curve
	if (index2 == 0) {
		groupParams = make_shared<ECF2mKoblitz>(dynamic_pointer_cast<ECF2mGroupParams>(groupParams), q, h);
	}
}


shared_ptr<ECElement> OpenSSLDlogECF2m::createPoint(const shared_ptr<EC_POINT> & point) {
	OpenSSLECF2mPoint* newPoint = new OpenSSLECF2mPoint(point, this);
	return shared_ptr<OpenSSLECF2mPoint>(newPoint);
}

string OpenSSLDlogECF2m::getGroupType() {
	return "ECF2m";
}

bool OpenSSLDlogECF2m::isMember(GroupElement* element) {
	// Checks that the element is the correct object.
	auto point = dynamic_cast<OpenSSLECF2mPoint*>(element);
	if (point == NULL) {
		throw invalid_argument("groupElement doesn't match the DlogGroup");
	}

	// Infinity point is a valid member.
	if (point->isInfinity()) {
		return true;
	}

	// A point (x, y) is a member of a Dlog group with prime order q over an Elliptic Curve if it meets the following two conditions:
	// 1)	P = (x,y) is a point in the Elliptic curve, i.e (x,y) is a solution of the curves equation.
	// 2)	P = (x,y) is a point in the q-order group which is a sub-group of the Elliptic Curve.
	// Those two checks are done in two steps:
	// 1.	Checking that the point is on the curve, performed by EC_POINT_is_on_curve.
	// 2.	Checking that the point is in the Dlog group,performed by checkSubGroupMembership.
	bool valid = EC_POINT_is_on_curve(curve.get(), point->getPoint().get(), ctx.get());

	//The second check is implemented in ECFpUtility since it is independent of the underlying library (BC, Miracl, or other)
	//If we ever decide to change the implementation there will only be one place to change it.
	valid = valid && checkSubGroupMembership(point);

	return valid;
}

/**
* checks if the given point is in the given dlog group with the q prime order.
* A point is in the group if it in the q-order group which is a sub-group of the Elliptic Curve.
* Base assumption of this function is that checkCurveMembership function is already been called and returned true.
* @param curve
* @param point
* @return true if the given point is in the given dlog group.
*/
bool OpenSSLDlogECF2m::checkSubGroupMembership(OpenSSLECF2mPoint* point) {
	//we assume that the point is on the curve group
	//get the cofactor of the group
	biginteger h = (dynamic_pointer_cast<ECGroupParams>(groupParams))->getCofactor();

	//if the cofactor is 1 the sub-group is same as the elliptic curve equation which the point is in.
	if (h == 1) {
		return true;
	}

	biginteger x = point->getX();

	//if the cofactor is greater than 1, the point must have order q (same as the order of the group)

	//if the cofactor is 2 and the x coefficient is 0, the point has order 2 and is not in the group
	if (h == 2) {
		if (x == 0) return false;
		else return true;
	}

	// if the cofactor is 3 and p^2 = p^(-1), the point has order 3 and is not in the group
	if (h == 3) {
		auto power = exponentiate(point, 2);
		auto inverse = getInverse(point);
		if (power == inverse) return false;
		else return true;
	}

	// if the cofactor is 4, the point has order 2 if the x coefficient of the point is 0, 
	// or the the point has order 4 if the x coefficient of the point raised to two is 0.
	// in both cases the point is not in the group.
	if (h == 4) {
		if (x == 0) {
			return false;
		}
		auto power = exponentiate(point, 2);
		auto powerX = (dynamic_pointer_cast<ECElement>(power))->getX();
		if (powerX == 0) return false;
		else return true;
	}

	// if the cofactor is bigger than 4, there is no optimized way to check the order, so we operates the naive:
	// if the point raised to q (order of the group) is the identity, the point has order q too and is in the group. 
	// else, it is not in the group
	auto r = (dynamic_pointer_cast<ECGroupParams>(groupParams))->getQ();
	auto pointPowR = exponentiate(point, r);
	if (pointPowR->isIdentity()) return true;
	else return false;
}

shared_ptr<GroupElement> OpenSSLDlogECF2m::generateElement(bool bCheckMembership, vector<biginteger> & values) {
	if (values.size() != 2) {
		throw invalid_argument("To generate an ECElement you should pass the x and y coordinates of the point");
	}
	OpenSSLECF2mPoint* point = new OpenSSLECF2mPoint(values[0], values[1], this, bCheckMembership);
	return shared_ptr<OpenSSLECF2mPoint>(point);
}

/*
 * Currently we don't support this conversion.</B> It will be implemented in the future. 
 * Meanwhile we return null.
*/
shared_ptr<GroupElement> OpenSSLDlogECF2m::encodeByteArrayToGroupElement(const vector<unsigned char> & binaryString) {


    shared_ptr<EC_POINT> point(EC_POINT_new(curve.get()), EC_POINT_free);
    if (NULL == point) {
        return NULL;
    }



    EC_POINT_oct2point(curve.get(), point.get(), binaryString.data(), binaryString.size(), ctx.get());

    return createPoint(point);

}

/*
* Currently we don't support this conversion.</B> It will be implemented in the future.
* Meanwhile we return empty vector.
*/
const vector<unsigned char> OpenSSLDlogECF2m::decodeGroupElementToByteArray(GroupElement* groupElement) {
	auto point = dynamic_cast<OpenSSLECF2mPoint*>(groupElement);
	// Checks that the element is the correct object.
	if (point == NULL)
		throw invalid_argument("element type doesn't match the group type");

    vector<byte> vec(100);
    EC_POINT_is_on_curve(curve.get(), point->getPoint().get(), ctx.get());

    int size = EC_POINT_point2oct(curve.get(),
                                  point->getPoint().get(),
                                  POINT_CONVERSION_COMPRESSED,
                                  vec.data(),
                                  vec.size(),
                                  ctx.get());

    vec.resize(size);

	return vec;
}

shared_ptr<GroupElement> OpenSSLDlogECF2m::reconstructElement(bool bCheckMembership, GroupElementSendableData* data) {
	ECElementSendableData* pointData = dynamic_cast<ECElementSendableData*> (data);
	OpenSSLECF2mPoint * point = new OpenSSLECF2mPoint(pointData->getX(), pointData->getY(), this, bCheckMembership);
	return shared_ptr<OpenSSLECF2mPoint>(point);
}

/************************************************************/
/****************EC Group elements classes*******************/
/************************************************************/


bool OpenSSLPoint::isInfinity() {
	if ((x == NULL) && (y == NULL)) 
		return true;
	else 
		return false;
}

OpenSSLECFpPoint::OpenSSLECFpPoint(const biginteger & x, const biginteger & y, OpenSSLDlogECFp* curve, bool bCheckMembership) {
	//if (bCheckMembership) {
		//auto params = dynamic_pointer_cast<ECFpGroupParams>(curve->getGroupParams());
		//checks if the given parameters are valid point on the curve.
	//	bool valid = checkCurveMembership(params.get(), x, y);
		// checks validity
	//	if (valid == false) // if not valid, throws exception
		//	throw invalid_argument("x, y values are not a point on this curve");
//	}
	//Create a point in the field with the given parameters, done by OpenSSL's code.
	BIGNUM *xOssl = biginteger_to_opensslbignum(x);
	BIGNUM *yOssl = biginteger_to_opensslbignum(y);
	if (x == NULL || y == NULL) 
		throw runtime_error("Failed to create the point");
	
	// Create the element.
	point = shared_ptr<EC_POINT>(EC_POINT_new(curve->getCurve().get()), EC_POINT_free);
	if (NULL == point) 
		throw runtime_error("Failed to create the point");

	//If the validity check done by OpenSSL did succeed, the function return 1.
	if (1 != EC_POINT_set_affine_coordinates_GFp(curve->getCurve().get(), point.get(), xOssl, yOssl, curve->getCTX().get())) {
		BN_free(xOssl);
		BN_free(yOssl);
		throw runtime_error("Failed to create the point");
	}
	//Release the allocated memory.
	BN_free(xOssl);
	BN_free(yOssl);

	//Keep the coordinates for performance reasons. See long comment above next to declaration.
	this->x = x;
	this->y = y;

	if (bCheckMembership) {
		//check if the given parameters are valid point on the curve.
		bool valid = curve->isMember(this);
		// checks validity
		if (valid == false) {// if not valid, throws exception

			throw new invalid_argument("x, y values are not a point on this curve");
		}
	}
}

/**
* Checks if the given x and y represent a valid point on the given curve,
* i.e. if the point (x, y) is a solution of the curves equation.
* @param params elliptic curve over Fp parameters
* @param x coefficient of the point
* @param y coefficient of the point
* @return true if the given x and y represented a valid point on the given curve
*/
bool OpenSSLECFpPoint::checkCurveMembership(ECFpGroupParams* params, const biginteger & x, const biginteger & y) {

	/* get a, b, p from group params */
	biginteger a = params->getA();
	biginteger b = params->getB();
	biginteger p = params->getP();

	//Calculates the curve equation with the given x,y.

	// compute x^3
	biginteger x3 = mp::powm(x, 3, p);
	// compute x^3+ax+b
	biginteger rightSide = (x3 + (a*x) + b) % p;
	// compute y^2
	biginteger leftSide = mp::powm(y, 2, p);
	// if the the equation is solved - the point is in the elliptic curve and return true
	if (leftSide == rightSide)
		return true;
	else return false;
}

OpenSSLECFpPoint::OpenSSLECFpPoint(const shared_ptr<EC_POINT> & point, OpenSSLDlogECFp* curve) {

	this->point = point;

	//Set x,y values.
	if (EC_POINT_is_at_infinity(curve->getCurve().get(), point.get())) {
		x = NULL;
		y = NULL;
	} else {
		auto xBN = BN_new();
		auto yBN = BN_new();
		if (xBN == NULL || yBN == NULL) 
			throw runtime_error("Failed to create the point");

		//Get x and y values.
		EC_POINT_get_affine_coordinates_GFp(curve->getCurve().get(), point.get(), xBN, yBN, curve->getCTX().get());

		x = opensslbignum_to_biginteger(xBN);
		y = opensslbignum_to_biginteger(yBN);

        BN_free(xBN);
        BN_free(yBN);
	}
}

OpenSSLECF2mPoint::OpenSSLECF2mPoint(const biginteger & x, const biginteger & y, OpenSSLDlogECF2m* curve, bool bCheckMembership) {
	//Create a point in the field with the given parameters, done by OpenSSL's code.
	BIGNUM *xOssl = biginteger_to_opensslbignum(x);
	BIGNUM *yOssl = biginteger_to_opensslbignum(y);
	if (x == NULL || y == NULL)
		throw runtime_error("Failed to create the point");

	// Create the element.
	point = shared_ptr<EC_POINT> (EC_POINT_new(curve->getCurve().get()), EC_POINT_free);
	if (NULL == point)
		throw runtime_error("Failed to create the point");

	//If the validity check done by OpenSSL did not succeed, then EC_POINT_set_affine_coordinates_GF2m returns 0,
	//indicating that this is not a valid point
	if (1 != EC_POINT_set_affine_coordinates_GF2m(curve->getCurve().get(), point.get(), xOssl, yOssl, curve->getCTX().get())) {
		BN_free(xOssl);
		BN_free(yOssl);
		throw invalid_argument("x, y values are not a point on this curve");
	}

	//Release the allocated memory.
	BN_free(xOssl);
	BN_free(yOssl);

	//Keep the coordinates for performance reasons. See long comment above next to declaration.
	this->x = x;
	this->y = y;

	if (bCheckMembership) {
		//check if the given parameters are valid point on the curve.
		bool valid = curve->isMember(this);
		// checks validity
		if (valid == false) {// if not valid, throws exception

			throw invalid_argument("x, y values are not a point on this curve");
		}
	}
}

OpenSSLECF2mPoint::OpenSSLECF2mPoint(const shared_ptr<EC_POINT> & point, OpenSSLDlogECF2m* curve) {
	this->point = point;

	//Set x,y values.
	if (EC_POINT_is_at_infinity(curve->getCurve().get(), point.get())) {
		x = NULL;
		y = NULL;
	}
	else {
		auto xBN = BN_new();
		auto yBN = BN_new();
		if (xBN == NULL || yBN == NULL)
			throw runtime_error("Failed to create the point");

		//Get x and y values.
		EC_POINT_get_affine_coordinates_GF2m(curve->getCurve().get(), point.get(), xBN, yBN, curve->getCTX().get());

		x = opensslbignum_to_biginteger(xBN);
		y = opensslbignum_to_biginteger(yBN);

		BN_free(xBN);
		BN_free(yBN);
	}
}
