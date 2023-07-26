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


#include "../../include/primitives/TrapdoorPermutationOpenSSL.hpp"


void OpenSSLRSAPermutation::setKey(const shared_ptr<PublicKey> & publicKey, const shared_ptr<PrivateKey> & privateKey)
{
    auto rsaPubKey = dynamic_pointer_cast<RSAPublicKey>(publicKey);
	auto rsaPrivKey = dynamic_pointer_cast<RSAPrivateKey>(privateKey);

	if (!rsaPubKey || (privateKey != nullptr && !rsaPrivKey))
		throw InvalidKeyException("Key type doesn't match the trapdoor permutation type");
	
	// Gets the values of modulus (N), pubExponent (e), privExponent (d).
	biginteger pubExponent = rsaPubKey->getPublicExponent();
	modulus = rsaPubKey->getModulus();

	if (privateKey)
	{ // if there is a privateKey
		biginteger privExponent = rsaPrivKey->getPrivateExponent();
		auto crtKey = dynamic_pointer_cast<RSAPrivateCrtKey>(privateKey);

		if (crtKey)
		{ // If private key is CRT private key.
			//Get all the crt parameters
			biginteger p = crtKey->getPrimeP();
            biginteger q = crtKey->getPrimeQ();
            biginteger dp = crtKey->getPrimeExponentP();
            biginteger dq = crtKey->getPrimeExponentQ();
            biginteger crt = crtKey->getCrtCoefficient();

			//Initialize the Openssl's object with crt key.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
			_rsa = initRSAPublicPrivateCrt(pubExponent, privExponent, p, q, dp, dq, crt);
#else
			_rsa = initRSAPublicPrivateCrt(pubExponent, privExponent, p, q, dp, dq, crt);
#endif
		}
		else
        {
		    //If private key is key with N, e, d.
			//Initialize the openSSL's object with the RSA parameters - n, e, d.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
			_rsa = initRSAPublicPrivate(pubExponent, privExponent);
#else
			_rsa = initRSAPublicPrivate(pubExponent, privExponent);
#endif
		}
	}
	else
    {
        // privateKey == NULL
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		_rsa = initRSAPublic(pubExponent);
#else
		_rsa = initRSAPublic(pubExponent);
#endif
	}
	// Call the parent's set key function that sets the keys.
	TrapdoorPermutation::setKey(publicKey, privateKey);
}

shared_ptr<RSA> OpenSSLRSAPermutation::initRSAPublicPrivateCrt(biginteger & pubExp, biginteger & privExp, biginteger & p,
	biginteger & q, biginteger & dp, biginteger & dq, biginteger & crt) {
    auto rsa = shared_ptr<RSA>(RSA_new(), RSA_free);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	//Convert all the parameters to OpenSSL's terminology and set them to the Openssl's rsa object.
	rsa->n = biginteger_to_opensslbignum(modulus);
	rsa->e = biginteger_to_opensslbignum(pubExp);
	rsa->d = biginteger_to_opensslbignum(privExp);
	rsa->p = biginteger_to_opensslbignum(p);
	rsa->q = biginteger_to_opensslbignum(q);
	rsa->dmp1 = biginteger_to_opensslbignum(dp);
	rsa->dmq1 = biginteger_to_opensslbignum(dq);
	rsa->iqmp = biginteger_to_opensslbignum(crt);

	if ((rsa->n == NULL) || (rsa->e == NULL) || (rsa->d == NULL) || (rsa->p == NULL) ||
		(rsa->q == NULL) || (rsa->dmp1 == NULL) || (rsa->dmq1 == NULL) || (rsa->iqmp == NULL)) {
		return nullptr;
	}
	return rsa;
#else
	int setKeyRes = RSA_set0_key(rsa.get(), biginteger_to_opensslbignum(modulus), biginteger_to_opensslbignum(pubExp),
                 biginteger_to_opensslbignum(privExp));
	int setFactorsRes = RSA_set0_factors(rsa.get(), biginteger_to_opensslbignum(p), biginteger_to_opensslbignum(q));
	int setCrtRes = RSA_set0_crt_params(rsa.get(), biginteger_to_opensslbignum(dp), biginteger_to_opensslbignum(dq),
	        biginteger_to_opensslbignum(crt));
	if (setKeyRes == 0 || setFactorsRes == 0 || setCrtRes ==0) return nullptr;

    return rsa;
#endif

}

shared_ptr<RSA> OpenSSLRSAPermutation::initRSAPublicPrivate(biginteger & pubExponent, biginteger & privExponent) {
	//Convert all the parameters to OpenSSL's terminology and set them to the Openssl's rsa object.
    auto rsa = shared_ptr<RSA>(RSA_new(), RSA_free);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	rsa->n = biginteger_to_opensslbignum(modulus);
	rsa->e = biginteger_to_opensslbignum(pubExponent);
	rsa->d = biginteger_to_opensslbignum(privExponent);
	if ((rsa->n == NULL) || (rsa->e == NULL) || (rsa->d == NULL)) {
		return nullptr;
	}
	return rsa;
#else
    int setKeyRes = RSA_set0_key(rsa.get(), biginteger_to_opensslbignum(modulus), biginteger_to_opensslbignum(pubExponent),
                 biginteger_to_opensslbignum(privExponent));
    if(setKeyRes == 0) return nullptr;
    return rsa;
#endif
}

shared_ptr<RSA> OpenSSLRSAPermutation::initRSAPublic(biginteger & pubExponent) {
	//Convert all the parameters to OpenSSL's terminology and set them to the Openssl's rsa object.
    auto rsa = shared_ptr<RSA>(RSA_new(), RSA_free);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	rsa->n = biginteger_to_opensslbignum(modulus);
	rsa->e = biginteger_to_opensslbignum(pubExponent);
	if ((rsa->n == NULL) || (rsa->e == NULL)) {
		return nullptr;
	}
	return rsa;
#else
    int setKeyRes = RSA_set0_key(rsa.get(), biginteger_to_opensslbignum(modulus), biginteger_to_opensslbignum(pubExponent), NULL);
    if(setKeyRes == 0) return nullptr;
    return rsa;
#endif
}

KeyPair OpenSSLRSAPermutation::generateKey(int keySize) {

	RSA* pair = RSA_new();
	BIGNUM* bne = BN_new();
	BN_set_word(bne, 65537);
	//Generate open SSL's RSA key.
	RSA_generate_key_ex(pair, keySize, bne, NULL);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	//Convert the key parameters into KeyPair.
	biginteger mod = opensslbignum_to_biginteger(pair->n);
	biginteger pubExp = opensslbignum_to_biginteger(pair->e);
	biginteger privExp = opensslbignum_to_biginteger(pair->d);

#else
	BIGNUM *n, *e, *d;
	n = BN_new();
	e = BN_new();
	d = BN_new();
	RSA_get0_key(pair, (const BIGNUM **)&n, (const BIGNUM **)&e, (const BIGNUM **) &d);
    biginteger mod = opensslbignum_to_biginteger(n);
    biginteger pubExp = opensslbignum_to_biginteger(e);
    biginteger privExp = opensslbignum_to_biginteger(d);
#endif
    KeyPair kp(new RSAPublicKey(mod, pubExp), new RSAPrivateKey(mod, privExp));
	RSA_free(pair);
	BN_free(bne);
	return kp;
}


shared_ptr<TPElement> OpenSSLRSAPermutation::compute(TPElement * tpEl) {
	if (!isKeySet())
		throw IllegalStateException("keys aren't set");
	RSAElement * rsaEl = dynamic_cast<RSAElement *>(tpEl);
	if (!rsaEl) 
		throw invalid_argument("trapdoor element type doesn't match the trapdoor permutation type");

	// Get the underlying biginteger object.
	biginteger elementP = rsaEl->getElement();

	//Call Openssl's function.
	biginteger result = computeRSA(elementP);

	// Create and initialize a RSAElement with the result.
	auto returnEl = make_shared<RSAElement>(modulus, result, false);

	return returnEl; // Return the created TPElement.
}

biginteger OpenSSLRSAPermutation::computeRSA(biginteger & elementP) {
	ERR_load_crypto_strings();
	// Seed the random geneartor.
	RAND_poll(); // reseeds using hardware state (clock, interrupts, etc).
	int size = RSA_size(_rsa.get());
	vector<byte> ret(size); //will hold the output
	
	//convert the element into bytes vector.
	size_t encodedSize = bytesCount(elementP);
	vector<byte> encodedBi(encodedSize);
	encodeBigInteger(elementP, encodedBi.data(), encodedSize);

	//Encrypt the array
	int success = RSA_public_encrypt(encodedSize, encodedBi.data(), ret.data(), _rsa.get(), RSA_NO_PADDING);

	if (-1 == success)
	{
		string error(ERR_reason_error_string(ERR_get_error()));
		throw runtime_error("failed to compute rsa " + error);
	}

	//Convert the output into biginteger.
	biginteger result = decodeBigInteger(ret.data(), size);
	return result;
}

shared_ptr<TPElement> OpenSSLRSAPermutation::invert(TPElement * tpEl) {
	if (!isKeySet())
		throw IllegalStateException("keys aren't set");
	// If only the public key was set and not the private key - can't do the invert, throw exception.
	if (privKey == NULL && pubKey != NULL) 
		throw InvalidKeyException("in order to decrypt a message, this object must be initialized with private key");
	RSAElement * rsaEl = dynamic_cast<RSAElement *>(tpEl);
	if (!rsaEl)
		throw invalid_argument("trapdoor element type doesn't match the trapdoor permutation type");

	// Get the underlying biginteger object.
	biginteger elementP = rsaEl->getElement();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	int size = RSA_size(_rsa.get());
#else
	int size = RSA_size(_rsa.get());
#endif
	vector<byte> ret(size); //Will hold the output

	//Convert the element to bytes vector.
	size_t encodedSize = bytesCount(elementP);
	vector<byte> encodedBi(encodedSize);
	encodeBigInteger(elementP, encodedBi.data(), encodedSize);
	
	// Invert the RSA permutation on the given bytes.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	RSA_private_decrypt(encodedSize, encodedBi.data(), ret.data(), _rsa.get(), RSA_NO_PADDING);
#else
	RSA_private_decrypt(encodedSize, encodedBi.data(), ret.data(), _rsa.get(), RSA_NO_PADDING);
#endif
	biginteger resValue = decodeBigInteger(ret.data(), size);
	// Create and initialize a RSAElement with the result.
	auto returnEl = make_shared<RSAElement>(modulus, resValue, false);
	return returnEl; // Return the result TPElement.
}
TPElValidity OpenSSLRSAPermutation::isElement(TPElement* tpEl) {
	if (!isKeySet())
		throw IllegalStateException("keys aren't set");
	RSAElement * rsaEl = dynamic_cast<RSAElement *>(tpEl);
	if (!rsaEl)
		throw invalid_argument("trapdoor element type doesn't match the trapdoor permutation type");

	TPElValidity validity;
	biginteger value = rsaEl->getElement();

	// If the modulus is unknown - returns DONT_KNOW. 
	if (modulus == NULL)
		validity = TPElValidity::DONT_KNOW;
	// If the value is valid (between 1 to (mod n) - 1) returns VALID.
	else if(value > 0 && value < modulus)
		validity = TPElValidity::VALID;
	// If the value is invalid returns NOT_VALID. 
	else
		validity = TPElValidity::NOT_VALID;

	// Returns the correct TPElValidity.
	return validity;
}

shared_ptr<TPElement> OpenSSLRSAPermutation::generateRandomTPElement() {
	if (!isKeySet())
		throw IllegalStateException("keys aren't set");

	//Call the constructor that generate random values.
	return make_shared<RSAElement>(modulus, random);
}