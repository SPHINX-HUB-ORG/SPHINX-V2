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


#include "../../include/primitives/PrfOpenSSL.hpp"
#include <algorithm>

/*************************************************/
/**** OpenSSLPRP ***/
/*************************************************/

SecretKey OpenSSLPRP::generateKey(int keySize) {
	//Generate random bytes to set as the key.
	vector<byte> vec(keySize / 8);
	prg->getPRGBytes(vec, 0, keySize / 8);
	SecretKey sk(vec, getAlgorithmName());
	return sk;
}

void OpenSSLPRP::computeBlock(const vector<byte> & inBytes, int inOff, vector<byte> &outBytes, int outOff) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	// Checks that the offset and length are correct.
	if ((inOff > (int)inBytes.size()) || (inOff + getBlockSize() > (int)inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	
	const byte* input = & inBytes[inOff];
	
	int size;
	int blockSize = getBlockSize();

	//Make anough space in the output vector.
	if ((int) outBytes.size() - outOff < blockSize)
		outBytes.resize(outOff + blockSize);
	
	// Compute the prp on the given input array, put the result in ret.
	EVP_EncryptUpdate(computeP, outBytes.data() + outOff, &size, input, blockSize);
}

void OpenSSLPRP::optimizedCompute(const vector<byte> & inBytes, vector<byte> &outBytes) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	if ((inBytes.size() % getBlockSize()) != 0)
		throw out_of_range("inBytes should be aligned to the block size");
	
	int size = inBytes.size();

	//Make anough space in the output vector.
	if ((int) outBytes.size() < size)
		outBytes.resize(size);
	
	// Compute the prp on each block and put the result in the output array.
	EVP_EncryptUpdate(computeP, outBytes.data(), &size, &inBytes[0], size);
}

void OpenSSLPRP::computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte> &outBytes, int outOff, int outLen) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	// the checks on the offset and length are done in the computeBlock(inBytes, inOff, outBytes, outOff).
	if (inLen == outLen && inLen == getBlockSize()) //Checks that the lengths are the same as the block size.
		computeBlock(inBytes, inOff, outBytes, outOff);
	else
		throw out_of_range("Wrong size");
}


void OpenSSLPRP::computeBlock(const vector<byte> & inBytes, int inOffset, int inLen, vector<byte> &outBytes, int outOffset) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	// The checks on the offset and length is done in the computeBlock (inBytes, inOffset, outBytes, outOffset).
	if (inLen == getBlockSize()) //Checks that the input length is the same as the block size.
		computeBlock(inBytes, inOffset, outBytes, outOffset);
	else
		throw out_of_range("Wrong size");
}

void OpenSSLPRP::invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	// Checks that the offsets are correct. 
	if ((inOff > (int)inBytes.size()) || (inOff + getBlockSize() > (int)inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	
	//Make anough space in the output vector.
	if ((int) outBytes.size() - outOff < getBlockSize())
		outBytes.resize(getBlockSize() + outOff);
	int size;

	//Invert the prp on the given input array, put the result in ret.
	EVP_DecryptUpdate(invertP, outBytes.data(), &size, &inBytes[inOff], getBlockSize());
}

void OpenSSLPRP::optimizedInvert(const vector<byte> & inBytes, vector<byte> &outBytes) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	if ((inBytes.size() % getBlockSize()) != 0) 
		throw out_of_range("inBytes should be aligned to the block size");
	
	int size = inBytes.size();
	//Make anough space in the output vector.
	if ((int) outBytes.size()< size)
		outBytes.resize(size);
	
	// compute the prp on each block and put the result in the output array.
	EVP_DecryptUpdate(invertP, outBytes.data(), &size, &inBytes[0], size);
}

void OpenSSLPRP::invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff, int len) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	// the checks of the offset and lengths are done in the invertBlock(inBytes, inOff, outBytes, outOff)
	if (len == getBlockSize()) //Checks that the length is the same as the block size
		invertBlock(inBytes, inOff, outBytes, outOff);
	else
		throw out_of_range("Wrong size");
}

OpenSSLPRP::~OpenSSLPRP() {
	//Delete the underlying Openssl's objects.
	EVP_CIPHER_CTX_cleanup(computeP);
	EVP_CIPHER_CTX_cleanup(invertP);
	EVP_CIPHER_CTX_free(computeP);
	EVP_CIPHER_CTX_free(invertP);
}

/*************************************************/
/**** OpenSSLAES ***/
/*************************************************/

OpenSSLAES::OpenSSLAES(const shared_ptr<PrgFromOpenSSLAES> & setRandom) {
	//Create the underlying Openssl's AES objects.
	prg = setRandom;
	computeP = EVP_CIPHER_CTX_new();
	invertP = EVP_CIPHER_CTX_new();
}

void OpenSSLAES::setKey(SecretKey & secretKey) {
	auto keyVec = secretKey.getEncoded();
	int len = keyVec.size();
	// AES key size should be 128/192/256 bits long.
	if (len != 16 && len != 24 && len != 32)
		throw InvalidKeyException("AES key size should be 128/192/256 bits long");

	// Set the key to the underlying objects.
	byte* keyBytes = &keyVec[0];
	int bitLen = len * 8; //number of bits in key.

	// Create the requested block cipher.
	const EVP_CIPHER* cipher=NULL;
	switch (bitLen) {
	case 128: cipher = EVP_aes_128_ecb();
		break;
	case 192: cipher = EVP_aes_192_ecb();
		break;
	case 256: cipher = EVP_aes_256_ecb();
		break;
	default: break;
	}

	// Initialize the AES objects with the key.
	EVP_EncryptInit(computeP, cipher, keyBytes, NULL);
	EVP_DecryptInit(invertP, cipher, keyBytes, NULL);

	// Set the AES objects with NO PADDING.
	EVP_CIPHER_CTX_set_padding(computeP, 0);
	EVP_CIPHER_CTX_set_padding(invertP, 0);

	_isKeySet = true;
}

/*************************************************/
/**** OpenSSLHMAC ***/
/*************************************************/
OpenSSLHMAC::OpenSSLHMAC(string hashName, const shared_ptr<PrgFromOpenSSLAES> & random) {
	//Create the underlying Openssl's Hmac object.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	hmac = new HMAC_CTX;
	HMAC_CTX_init(hmac);
#else
    hmac = HMAC_CTX_new();
#endif
    OpenSSL_add_all_digests();


	/*
	* The way we call the hash is not the same as OpenSSL. For example: we call "SHA-1" while OpenSSL calls it "SHA1".
	* So the hyphen should be deleted.
	*/
	hashName.erase(remove(hashName.begin(), hashName.end(), '-'), hashName.end());
	// Get the underlying hash function.
	const EVP_MD *md = EVP_get_digestbyname(hashName.c_str());

	// Create an Hmac object and initialize it with the created hash and default key.
	int res = HMAC_Init_ex(hmac, "012345678", 0, md, NULL);
	if (0 == res)
		throw runtime_error("failed to create hmac");

	this->random = random;
}

void OpenSSLHMAC::setKey(SecretKey & secretKey) {
	// Initialize the Hmac object with the given key.
	auto secVec = secretKey.getEncoded();
	HMAC_Init_ex(hmac, &secVec[0], secVec.size(), NULL, NULL);
	_isKeySet = true;
	_key = secretKey;
}

string OpenSSLHMAC::getAlgorithmName() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	int type = EVP_MD_type(hmac->md);
#else
    int type = EVP_MD_type(HMAC_CTX_get_md(hmac));
#endif
	// Convert the type to a name.
	const char* name = OBJ_nid2sn(type);
	return "Hmac/" + string(name);
}

void OpenSSLHMAC::computeBlock(const vector<byte> & inBytes, int inOff, vector<byte> &outBytes, int outOff) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	throw out_of_range("Size of input is not specified");
}

void OpenSSLHMAC::computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte> &outBytes, int outOff, int outLen) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");

	// The checks of the offsets and lengths are done in the conputeBlock (inBytes, inOff, inLen, outBytes, outOff).
	// make sure the output size is correct.
	if (outLen == getBlockSize())
		computeBlock(inBytes, inOff, inLen, outBytes, outOff);
	else
		throw out_of_range("Output size is incorrect");
}

void OpenSSLHMAC::computeBlock(const vector<byte> & inBytes, int inOffset, int inLen, vector<byte> &outBytes, int outOffset) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	
	// Check that the offset and length are correct.
	if ((inOffset > (int) inBytes.size()) || (inOffset + inLen > (int) inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	
	// Update the Hmac object.
	HMAC_Update(hmac, &inBytes[inOffset], inLen);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	int size = EVP_MD_size(hmac->md);	// Get the size of the hash output.
#else
    int size = EVP_MD_size(HMAC_CTX_get_md(hmac));
#endif
	if ((int)outBytes.size() < outOffset + size)
		outBytes.resize(outOffset + size);

	//Compute the final function and copy the output the the given output array.
	if (0 == (HMAC_Final(hmac, outBytes.data(), NULL)))
		throw runtime_error("failed to init hmac object");

	// initialize the Hmac again in order to enable repeated calls.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	if (0 == (HMAC_Init_ex(hmac, hmac->key, hmac->key_length, hmac->md, NULL)))
#else
	    SecretKey key = _key;
	    if (0 == (HMAC_Init_ex(hmac, (const void*)_key.getEncoded().data(), key.getEncoded().size(),
	            HMAC_CTX_get_md(hmac), NULL)))
#endif
		throw runtime_error("failed to init hmac object");
}

SecretKey OpenSSLHMAC::generateKey(int keySize) {
	// Generate a random string of bits of length keySize, which has to be greater that zero. 

	// If the key size is zero or less - throw exception.
	if (keySize <= 0)
		throw invalid_argument("key size must be greater than 0");

	// The key size has to be a multiple of 8 so that we can obtain an array of random bytes which we use
	// to create the SecretKey.
	if ((keySize % 8) != 0)
		throw invalid_argument("Wrong key size: must be a multiple of 8");

	vector<byte> genBytes(keySize / 8); // Creates a byte vector of size keySize.
	random->getPRGBytes(genBytes, 0, keySize / 8);	// Generates the bytes using the random.
	return SecretKey(genBytes.data(), keySize/8, "");
}

vector<byte> OpenSSLHMAC::mac(const vector<byte> &msg, int offset, int msgLen) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	// Creates the tag.
	vector<byte> tag(getMacSize());
	// Computes the hmac operation.
	computeBlock(msg, offset, msgLen, tag, 0);
	//Returns the tag.
	return tag;
}

bool OpenSSLHMAC::verify(const vector<byte> &msg, int offset, int msgLength, vector<byte>& tag) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	// If the tag size is not the mac size - returns false.
	if ((int) tag.size() != getMacSize())
		return false;
	// Calculate the mac on the msg to get the real tag.
	vector<byte> macTag = mac(msg, offset, msgLength);

	// Compares the real tag to the given tag.
	// for code-security reasons, the comparison is fully performed. that is, even if we know already after the first few bits 
	// that the tag is not equal to the mac, we continue the checking until the end of the tag bits.
	bool equal = true;
	int length = macTag.size();
	for (int i = 0; i<length; i++) {
		if (macTag[i] != tag[i]) {
			equal = false;
		}
	}
	return equal;
}

void OpenSSLHMAC::update(vector<byte> & msg, int offset, int msgLen) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");

	// Update the Hmac object.
	HMAC_Update(hmac, &msg[offset], msgLen);
}

void OpenSSLHMAC::doFinal(vector<byte> & msg, int offset, int msgLength, vector<byte> & tag_res) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	
	// Update the last msg block.
	update(msg, offset, msgLength);

	if ((int) tag_res.size() < getMacSize())
		tag_res.resize(getMacSize());

	// compute the final function and copy the output the the given output array
	if (0 == (HMAC_Final(hmac, tag_res.data(), NULL)))
		throw runtime_error("failed to init hmac object");

	//initialize the Hmac again in order to enable repeated calls.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (0 == (HMAC_Init_ex(hmac, hmac->key, hmac->key_length, hmac->md, NULL)))
#else
    SecretKey key = _key;
    if (0 == (HMAC_Init_ex(hmac, (const void*)_key.getEncoded().data(), key.getEncoded().size(),
                           HMAC_CTX_get_md(hmac), NULL)))
#endif
		throw runtime_error("failed to init hmac object");
}

OpenSSLHMAC::~OpenSSLHMAC()
{
	//Delete the underlying openssl's object.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	HMAC_CTX_cleanup(hmac);
	delete hmac;
#else
    HMAC_CTX_free(hmac);
#endif

}

/*************************************************/
/**** OpenSSLTripleDES ***/
/*************************************************/

OpenSSLTripleDES::OpenSSLTripleDES() {
	// Create the underlying openssl's objects.
	computeP = EVP_CIPHER_CTX_new();
	invertP = EVP_CIPHER_CTX_new();
	prg = get_seeded_prg();
}

void OpenSSLTripleDES::setKey(SecretKey & secretKey) {
	vector<byte> keyBytesVector = secretKey.getEncoded();
	int len = keyBytesVector.size();

	// TripleDES key size should be 128/192 bits long.
	if (len != 16 && len != 24)
		throw InvalidKeyException("TripleDES key size should be 128/192 bits long");

	// Create the requested block cipher.
	const EVP_CIPHER* cipher = EVP_des_ede3();

	// Initialize the Triple DES objects with the key.
	EVP_EncryptInit(computeP, cipher, &keyBytesVector[0], NULL);
	EVP_DecryptInit(invertP, cipher, &keyBytesVector[0], NULL);

	// Set the Triple DES objects with NO PADDING.
	EVP_CIPHER_CTX_set_padding(computeP, 0);
	EVP_CIPHER_CTX_set_padding(invertP, 0);
	_isKeySet= true;
}

std::shared_ptr<PseudorandomFunction> PseudorandomFunction::get_new_prf(string algName) {
	if (algName == "AES")
		return make_shared<OpenSSLAES>();
	if (algName == "TripleDES")
		return make_shared<OpenSSLTripleDES>();
	if (algName == "HMAC")
		return make_shared<OpenSSLHMAC>();
	// Wrong algorithm name
	throw invalid_argument("unexpected prf name");
}