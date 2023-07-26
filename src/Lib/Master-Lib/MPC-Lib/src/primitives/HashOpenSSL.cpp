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


#include "../../include/primitives/HashOpenSSL.hpp"

OpenSSLHash::OpenSSLHash(string hashName) {
	//Instantiates a hash object in OpenSSL. 
	const EVP_MD *md;

	OpenSSL_add_all_digests();

	//Get the string from java.
	const char* name = hashName.c_str();

	// Get the OpenSSL digest.
	md = EVP_get_digestbyname(name);
	if (md == 0)
		throw runtime_error("failed to create hash");

	// Create an OpenSSL EVP_MD_CTX struct and initialize it with the created hash.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	hash = shared_ptr<EVP_MD_CTX>(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);

	if (0 == (EVP_DigestInit(hash.get(), md)))
		throw runtime_error("failed to create hash");

	hashSize = EVP_MD_CTX_size(hash.get());
#else
    hash = EVP_MD_CTX_new();
    if (0 == (EVP_DigestInit(hash, md)))
        throw runtime_error("failed to create hash");
    hashSize = EVP_MD_CTX_size(hash);
#endif
}

string OpenSSLHash::getAlgorithmName() {
	//Return the name of the underlying hash function.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	int type = EVP_MD_CTX_type(hash.get());
#else
	int type = EVP_MD_CTX_type(hash);
#endif
	const char* name = OBJ_nid2sn(type);
	return string(name);
}


void OpenSSLHash::update(const vector<byte> &in, int inOffset, int inLen){
	//Check that the offset and length are correct.
	if ((inOffset > (int)in.size()) || (inOffset + inLen > (int)in.size()) || (inOffset<0))
		throw out_of_range("wrong offset for the given input buffer");
	if (inLen < 0)
		throw invalid_argument("wrong length for the given input buffer");
	if (inLen == 0)
		throw new out_of_range("wrong length for the given input buffer");

	// Update the hash with the message.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_DigestUpdate(hash.get(), in.data() + inOffset, inLen);
#else
	EVP_DigestUpdate(hash, in.data() + inOffset, inLen);
#endif
}

void OpenSSLHash::hashFinal(vector<byte> &out, int outOffset) {

	//Checks that the offset and length are correct.
	if (outOffset<0)
		throw new out_of_range("wrong offset for the given output buffer");
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	int length = EVP_MD_CTX_size(hash.get());
#else
	int length = EVP_MD_CTX_size(hash);
#endif
	if ((int) out.size() < outOffset + length) {
		out.resize(outOffset + length);
	}
	//Call the underlying hash's final method.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestFinal_ex(hash.get(), out.data() + outOffset, NULL);
	
	//Initialize the hash structure again to enable repeated calls.
	EVP_DigestInit(hash.get(), EVP_MD_CTX_md(hash.get()));
#else
    EVP_DigestFinal_ex(hash, out.data() + outOffset, NULL);

    //Initialize the hash structure again to enable repeated calls.
    EVP_DigestInit(hash, EVP_MD_CTX_md(hash));
#endif
}

shared_ptr<CryptographicHash> CryptographicHash::get_new_cryptographic_hash(string hashName)
{
	//Return a new hash function according to the given name.
	set<string> algSet = { "SHA1", "SHA224", "SHA256", "SHA384", "SHA512" };
	if (algSet.find(hashName) == algSet.end())
		throw invalid_argument("unexpected hash_name");
	return make_shared<OpenSSLHash>(hashName);
}