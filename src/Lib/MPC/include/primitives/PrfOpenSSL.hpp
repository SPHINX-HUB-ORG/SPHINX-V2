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


#ifndef SCAPI_OPENSSL_PRF_H
#define SCAPI_OPENSSL_PRF_H

#include "Prf.hpp"
#include "HashOpenSSL.hpp"
#include "Prg.hpp"
#include "../cryptoInfra/Key.hpp"
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

/**
 * Abstract class that implements the PRPFixed using OpenSSL library.
*/
class OpenSSLPRP : public PrpFixed {
	
protected:
	shared_ptr<PrgFromOpenSSLAES> prg;
	EVP_CIPHER_CTX* computeP;		//OpenSSL's object used to compute the prp.
	EVP_CIPHER_CTX* invertP;		//OpenSSL's object used to invert the prp.
	bool _isKeySet;

public:
	bool isKeySet() override { return _isKeySet; }

	/**
	* This class does not need parameters to generate a key. Call the other generateKey function that accept the key size.
	*/
	SecretKey generateKey(AlgorithmParameterSpec & keyParams) override {
		throw NotImplementedException("To generate a key for this prf object use the generateKey(int keySize) function");
	};

	SecretKey generateKey(int keySize) override;

	/**
	* Computes the function using the secret key.
	* The user supplies the input byte vector and the offset from which to take the data from.
	* The user also supplies the output byte vector as well as the offset.
	* The computeBlock function will put the output in the output vector starting at the offset. 
	* This function is suitable for block ciphers where the input/output length is known in advance.
	* @param inBytes input bytes to compute
	* @param inOff input offset in the inBytes array
	* @param outBytes output bytes. The resulted bytes of compute
	* @param outOff output offset in the outBytes array to put the result from
	*/
	void computeBlock(const vector<byte> & inBytes, int inOff, vector<byte> &outBytes, int outOff) override;

	/**
	* Computes the function using the secret key.
	* This function is provided in the interface especially for the sub-family PrfVaryingIOLength, which may have variable input and output length.
	* If the implemented algorithm is a block cipher then the size of the input as well as the output is known in advance and
	* the use may call the other computeBlock function where length is not require.
	* @param inBytes input bytes to compute
	* @param inOff input offset in the inBytes array
	* @param inLen the length of the input array
	* @param outBytes output bytes. The resulted bytes of compute
	* @param outOff output offset in the outBytes array to put the result from
	* @param outLen the length of the output array
	*/
	void computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte> &outBytes, int outOff, int outLen) override;

	/**
	* Computes the function using the secret key. 
	* This function is provided in this PseudorandomFunction interface for the sake of interfaces (or classes) for which
	* the input length can be different for each computation. Hmac and Prf/Prp with variable input length are examples of
	* such interfaces.
	*
	* @param inBytes input bytes to compute
	* @param inOffset input offset in the inBytes vector
	* @param inLen the length of the input vector
	* @param outBytes output bytes. The resulted bytes of compute.
	* @param outOffset output offset in the outBytes vector to put the result from
	*/
	void computeBlock(const vector<byte> & inBytes, int inOffset, int inLen, vector<byte> &outBytes, int outOffset) override;
	
	/**
	* Computes the permutation on the given vector.
	* The given vector length does not have to be the size of the block but a MUST be aligned to the block size.
	* The optimized compute block divides the given input into blocks and compute each one of them separately.
	* The output vector will contain a concatenation of all the results of computing the blocks.
	*
	* @param inBytes input bytes to compute.
	* @param outBytes output bytes. The resulted bytes of compute.
	*/
	void optimizedCompute(const vector<byte> & inBytes, vector<byte> &outBytes);

	/**
	* Inverts the permutation using the given key. 
	* This function is a part of the PseudorandomPermutation interface since any PseudorandomPermutation must be efficiently invertible (given the key).
	* For block ciphers, for example, the length is known in advance and so there is no need to specify the length.
	* @param inBytes input bytes to invert.
	* @param inOff input offset in the inBytes array
	* @param outBytes output bytes. The resulted bytes of invert
	* @param outOff output offset in the outBytes array to put the result from
	*/
	void invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff) override;
	
	/**
	* Inverts the permutation on the given vector.
	* The given vector length does not have to be the size of the block but a MUST be aligned to the block size.
	* The optimized invert block divides the given input into blocks and inverts each one of them separately.
	* The output vector will contain a concatenation of all the results of inverting the blocks.
	*
	* @param inBytes input bytes to invert.
	* @param outBytes output bytes. The inverted bytes.
	*/
	void optimizedInvert(const vector<byte> & inBytes, vector<byte> &outBytes);

	/**
	* Inverts the permutation using the given key.
	* Since PseudorandomPermutation can also have varying input and output length (although the input and the output should be the same length),
	* the common parameter len of the input and the output is needed.
	* @param inBytes input bytes to invert.
	* @param inOff input offset in the inBytes array
	* @param outBytes output bytes. The resulted bytes of invert
	* @param outOff output offset in the outBytes array to put the result from
	* @param len the length of the input and the output
	*/
	void invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff, int len) override;
	virtual ~OpenSSLPRP();
};
/**
* Concrete class of PRF family for AES. This class wraps the implementation of OpenSSL library.
*/
class OpenSSLAES : public OpenSSLPRP, public AES {
private: 
public:
	OpenSSLAES(const shared_ptr<PrgFromOpenSSLAES> & setRandom = get_seeded_prg());

	/**
	* Initializes this AES objects with the given secret key.
	* @param secretKey secret key.
	* @throws InvalidKeyException if the key is not 128/192/256 bits long.
	*/
	void setKey(SecretKey & secretKey) override;

	string getAlgorithmName() override { return "AES"; };

	int getBlockSize() override { return 16; };

	virtual ~OpenSSLAES() {};
};

class OpenSSLHMAC : public Hmac {
private:
	HMAC_CTX * hmac; // Pointer to the OpenSSL hmac object.
	bool _isKeySet;  // Until setKey is called set to false.
	shared_ptr<PrgFromOpenSSLAES> random; //source of randomness used in key generation
	SecretKey _key; //needed for OpenSSL V1.1

public: 
	/**
	* This constructor receives a hashName and builds the underlying hmac according to it. It can be called from the factory.
	* @param hashName - the hash function to translate into OpenSSL's hash.
	* @throws FactoriesException if there is no hash function with given name.
	*/
	OpenSSLHMAC(string hashName = "SHA-256", const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

	/**
	* This constructor gets a random and a SCAPI CryptographicHash to be the underlying hash and retrieves the name of the hash in
	* order to create the related OpenSSL's hash.
	* @param hash - the underlying hash to use.
	* @param random the random object to use.
	* @throws FactoriesException if there is no hash function with given name.
	*/
	OpenSSLHMAC(CryptographicHash *hash, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) : OpenSSLHMAC(hash->getAlgorithmName(), random) {}
	
	/**
	* Initializes this hmac with a secret key.
	* @param secretKey the secret key
	*/
	void setKey(SecretKey & secretKey) override;
	void setMacKey(SecretKey & secretKey) override { setKey(secretKey); };
	bool isKeySet() override { return _isKeySet; };
	string getAlgorithmName() override;
	int getBlockSize() override
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	    return EVP_MD_size(hmac->md);
#else
        return EVP_MD_size(HMAC_CTX_get_md(hmac));
#endif
	};
	
	/**
	* Computes the function using the secret key.
	* The user supplies the input byte vector and the offset from which to take the data from.
	* The user also supplies the output byte vector as well as the offset.
	* The computeBlock function will put the output in the output vector starting at the offset.
	* This function is suitable for block ciphers where the input/output length is known in advance.
	* @param inBytes input bytes to compute
	* @param inOff input offset in the inBytes array
	* @param outBytes output bytes. The resulted bytes of compute
	* @param outOff output offset in the outBytes array to put the result from
	*/
	void computeBlock(const vector<byte> & inBytes, int inOff, vector<byte> &outBytes, int outOff) override;
	
	/**
	* Computes the function using the secret key.
	* This function is provided in the interface especially for the sub-family PrfVaryingIOLength, which may have variable input and output length.
	* If the implemented algorithm is a block cipher then the size of the input as well as the output is known in advance and
	* the use may call the other computeBlock function where length is not require.
	* @param inBytes input bytes to compute
	* @param inOff input offset in the inBytes array
	* @param inLen the length of the input array
	* @param outBytes output bytes. The resulted bytes of compute
	* @param outOff output offset in the outBytes array to put the result from
	* @param outLen the length of the output array
	*/
	void computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte> &outBytes, int outOff, int outLen) override;
	
	/**
	* Computes the function using the secret key.
	* This function is provided in this PseudorandomFunction interface for the sake of interfaces (or classes) for which
	* the input length can be different for each computation. Hmac and Prf/Prp with variable input length are examples of
	* such interfaces.
	*
	* @param inBytes input bytes to compute
	* @param inOffset input offset in the inBytes vector
	* @param inLen the length of the input vector
	* @param outBytes output bytes. The resulted bytes of compute.
	* @param outOffset output offset in the outBytes vector to put the result from
	*/
	void computeBlock(const vector<byte> & inBytes, int inOffset, int inLen, vector<byte> &outBytes, int outOffset) override;
	
	SecretKey generateKey(AlgorithmParameterSpec & keyParams) override {
		throw NotImplementedException("To generate a key for this HMAC object use the generateKey(int keySize) function");
	};
	
	SecretKey generateKey(int keySize) override;
	
	int getMacSize() override { return getBlockSize(); };
	virtual vector<byte> mac(const vector<byte> &msg, int offset, int msgLen) override;
	virtual bool verify(const vector<byte> &msg, int offset, int msgLength, vector<byte>& tag) override;
	virtual void update(vector<byte> & msg, int offset, int msgLen) override;
	virtual void doFinal(vector<byte> & msg, int offset, int msgLength, vector<byte> & tag_res) override;
	~OpenSSLHMAC();
};

/**
* Concrete class of PRF family for Triple DES. This class wraps the implementation of OpenSSL library.
*/
class OpenSSLTripleDES : public OpenSSLPRP, public TripleDES {
public:
	/**
	* Default constructor that creates the TripleDES objects. Uses default implementation of SecureRandom.
	*/
	OpenSSLTripleDES();
	void setKey(SecretKey & secretKey) override;
	string getAlgorithmName() override{ return "TripleDES"; };
	int getBlockSize() override { return 8; }; // TripleDES works on 64 bit block.
};

#endif