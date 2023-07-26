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


#include "../../include/primitives/Kdf.hpp"

void HKDF::nextRounds(int outLen, const vector<byte> & iv, int hmacLength, vector<byte> & outBytes, vector<byte> & intermediateOutBytes) {
	int rounds = (int)ceil((float)outLen / (float)hmacLength); // The smallest number so that  hmacLength * rounds >= outLen
	int currentInBytesSize;	// The size of the CTXInfo and also the round.
	if (iv.size() > 0)
		currentInBytesSize = hmacLength + iv.size() + 1; // The size of the CTXInfo and also the round.
	else //no CTXInfo
		currentInBytesSize = hmacLength + 1; // The size without the CTXInfo and also the round;

	//The result of the current computation.
	vector<byte> currentInBytes(currentInBytesSize);

	//For rounds 2 to t.
	if (iv.size() > 0)
		//In case we have an iv. puts it (ctxInfo after the K from the previous round at position hmacLength).
		memcpy(currentInBytes.data() + hmacLength, iv.data(), iv.size());
		
	for (int i = 2; i <= rounds; i++) {
		// Copy the output of the last results.
		memcpy(currentInBytes.data(), intermediateOutBytes.data(), intermediateOutBytes.size());
		// Copy the round integer to the data array.
		currentInBytes[currentInBytesSize - 1] = (byte)i;
		
		//Operates the hmac to get the round output.
		this->hmac->computeBlock(currentInBytes, 0, currentInBytesSize, intermediateOutBytes, 0);

		if (i == rounds)  //We fill the rest of the array with a portion of the last result.
			//Copy the results to the output array
			outBytes.insert(outBytes.begin() + hmacLength*(i - 1), &intermediateOutBytes[0], &intermediateOutBytes[outLen - hmacLength*(i - 1)]);
		else 
			//Copy the results to the output array
			outBytes.insert(outBytes.begin() + hmacLength*(i - 1), &intermediateOutBytes[0], &intermediateOutBytes[hmacLength]);
	}
}

void HKDF::firstRound(vector<byte>& outBytes, const vector<byte> & iv, vector<byte> & intermediateOutBytes, int outLength) {
	// Round 1.
	vector<byte> firstRoundInput; //Data for the creating K(1).
	int firstRoundSize;
	if (iv.size() > 0) {
		firstRoundSize = iv.size() + 1;
		firstRoundInput.resize(firstRoundSize);
		// Copy the CTXInfo - iv.
		memcpy(firstRoundInput.data(), iv.data(), iv.size());
	}
	else {
		firstRoundSize = 1;
		firstRoundInput.resize(firstRoundSize);
	}
	
	// Copy the integer with zero to the data array.
	firstRoundInput[firstRoundSize - 1] = (byte)1;

	// First computes the new key. The new key is the result of computing the hmac function.
	// calculate K(1) and put it in intermediateOutBytes.
	hmac->computeBlock(firstRoundInput, 0, firstRoundSize, intermediateOutBytes, 0);
	
	// copies the results to the output array
	outBytes.assign(intermediateOutBytes.begin(), intermediateOutBytes.begin() + outLength);
}

SecretKey HKDF::deriveKey(const vector<byte> & entropySource, int inOff, int inLen, int outLen, const vector<byte>& iv) {
	//Check that the offset and length are correct.
	if ((inOff > (int)entropySource.size()) || (inOff + inLen >  (int) entropySource.size()))
		throw out_of_range("wrong offset for the given input buffer");

	//In order to be thread safe we have to synchronized this function.

	// Consider the following situation: thread #1 calls the deriveKey function. It starts to derive the key, 
	// calls the hmac setKey function and so on. In the meantime, thread #2 calls the deriveKey function as well.	
	// Without synchronization, thread #2 will set the hmac object with the fixed key (what is done in the beginning of 
	// the key derivation).
	// This will delete all thread #1 work until that time and the results of the deriveKey will be wrong.

	// By adding the synchronized block we let only one thread to be able execute the synchronized code at the same time. 
	// All other threads attempting to enter the synchronized block are blocked until the thread inside the 
	// synchronized block exits the block.

	unique_lock<mutex> lock(_mutex);
	
	// Sets the hmac object with a fixed key that was randomly generated once. This is done every time a new derived key is requested otherwise the result of deriving
	// a key from the same entropy source will be different in subsequent calls to this function (as long as the same instance of HKDF is used). 
	string str_key = boost::algorithm::unhex(string("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"));
	char const *c_key = str_key.c_str();
	SecretKey key((byte*) c_key, strlen(c_key), "");
	hmac->setKey(key);
	int hmacLength = hmac->getBlockSize(); // The size of the output of the hmac.
	vector<byte> outBytes;				   // The output key.
	vector<byte> roundKey;				   // PRK from the pseudocode.
	vector<byte> intermediateOutBytes;	   // round result K(i) in the pseudocode

	// First computes the new key. The new key is the result of computing the hmac function.
	//RoundKey is now K(0)
	hmac->computeBlock(entropySource, 0, entropySource.size(), roundKey, 0);
	//Init the hmac with the new key. From now on this is the key for all the rounds.
	SecretKey roundSecretKey(roundKey, "HKDF");
	hmac->setKey(roundSecretKey);
	
	// Calculates the first round.
	// K(1) = HMAC(PRK,(CTXinfo,1)) [key=PRK, data=(CTXinfo,1)]
	if (outLen < hmacLength)
		firstRound(outBytes, iv, intermediateOutBytes, outLen);
	else
		firstRound(outBytes, iv, intermediateOutBytes, hmacLength);

	// Calculates the next rounds
	// FOR i = 2 TO t
	// K(i) = HMAC(PRK,(K(i-1),CTXinfo,i)) [key=PRK, data=(K(i-1),CTXinfo,i)]
	nextRounds(outLen, iv, hmacLength, outBytes, intermediateOutBytes);

	//creates the secret key from the generated bytes
	return SecretKey(outBytes, "HKDF");
	// Unlocking happens automatically since the lock
	// gets destroyed here.
}
