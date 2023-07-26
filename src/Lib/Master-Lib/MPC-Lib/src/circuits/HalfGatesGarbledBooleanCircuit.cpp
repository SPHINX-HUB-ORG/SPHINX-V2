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

#include <stdlib.h>
#include <string.h>
#include <iostream>
#include "../../include/circuits/Compat.h"
#include "../../include/circuits/GarbledGate.h"
#include "../../include/circuits/TedKrovetzAesNiWrapperC.h"
#include "../../include/circuits/HalfGatesGarbledBooleanCircuit.h"

using namespace std;

HalfGatesGarbledBooleanCircuit::HalfGatesGarbledBooleanCircuit(void)
{
}

HalfGatesGarbledBooleanCircuit::HalfGatesGarbledBooleanCircuit(const char* fileName, bool isNonXorOutputsRequired){

	//create the needed memory for this circuit
	createCircuitMemory(fileName, isNonXorOutputsRequired);
	//isTwoRows = true;
}

void HalfGatesGarbledBooleanCircuit::createCircuitMemory(const char* fileName, bool isNonXorOutputsRequired){

	createCircuit(fileName, true, isNonXorOutputsRequired);
	numOfRows = 2;

	if (isNonXorOutputsRequired == true){
		garbledTables = (block *)_aligned_malloc(sizeof(block) * ((numberOfGates - numOfXorGates - numOfNotGates)
		        * 2 + 2 * numberOfOutputs), 16);
		if (garbledTables == nullptr) {
			cout << "garbledTables could not be allocated";
			exit(0);
		}
		memset(garbledTables, 0, (sizeof(block) * ((numberOfGates - numOfXorGates - numOfNotGates)
		* 2 + 2 * numberOfOutputs)));

        garbledWires = (block *)_aligned_malloc(sizeof(block) * ((lastWireIndex + 1) + 1 + 2 * numberOfOutputs),
                16);

		if (garbledWires == nullptr) {
			cout << "garbledWires could not be allocated";
			exit(0);
		}
		memset(garbledWires, 0, sizeof(block) * ((lastWireIndex + 1) + 1 + 2 * numberOfOutputs));
		garbledWires++;
	}
	else{
		garbledTables = (block *)_aligned_malloc(sizeof(block) *
		        (numberOfGates - numOfXorGates - numOfNotGates) * 2, 16);

		if (garbledTables == nullptr) {
			cout << "garbled tables could not be allocated";
			exit(0);
		}
		memset(garbledTables, 0, (sizeof(block) * (numberOfGates - numOfXorGates - numOfNotGates) * 2));

		garbledWires = (block *)_aligned_malloc(sizeof(block) * ((lastWireIndex + 1) + 1), 16);

		if (garbledWires == nullptr) {
			cout << "garbledWires could not be allocated";
			exit(0);
		}
		memset(garbledWires, 0, sizeof(block) * ((lastWireIndex + 1) + 1));
		garbledWires++;
	}

	encryptedChunkKeys = (block *)_aligned_malloc(sizeof(block) * numberOfInputs, 16);
	if (encryptedChunkKeys == nullptr) {
		cout << "encryptedChunkKeys could not be allocated";
		exit(0);
	}
	memset(encryptedChunkKeys, 0, sizeof(block) * numberOfInputs);

	indexArray = (block *)_aligned_malloc(sizeof(block) * numberOfInputs, 16);
	if (indexArray == nullptr) {
		cout << "indexArray could not be allocated";
		exit(0);
	}

	//we put the indices ahead of time to encrypt the whole chunk in one call.
	for (int i = 0; i < numberOfInputs; i++)
		indexArray[i] = _mm_set_epi32(0, 0, 0, i);
}


HalfGatesGarbledBooleanCircuit::~HalfGatesGarbledBooleanCircuit(void)
{
	//free memory allocated in this class
	if (indexArray!=nullptr)
		_aligned_free(indexArray);

	if (encryptedChunkKeys!=nullptr)
		_aligned_free(encryptedChunkKeys);
		
	if (garbledWires != nullptr){
		garbledWires--;
		_aligned_free(garbledWires);
	}

}

void HalfGatesGarbledBooleanCircuit::garble(block *emptyBothInputKeys, block *emptyBothOutputKeys,
        vector<unsigned char> & emptyTranslationTable, block seed){

	this->seed = seed;

	//init encryption key of the seed and calc all the wire keys
	initAesEncryptionsAndAllKeys(emptyBothInputKeys);


	//declare some variables that will be used for garbling
	int nonXorIndex = 0;

	//two different tweaks one for input0 and the other for input1
	block tweak;
	block tweak2;

	//go over all the gates in the circuit
	for (int i = 0; i < numberOfGates; i++){

		if (garbledGates[i].truthTable == XOR_GATE){
			//create the 0-key by xoring the two 0-keys of the input
			garbledWires[garbledGates[i].output] = _mm_xor_si128(garbledWires[garbledGates[i].input0],
			        garbledWires[garbledGates[i].input1]);
			continue;
		}
		else if (garbledGates[i].truthTable == XOR_NOT_GATE){
			//create the 0-key by xoring the two 0-keys of the input and xoring that with the delta.
			garbledWires[garbledGates[i].output] = _mm_xor_si128(_mm_xor_si128(
			        garbledWires[garbledGates[i].input0], garbledWires[garbledGates[i].input1]), deltaFreeXor);

		}

		else{
			//two different tweaks
			tweak = _mm_set_epi32(0, 0, 0, i);
			tweak2 = _mm_set_epi32(0, 0, 0, i+numberOfGates);

			//create input arrays in order to get the inputs immedietly and not invoke unneeded xor's
			block inputs[4];
			inputs[0] = garbledWires[garbledGates[i].input0];
			inputs[1] = _mm_xor_si128(inputs[0], deltaFreeXor);

			inputs[2] = garbledWires[garbledGates[i].input1];
			inputs[3] = _mm_xor_si128(inputs[2], deltaFreeXor);

			//signal bits of wire 0 of input0 and wire 0 of input1
			int wire0signalBitsArray = getSignalBitOf(inputs[0]);
			int wire1signalBitsArray = getSignalBitOf(inputs[2]);

			//generate the keys array
			block keys[4];

			//generate K = H(input) = 2Input XOR tweak
			keys[0] = _mm_xor_si128(_mm_slli_epi64(inputs[0], 1), tweak);
			keys[1] = _mm_xor_si128(_mm_slli_epi64(inputs[1], 1), tweak);
			keys[2] = _mm_xor_si128(_mm_slli_epi64(inputs[2], 1), tweak2);
			keys[3] = _mm_xor_si128(_mm_slli_epi64(inputs[3], 1), tweak2);
			
			

			//generate the keys array as well as the encryptedKeys array
			block encryptedKeys[4];
			//Encrypt the 4 keys in one chunk to gain pipelining and puts the answer in encryptedKeys block array
			AES_ecb_encrypt_blks_4_in_out(keys, encryptedKeys, &aesFixedKey);
		
			


			if (wire1signalBitsArray == 0){//signal bit of wire 0 of input1 is zero

				garbledTables[2 * nonXorIndex] = _mm_xor_si128(_mm_xor_si128(encryptedKeys[0], keys[0]),
				        _mm_xor_si128(encryptedKeys[1], keys[1]));
			}
			else{//signal bit of wire 0 of input1 is one
				garbledTables[2 * nonXorIndex] = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(encryptedKeys[0],
				        keys[0]), _mm_xor_si128(encryptedKeys[1], keys[1])), deltaFreeXor);
			}

			//two temporary values that will eventually be XORed together to calculate the output0 zero wire
			block tempK0, tempK1;

			if (wire0signalBitsArray == 0){//signal bit of wire 0 of input0 is zero

				tempK0 = _mm_xor_si128(encryptedKeys[0], keys[0]);
			}
			else{//signal bit of wire 0 of input0 is one
				tempK0 = _mm_xor_si128(_mm_xor_si128(encryptedKeys[0],keys[0]),
				        garbledTables[2 * nonXorIndex]);
			}

			garbledTables[2 * nonXorIndex + 1] = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(encryptedKeys[2],
			        keys[2]), _mm_xor_si128(encryptedKeys[3], keys[3])), inputs[0]);

			if (wire1signalBitsArray == 0){
				tempK1 = _mm_xor_si128(encryptedKeys[2], keys[2]);
			}
			else{
				tempK1 = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(encryptedKeys[2], keys[2]),
				        garbledTables[2 * nonXorIndex + 1]), inputs[0]);
			}

			//set the garbled output to be the XOR of the two temp keys
			garbledWires[garbledGates[i].output] = _mm_xor_si128(tempK0, tempK1);

			nonXorIndex++;
		}

	}


	
		
	if (isNonXorOutputsRequired){//check if the user requires that the output keys will not have a fixed delta xor between pair of keys of a wire.
		//call the function that returns the emptyBothOutputKeys without deltaFreeXor between each pair of wires
		garbleOutputWiresToNoFixedDelta(&deltaFreeXor, nonXorIndex, emptyBothOutputKeys);
	}
	else{
		//copy the output keys to get back to the caller of the function as well as filling the translation table.
		//The input keys were already filled in the initialization of the function.
		for (int i = 0; i < numberOfOutputs; i++){
			emptyBothOutputKeys[2 * i] = garbledWires[outputIndices[i]];
			emptyBothOutputKeys[2 * i + 1] = _mm_xor_si128(emptyBothOutputKeys[2 * i], deltaFreeXor);
		}
	}

	translationTable.clear();
	//update the translation table
	for (int i = 0; i < numberOfOutputs; i++){
		translationTable.push_back(getSignalBitOf(emptyBothOutputKeys[2 * i]));
		emptyTranslationTable.push_back(getSignalBitOf(emptyBothOutputKeys[2 * i]));
	}

}

void HalfGatesGarbledBooleanCircuit::initAesEncryptionsAndAllKeys(block* emptyBothInputKeys){

	//reserve memory for the translation table
	translationTable.reserve(numberOfOutputs);
	

	///create the aes with the seed as the key. This will be used for encrypting the input keys
	AES_set_encrypt_key((const unsigned char *)&seed, 128, &aesSeedKey);

	//create the delta for the free Xor. Encrypt zero twice. We get a good enough random delta by encrypting twice
	deltaFreeXor = ZERO_BLOCK;
	AES_ecb_encrypt(&deltaFreeXor, &aesSeedKey);
	AES_ecb_encrypt(&deltaFreeXor, &aesSeedKey);

	//set the last bit of the first char to 1
	*((unsigned char *)(&deltaFreeXor)) |= 1;

	AES_ecb_encrypt_chunk_in_out(indexArray,
		encryptedChunkKeys,
		numberOfInputs,
		&aesSeedKey);


	//create the input keys. We encrypt using the aes with the seed as index and encrypt the index of the input wire,
	for (int i = 0; i<numberOfInputs; i++){
		garbledWires[inputIndices[i]] = emptyBothInputKeys[2 * i] = encryptedChunkKeys[i];

		emptyBothInputKeys[2 * i + 1] = _mm_xor_si128(encryptedChunkKeys[i], deltaFreeXor);
	}


	//set the fixed -1 wire to delta, this way we turn a not gate into a xor gate.
	garbledWires[-1] = deltaFreeXor;
}



void  HalfGatesGarbledBooleanCircuit::compute(block * singleWiresInputKeys, block * Output)
{
	int nonXorIndex = 0;
	for (int i = 0; i < numberOfInputs; i++){

		//get the input keys into the computed wires array
		computedWires[inputIndices[i]] = singleWiresInputKeys[i];
	}

	for (int i = 0; i < numberOfGates; i++){

		if (garbledGates[i].truthTable == XOR_GATE || garbledGates[i].truthTable == XOR_NOT_GATE){
			//create the output key by xoring the computed keys if the first input wire and the second input wire
			computedWires[garbledGates[i].output] = _mm_xor_si128(computedWires[garbledGates[i].input0],
			        computedWires[garbledGates[i].input1]);
			continue;

		}

		else{

			block keys[2];
			block keys2[2];
			//get the keys from the already calculated wires
			keys[0] = computedWires[garbledGates[i].input0];
			keys[1] = computedWires[garbledGates[i].input1];

			//Get the signal bits of A and B which are the input keys computed.
			int wire0SignalBit = getSignalBitOf(keys[0]);
			int wire1SignalBit = getSignalBitOf(keys[1]);

			//Calc the tweak
			block tweak = _mm_set_epi32(0, 0, 0, i);
			block tweak2 = _mm_set_epi32(0, 0, 0, i + numberOfGates);

			//Deduce the key to encrypt
			keys2[0] = _mm_xor_si128(_mm_slli_epi64(keys[0], 1), tweak);
			keys2[1] = _mm_xor_si128(_mm_slli_epi64(keys[1], 1), tweak2);


			//generate the keys array as well as the encryptedKeys array
			block encryptedKeys[2];
			//Encrypt the 2 keys in one chunk to gain pipelining and puts the answer in encryptedKeys block array
			AES_ecb_encrypt_blks_2_in_out(keys2, encryptedKeys, &aesFixedKey);

			block tempK0, tempK1;
			//for more information look at the pseudo-code of "Two Halves Make a Whole Reducing Data Transfer in
			// Garbled Circuits using Half Gates" page 9
			if (wire0SignalBit == 0){
				tempK0 = _mm_xor_si128(encryptedKeys[0], keys2[0]);
			}
			else{
				tempK0 = _mm_xor_si128(_mm_xor_si128(encryptedKeys[0], keys2[0]),
				        garbledTables[2 * nonXorIndex]);
			}

			if (wire1SignalBit == 0){
				tempK1 = _mm_xor_si128(encryptedKeys[1], keys2[1]);
			}
			else{
				tempK1 = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(encryptedKeys[1], keys2[1]),
				        garbledTables[2 * nonXorIndex + 1]), keys[0]);
			}

			computedWires[garbledGates[i].output] = _mm_xor_si128(tempK0, tempK1);


			//increment the nonXor gates number only for the non-xor (not XOR or XOR_NOT) gates. For circuits
			//That do not use FreeXor optimization it will be incremented for every gate
			nonXorIndex++;
		}

	}

	if (isNonXorOutputsRequired){
	    //check if the user requires that the output keys will not have a fixed delta xor between pair of keys of a wire.
		//call the function that returns the Output where xoring
		// with the other wire key will not have fixed delta for all the outputs
		computeOutputWiresToNoFixedDelta(nonXorIndex, Output);
	}

	else{
		//copy the output wire keys which are the result the user is interested in.
		for (int i = 0; i < numberOfOutputs; i++) {
			Output[i] = computedWires[outputIndices[i]];

		}
	}
}


bool HalfGatesGarbledBooleanCircuit::internalVerify(block *bothInputKeys, block *emptyBothWireOutputKeys){

	int nonXorIndex = 0;

	//set the delta to be the xor between the first 2 inputs
	deltaFreeXor = _mm_xor_si128(bothInputKeys[0], bothInputKeys[1]);


	//copy the 0-wire input keys.
	for (int i = 0; i<numberOfInputs; i++){

		//get the input keys into the computed wires array
		garbledWires[inputIndices[i]] = bothInputKeys[2 * i];
	}

	for (int i = 0; i<numberOfGates; i++){

		if (garbledGates[i].truthTable == XOR_GATE){
			//Create the 0-key of the output
			garbledWires[garbledGates[i].output] = _mm_xor_si128(garbledWires[garbledGates[i].input0], garbledWires[garbledGates[i].input1]);

			continue;

		}
		else if (garbledGates[i].truthTable == XOR_NOT_GATE){
			//create the 0-key by xoring the two 0-keys of the input and xoring that with the delta.
			garbledWires[garbledGates[i].output] = _mm_xor_si128(_mm_xor_si128(garbledWires[garbledGates[i].input0], garbledWires[garbledGates[i].input1]), deltaFreeXor);


		}

		else{

			//Calc the tweak
			block tweak = _mm_set_epi32(0, 0, 0, i);
			block tweak2 = _mm_set_epi32(0, 0, 0, i + numberOfGates);


			//create input arrays in order to get the inputs immedietly and not invoke unneeded xor's
			block inputs[4];
			inputs[0] = garbledWires[garbledGates[i].input0];
			inputs[1] = _mm_xor_si128(inputs[0], deltaFreeXor);

			inputs[2] = garbledWires[garbledGates[i].input1];
			inputs[3] = _mm_xor_si128(inputs[2], deltaFreeXor);
			//generate the keys array
			block keys[4];
			

			//signal bits of input0 and input1
			int wire0SignalBit, wire1SignalBit;


			//generate K = H(input) = 2Input XOR tweak
			keys[0] = _mm_xor_si128(_mm_slli_epi64(inputs[0], 1), tweak);
			keys[1] = _mm_xor_si128(_mm_slli_epi64(inputs[1], 1), tweak);
			keys[2] = _mm_xor_si128(_mm_slli_epi64(inputs[2], 1), tweak2);
			keys[3] = _mm_xor_si128(_mm_slli_epi64(inputs[3], 1), tweak2);


			//generate the keys array as well as the encryptedKeys array
			block encryptedKeys[4];
			//Encrypt the 4 keys in one chunk to gain pipelining and puts the answer in encryptedKeys block array
			AES_ecb_encrypt_blks_4_in_out(keys, encryptedKeys, &aesFixedKey);

			
			//declare temp variables to store the 0-wire key and the 1-wire key
			block k0;

			//for more information look at the pseudo-code of compute.
			for (int index0 = 0; index0< 2; index0++){
				wire0SignalBit = getSignalBitOf(inputs[index0]);
				for (int j = 0; j < 2; j++){

					//last iteration, this should compute the k1 value, but since it is the only wire 1 key that is computed, there is no value to
					//compare it to, since the gate can only be an AND gate.
					if (index0 == 1 && j == 1){
						continue;
					}

					wire1SignalBit = getSignalBitOf(inputs[j+2]);

					block tempK0, tempK1;
					

					if (wire0SignalBit == 0){
						tempK0 = _mm_xor_si128(encryptedKeys[index0], keys[index0]);
					}
					else{
						tempK0 = _mm_xor_si128(_mm_xor_si128(encryptedKeys[index0], keys[index0]), garbledTables[2 * nonXorIndex]);
					}

					if (wire1SignalBit == 0){
						tempK1 = _mm_xor_si128(encryptedKeys[j+2], keys[j+2]);
					}
					else{
						tempK1 = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(encryptedKeys[j+2], keys[j+2]), garbledTables[2 * nonXorIndex + 1]), inputs[index0]);
					}

					//first iteration that computes the k0 wire
					if (index0 == 0 && j == 0){//this is a zero value output
						k0 = garbledWires[garbledGates[i].output] = _mm_xor_si128(tempK0, tempK1);
					}
					//cases 0,1 and 1,0. These cases should also compute k0, we compare it to the k0 calculated in the first iteration.
					else {
						k0 = _mm_xor_si128(tempK0, tempK1);
						if (!(equalBlocks(k0, garbledWires[garbledGates[i].output])))
							return false;
					}
				}

			}

			//increment the nonXor gates number only for the non-xor (not XOR or XOR_NOT) gates.
			nonXorIndex++;
		}
	}


	//copy the output keys to return to the caller of the function
	for (int i = 0; i < numberOfOutputs; i++) {
		emptyBothWireOutputKeys[2 * i] = garbledWires[outputIndices[i]];
		emptyBothWireOutputKeys[2 * i + 1] = _mm_xor_si128(emptyBothWireOutputKeys[2 * i], deltaFreeXor);

	}

	return true;

}
