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

#include <string.h>
#include <iostream>
#include "../../include/circuits/Compat.h"
#include "../../include/circuits/GarbledGate.h"
#include "../../include/circuits/TedKrovetzAesNiWrapperC.h"
#include "../../include/circuits/RowReductionGarbledBooleanCircuit.h"

using namespace std;


RowReductionGarbledBooleanCircuit::RowReductionGarbledBooleanCircuit(void){}


RowReductionGarbledBooleanCircuit::~RowReductionGarbledBooleanCircuit(void)
{

	if (garbledWires != nullptr){
		garbledWires--;
		_aligned_free(garbledWires);
	}
	if (encryptedChunkKeys != nullptr)
		_aligned_free(encryptedChunkKeys);

	if (indexArray != nullptr)
		_aligned_free(indexArray);


}

RowReductionGarbledBooleanCircuit::RowReductionGarbledBooleanCircuit(const char* fileName, bool isNonXorOutputsRequired)
{
	//create the needed memory for this circuit
	createCircuitMemory(fileName, isNonXorOutputsRequired);
	isFreeXor = true;
}

void RowReductionGarbledBooleanCircuit::createCircuitMemory(const char* fileName, bool isNonXorOutputsRequired) {
	
	//call the base class to create circuit function
	createCircuit(fileName, true,isNonXorOutputsRequired);

	numOfRows = 3;

	//create this memory and initialize it in construction time to gain performance
	if (isNonXorOutputsRequired == true){
		garbledTables = (block *)_aligned_malloc(sizeof(block) * ((numberOfGates - numOfXorGates - numOfNotGates) * 3 + 2 * numberOfOutputs), 16);
		if (garbledTables == nullptr) {
			cout << "garbledTables could not be allocated";
			exit(0);
		}
		memset(garbledTables, 0, (sizeof(block) * ((numberOfGates - numOfXorGates - numOfNotGates) * 3 + 2 * numberOfOutputs)));

		garbledWires = (block *)_aligned_malloc(sizeof(block) * ((lastWireIndex + 1) + 1 + 2 * numberOfOutputs), 16);

		if (garbledWires == nullptr) {
			cout << "garbledWires could not be allocated";
			exit(0);
		}
		memset(garbledWires, 0, sizeof(block) * ((lastWireIndex + 1) + 1 + 2 * numberOfOutputs));
		garbledWires++;
	}
	else{
		garbledTables = (block *)_aligned_malloc(sizeof(block) * (numberOfGates - numOfXorGates - numOfNotGates) * 3, 16);

		if (garbledTables == nullptr) {
			cout << "garbled tables could not be allocated";
			exit(0);
		}
		memset(garbledTables, 0, (sizeof(block) * (numberOfGates - numOfXorGates - numOfNotGates) * 3));

		garbledWires = (block *)_aligned_malloc(sizeof(block) * ((lastWireIndex + 1) + 1), 16);

		if (garbledWires == nullptr) {
			cout << "garbledWires could not be allocated";
			exit(0);
		}
		memset(garbledWires, 0, sizeof(block) * ((lastWireIndex + 1) + 1));
		garbledWires++;
	}

	encryptedChunkKeys = (block *)_aligned_malloc(sizeof(block) * (numberOfInputs), 16);
	if (encryptedChunkKeys == nullptr) {
		cout << "encryptedChunkKeys could not be allocated";
		exit(0);
	}
	memset(encryptedChunkKeys, 0, sizeof(block) * (numberOfInputs));
	indexArray = (block *)_aligned_malloc(sizeof(block) * (numberOfInputs), 16);
	if (indexArray == nullptr) {
		cout << "indexArray could not be allocated";
		exit(0);
	}

	//we put the indices ahead of time to encrypt the whole chunk in one call.
	for (int i = 0; i < numberOfInputs; i++){

		indexArray[i] = _mm_set_epi32(0, 0, 0, i);

	}
	

}



void RowReductionGarbledBooleanCircuit::garble(block *emptyBothInputKeys, block *emptyBothOutputKeys, vector<unsigned char> & emptyTranslationTable, block seed){

	this->seed = seed;

	//init the aes encryptions of the seed and the fixed key. Fill the input wires
	initAesEncryptionsAndInputKeys(emptyBothInputKeys);

	int nonXorIndex= 0;
	int r;
	block tweak;

	

	for(int i=0; i<numberOfGates; i++){

		if (garbledGates[i].truthTable == XOR_GATE){
			//create the 0-key by xoring the two 0-keys of the input
			garbledWires[garbledGates[i].output] = _mm_xor_si128(garbledWires[garbledGates[i].input0], garbledWires[garbledGates[i].input1]);
			continue;
		}
		else if (garbledGates[i].truthTable == XOR_NOT_GATE){
			//create the 0-key by xoring the two 0-keys of the input and xoring that with the delta.
			garbledWires[garbledGates[i].output] = _mm_xor_si128(_mm_xor_si128(garbledWires[garbledGates[i].input0], garbledWires[garbledGates[i].input1]), deltaFreeXor);


		}
		else{

			tweak = _mm_set_epi32(0, 0, 0, i);

			//create input arrays in order to get the inputs immedietly and not invoke unneeded xor's
			block input0Both[2];
			block input1Both[2];
			input0Both[0] = garbledWires[garbledGates[i].input0];
			input0Both[1] = _mm_xor_si128(input0Both[0], deltaFreeXor);

			input1Both[0] = garbledWires[garbledGates[i].input1];
			input1Both[1] = _mm_xor_si128(input1Both[0], deltaFreeXor);


			//An array of signal bits the 0-wire. This prevents from calling the function getSignalBitOf more than
			//once for each 0-wire in the for loop below
			int wire1signalBitsArray[2];
			wire1signalBitsArray[0] = getSignalBitOf(input1Both[0]);
			wire1signalBitsArray[1] = 1 - wire1signalBitsArray[0];


			//An array of signal bits the 0-wire. This prevents from calling the function getSignalBitOf more than
			//once for each 0-wire in the for loop below
			int wire0signalBitsArray[2];
			wire0signalBitsArray[0] = getSignalBitOf(input0Both[0]);
			wire0signalBitsArray[1] = 1 - wire0signalBitsArray[0];

			//create a 4 block keys with the value 2A^4B^T to encrypt in a chunk of 4 for the garbled table
			block keys[4];

			int signalBits[4];
			signalBits[0] = 2 * wire0signalBitsArray[0] + wire1signalBitsArray[0];
			signalBits[1] = 2 * wire0signalBitsArray[0] + wire1signalBitsArray[1];
			signalBits[2] = 2 * wire0signalBitsArray[1] + wire1signalBitsArray[0];
			signalBits[3] = 2 * wire0signalBitsArray[1] + wire1signalBitsArray[1];

			keys[signalBits[0]] = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi64(input0Both[0], 1), _mm_srli_epi64(input1Both[0],1) ), tweak);
			keys[signalBits[1]] = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi64(input0Both[0], 1), _mm_srli_epi64(input1Both[1], 1) ), tweak);
			keys[signalBits[2]] = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi64(input0Both[1], 1), _mm_srli_epi64(input1Both[0], 1) ), tweak);
			keys[signalBits[3]] = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi64(input0Both[1], 1), _mm_srli_epi64(input1Both[1], 1) ), tweak);
			
			/*for (int a = 0; a<2; a++){


				//let currentsignalBit0 be the XOR of the signal bit of the 0-key of the first wire and the current bit of a
				int currentsignalBit0 = wire0signalBitsArray[a];
				A = input0Both[a];
				//Shift left to double A for security (actually the 2 64 bit are shifted and not the whole 128 bit block
				twoA = _mm_slli_epi64(A, 1);


				for (int b = 0; b<2; b++)
				{
					int currentsignalBit1 = wire1signalBitsArray[b];

					B = input1Both[b];

					//Shift right instead of shifting left twice.This is secure since the alignment is broken
					fourB = _mm_srli_epi64(B, 1);

					//calc 2A+4B+T.
					keys[2 * currentsignalBit0 + currentsignalBit1] = _mm_xor_si128((_mm_xor_si128(twoA, fourB)), tweak);

				}
			}*/

			//generate the keys array as well as the encryptedKeys array
			block encryptedKeys[4];
			//Encrypt the 4 keys in one chunk to gain pipelining and puts the answer in encryptedKeys block array
			AES_ecb_encrypt_blks_4_in_out(keys, encryptedKeys, &aesFixedKey);




			for (int a = 0; a<2; a++){
				int currentsignalBit0 = wire0signalBitsArray[a];
				for (int b = 0; b<2; b++)
				{
					
					int currentsignalBit1 = wire1signalBitsArray[b];
					//r = getRowTruthTableResult(currentsignalBit0, currentsignalBit1, garbledGates[i].truthTable);
					r = garbledGates[i].truthTableBits[2 * currentsignalBit0 + currentsignalBit1];
					//called the first time and thus creates the output keys first. This insures that the next iterations will have the output key.
					if (a == 0 && b == 0){

						//now, after the encryption of the first key can generate the key of the output
						if (r == 0){
							garbledWires[garbledGates[i].output] = _mm_xor_si128(encryptedKeys[0], keys[0]);
						}
						else{
							garbledWires[garbledGates[i].output] = _mm_xor_si128(_mm_xor_si128(encryptedKeys[0], keys[0]), deltaFreeXor);
						}
					}
					else{ //we now have the key of the output so we can complete the garbled tables of remaining 3 rows.
						if (r == 0)
							garbledTables[3 * nonXorIndex + 2 * a + b - 1] = _mm_xor_si128(_mm_xor_si128(encryptedKeys[2 * a + b], keys[2 * a + b]), garbledWires[garbledGates[i].output]);
						else{
							garbledTables[3 * nonXorIndex + 2 * a + b - 1] = _mm_xor_si128(_mm_xor_si128(encryptedKeys[2 * a + b], keys[2 * a + b]), _mm_xor_si128(garbledWires[garbledGates[i].output], deltaFreeXor));
						}
					}
				}
			}
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
	for (int i = 0; i < numberOfOutputs; i++) {
		translationTable.push_back(getSignalBitOf(emptyBothOutputKeys[2 * i]));
		emptyTranslationTable.push_back(getSignalBitOf(emptyBothOutputKeys[2 * i]));
	}

}


void RowReductionGarbledBooleanCircuit::initAesEncryptionsAndInputKeys(block* emptyBothInputKeys){

	//create the translation table
	/*if(translationTable==nullptr){
	translationTable = new unsigned char[numberOfOutputs];
	}*/

	//create the aes with the seed as the key. This will be used for encrypting the input keys
	AES_set_encrypt_key((const unsigned char *)&seed, 128, &aesSeedKey);

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


bool RowReductionGarbledBooleanCircuit::internalVerify(block *bothInputKeys, block *emptyBothWireOutputKeys){

	bool isVerified = true;

	int nonXorIndex = 0;
	int r;

	//copy the 0-wire input keys.
	for (int i = 0; i<numberOfInputs; i++){

		//get the input keys into the computed wires array
		garbledWires[inputIndices[i]] = bothInputKeys[2 * i];
	}

	for (int i = 0; i<numberOfGates; i++){

		if (garbledGates[i].truthTable == XOR_GATE ){
			//Create the 0-key of the output
			garbledWires[garbledGates[i].output] = _mm_xor_si128(garbledWires[garbledGates[i].input0], garbledWires[garbledGates[i].input1]);

			continue;

		}
		else if (garbledGates[i].truthTable == XOR_NOT_GATE){
			//create the 0-key by xoring the two 0-keys of the input and xoring that with the delta.
			garbledWires[garbledGates[i].output] = _mm_xor_si128(_mm_xor_si128(garbledWires[garbledGates[i].input0], garbledWires[garbledGates[i].input1]), deltaFreeXor);


		}

		else{

			block keys[4];
			

			//create input arrays in order to get the inputs immedietly and not invoke unneeded xor's
			block input0Both[2];
			block input1Both[2];
			input0Both[0] = garbledWires[garbledGates[i].input0];
			input0Both[1] = _mm_xor_si128(input0Both[0], deltaFreeXor);

			input1Both[0] = garbledWires[garbledGates[i].input1];
			input1Both[1] = _mm_xor_si128(input1Both[0], deltaFreeXor);


			//An array of signal bits the 0-wire. This prevents from calling the function getSignalBitOf more than
			//once for each 0-wire in the for loop below
			int wire0signalBitsArray[2];
			wire0signalBitsArray[0] = getSignalBitOf(input0Both[0]);
			wire0signalBitsArray[1] = 1 - wire0signalBitsArray[0];


			//An array of signal bits the 0-wire. This prevents from calling the function getSignalBitOf more than
			//once for each 0-wire in the for loop below
			int wire1signalBitsArray[2];
			wire1signalBitsArray[0] = getSignalBitOf(input1Both[0]);
			wire1signalBitsArray[1] = 1 - wire1signalBitsArray[0];


			block tweak = _mm_set_epi32(0, 0, 0, i);;
			for (int firstIndex = 0; firstIndex<2; firstIndex++){
				block A = input0Both[firstIndex];
				//Shift left to double A for security (actually the 2 64 bit are shifted and not the whole 128 bit block
				block twoA = _mm_slli_epi64(A, 1);

				for (int secondIndex = 0; secondIndex<2; secondIndex++){

					block B = input1Both[secondIndex];

					//Shift right instead of shifting left twice.This is secure since the alignment is broken
					block fourB = _mm_srli_epi64(B, 1);


					//deduce the key to encrypt
					keys[2 * firstIndex + secondIndex] = _mm_xor_si128(_mm_xor_si128(twoA, fourB), tweak);
				}
			}

			//generate the keys array as well as the encryptedKeys array.
			block encryptedKeys[4];
			//Encrypt the 4 keys in one chunk to gain pipelining and puts the answer in encryptedKeys block array.
			AES_ecb_encrypt_blks_4_in_out(keys, encryptedKeys, &aesFixedKey);


			//declare temp variables to store the 0-wire key and the 1-wire key
			block k0;
			block k1;
			block k1Set;

			//flags that indicateif we have already calcaulated the keys before
			bool isK0Set = false;
			bool isK1Set = false;

			for (int firstIndex = 0; firstIndex<2; firstIndex++){
				//get the signal bit of A from the pre-claculated array
				int a = wire0signalBitsArray[firstIndex];
				for (int secondIndex = 0; secondIndex<2; secondIndex++){

					int location = 2 * firstIndex + secondIndex;

					//check the result for the indices firstIndex and secondIndex in the truth table of the gate
					r = garbledGates[i].truthTableBits[location];

					int rowIndex;//the row in the current garbled table 
					//get the keys from the already calculated wires
				
					int b = wire1signalBitsArray[secondIndex];

					rowIndex = 2 * a + b - 1;

					

					if (rowIndex == -1){//compute the calculated row

						if (r == 0){
							//calc the 0-wire since this row does not exist in the garbled table
							k0 = _mm_xor_si128(encryptedKeys[location], keys[location]);
							if (isK0Set == false){//if the first key was not created yet, caclculate it and set the flag to true

								//put the first key in the output table.
								garbledWires[garbledGates[i].output] = k0;
								//and set the flag to true
								isK0Set = true;
							}
							else{//Key0 was already cretaed, check that it is the same as the one calculated now
								if (!(equalBlocks(k0, garbledWires[garbledGates[i].output])))
									return false;
							}
						}

						else{
							//calc the 1-wire since this row does not exist in the garbled table
							k1 = _mm_xor_si128(encryptedKeys[location], keys[location]);
							if (isK1Set == false){//if the second key was not created yet, caclculate it and set the flag to true
								//set K1 to a temp variable
								k1Set = k1;
								//and set the flag to true
								isK1Set = true;
							}
							else{//Key1 was already cretaed, check that it is the same as the one calculated now
								if (!(equalBlocks(k1, k1Set)))
									return false;
							}
						}
					}
					else{

						if (r == 0){
							//create the 0-wire key using the garbled table.
							k0 = _mm_xor_si128(_mm_xor_si128(encryptedKeys[location], keys[2 * firstIndex + secondIndex]), garbledTables[3 * nonXorIndex + rowIndex]);
							if (isK0Set == false){//if the first key was not created yet, create it using the garbled table and set the flag to true
								
								//put the first key in the output table.
								garbledWires[garbledGates[i].output] = k0;
								//and set the flag to true
								isK0Set = true;
							}
							else{//Key1 was already cretaed, check that it is the same as the one created one
								if (!(equalBlocks(k0, garbledWires[garbledGates[i].output])))
									return false;
							}
						}
						else{
							//create the 1-wire key using the garbled table.
							k1 = _mm_xor_si128(_mm_xor_si128(encryptedKeys[location], keys[location]), garbledTables[3 * nonXorIndex + rowIndex]);
							if (isK1Set == false){//if the second key was not created yet, create it using the garbled table and set the flag to true
								//set K1 to a temp variable
								k1Set = k1;
								//and set the flag to true
								isK1Set = true;
							}
							else{//Key0 was already cretaed, check that it is the same as the one created one
								if (!(equalBlocks(k1, k1Set)))
									return false;
							}
						}
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

	if (isNonXorOutputsRequired){
		verifyOutputWiresToNoFixedDelta(emptyBothWireOutputKeys);
	}

	return isVerified;

}
