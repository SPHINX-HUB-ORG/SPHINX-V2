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
#include "../../include/circuits/StandardGarbledBooleanCircuit.h"
#include "../../include/circuits/GarbledBooleanCircuitFixedKey.h"


using namespace std;

StandardGarbledBooleanCircuit::StandardGarbledBooleanCircuit(){}


StandardGarbledBooleanCircuit::~StandardGarbledBooleanCircuit()
{
	if (garbledWires != nullptr){
		garbledWires--;
		garbledWires--;
		_aligned_free(garbledWires);
	}
}

StandardGarbledBooleanCircuit::StandardGarbledBooleanCircuit(const char* fileName)
{
	//create the needed memory for this circuit
	createCircuitMemory(fileName);
	isFreeXor = false;
}
void StandardGarbledBooleanCircuit::createCircuitMemory(const char* fileName, bool isNonXorOutputsRequired){

	createCircuit(fileName, false, false);
	this->isNonXorOutputsRequired = false;

	numOfRows = 4;

	//create this memory and initialize it in construction time to gain performance
	garbledTables = (block *)_aligned_malloc(sizeof(block) * numberOfGates * 4, 16);
	if (garbledTables == nullptr) {
		cout << "garbledTables could not be allocated";
		exit(0);
	}
	memset(garbledTables, 0, (sizeof(block) *numberOfGates * 4));


	garbledWires = (block *)_aligned_malloc(sizeof(block) * ((lastWireIndex +1) * 2 + 2), 16);

	if (garbledWires == nullptr) {
		cout << "garbledWires could not be allocated";
		exit(0);
	}
	memset(garbledWires, 0, (sizeof(block) *((lastWireIndex + 1) * 2 + 2)));
	garbledWires++;//increment back so the fixed 0-wire and 1-wire of the -1 wire will be accessed by a negative value.
	garbledWires++;

	indexArray = (block *)_aligned_malloc(sizeof(block) *  ((lastWireIndex + 1) * 2 + 2), 16);
	if (indexArray == nullptr) {
		cout << "arrayToEncrypt could not be allocated";
		exit(0);
	}

	for (int i = 0; i < (lastWireIndex + 1) * 2 + 2; i++)
		indexArray[i] = _mm_set_epi32(0, 0, 0, i);

}

void StandardGarbledBooleanCircuit::garble(block *emptyBothInputKeys, block *emptyBothOutputKeys, vector<unsigned char> & emptyTranslationTable, block seed){
	
	this->seed = seed;

	//init encryption key of the seed and calc all the wire keys
	initAesEncryptionsAndAllKeys(emptyBothInputKeys);

	//declare some variables that will be used for garbling
	block A;
	block twoA;
	block B;
	block fourB;
	int r;
	int rowNumber;
	block tweak;
	
	for(int i=0; i<numberOfGates; i++){
	

		//generate the keys array as well as the encryptedKeys array
		tweak =  _mm_set_epi32(0,0,0,i);

		//create input arrays in order to get the inputs immedietly and not invoke unneeded xor's
		block input0Both[2];
		block input1Both[2];
		input0Both[0] = garbledWires[2*garbledGates[i].input0];
		input0Both[1] = garbledWires[2 * garbledGates[i].input0 + 1];

		input1Both[0] = garbledWires[2* garbledGates[i].input1];
		input1Both[1] = garbledWires[2 * garbledGates[i].input1 + 1];

		//generate the keys array
		block keys[4];
		for(int a=0;a<2;a++){

			A = input0Both[a];
			//Shift left to double A for security (actually the 2 64 bit are shifted and not the whole 128 bit block
			twoA = _mm_slli_epi64(A,1);
			for(int b=0; b<2; b++)
			{

				B = input1Both[b];

				//Shift right instead of shifting left twice.This is secure since the alignment is broken
				fourB = _mm_srli_epi64(B,1);
				//block fourB = _mm_slli_epi64(B,2);

				//calc 2A+4B+T.
				keys[2 * a + b] = _mm_xor_si128((_mm_xor_si128(twoA, fourB)), tweak);


			}
		}
		
		//generate the keys array as well as the encryptedKeys array
		block encryptedKeys[4];
		//Encrypt the 4 keys in one chunk to gain pipelining and puts the answer in encryptedKeys block array
		AES_ecb_encrypt_blks_4_in_out(keys, encryptedKeys, &aesFixedKey);

			
		//save the output to a local array
		block outputBoth[2];
		outputBoth[0] = garbledWires[garbledGates[i].output * 2];
		outputBoth[1] = garbledWires[garbledGates[i].output * 2 + 1];


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
			
		for(int a=0;a<2;a++){
			//get the signal bit from the pre-claculated array
			int wire0signalBit = wire0signalBitsArray[a];
			for(int b=0; b<2; b++){

				int location = 2 * a + b;
				//get the signal bit from the pre-claculated array
				int wire1signalBit = wire1signalBitsArray[b];
					
				//calc the row number the encrypted values should be put in
				rowNumber = 2*wire0signalBit + wire1signalBit;
				
				//get the location from the truth table array to improve performance
				r = garbledGates[i].truthTableBits[location];/* -'0';*/
				
				//calculate the garbled table for this gate. That is, calc  E(2A+4B+T)^K^Output
				garbledTables[i*4 + rowNumber] = _mm_xor_si128(_mm_xor_si128(encryptedKeys[location], keys[location]), outputBoth[r]);
					
			}
			
		}

	}
	translationTable.clear();
	//copy the output keys to get back to the caller of the function as well as filling the translation table.
	//The input keys were already filled in the initialization of the function.
	for (int i = 0; i < numberOfOutputs; i++) {
		emptyBothOutputKeys[2 * i] = garbledWires[outputIndices[i] *2];
		emptyBothOutputKeys[2 * i + 1] = garbledWires[outputIndices[i] *2 +1];

		//update the translation table
		
		translationTable.push_back(getSignalBitOf(emptyBothOutputKeys[2 * i]));
		emptyTranslationTable.push_back(getSignalBitOf(emptyBothOutputKeys[2 * i]));
		
	}

}


int StandardGarbledBooleanCircuit::getGarbledTableSize()
{

	if (isNonXorOutputsRequired == true) {
		return sizeof(block) * (numberOfGates * getNumOfRows() + 2 * numberOfOutputs);
	}
	else {
		return sizeof(block) * numberOfGates * getNumOfRows();
	}


}

void StandardGarbledBooleanCircuit::initAesEncryptionsAndAllKeys(block* emptyBothInputKeys){

	//clock_t stop , start;
	//reserve memory for the translation table
	translationTable.reserve(numberOfOutputs);

	///create the aes with the seed as the key. This will be used for encrypting the input keys
	AES_set_encrypt_key((const unsigned char *)&seed, 128, &aesSeedKey);

	
	//encrypt all the keys in one call with large arrays
	AES_ecb_encrypt_chunk_in_out(indexArray, garbledWires-2, (lastWireIndex + 1) * 2+2, &aesSeedKey);
	

	//put in the 1-wire 0 this is the value of the computed wire in position -1 and thus the thruth table for XOR produced from NOT gate will be computed to NOT
	garbledWires[-1] = ZERO_BLOCK;


	for (int i = -1; i < lastWireIndex+1; i++){
		setSignalBit(&garbledWires[2 * i + 1], &garbledWires[2 * i]);

	}
	
	//copy the input keys to the emptyBothInputKeys array
	for (int i = 0; i<numberOfInputs; i++){
		emptyBothInputKeys[2 * i]= garbledWires[inputIndices[i]*2] ;
		emptyBothInputKeys[2 * i+1] = garbledWires[inputIndices[i] *2 +1];
	}

}



bool StandardGarbledBooleanCircuit::internalVerify(block *bothInputKeys, block *emptyBothWireOutputKeys){

	bool isVerified = true;

	int r;

	//copy both input keys
	for (int i = 0; i<numberOfInputs; i++){

		//get the input keys into the computed wires array
		garbledWires[inputIndices[i]*2] = bothInputKeys[2 * i];
		garbledWires[inputIndices[i]*2+1] = bothInputKeys[2 * i + 1];
	}

	for (int i = 0; i<numberOfGates; i++){


		//create local input arrays to store the input values
		block input0Both[2];
		block input1Both[2];
		input0Both[0] = garbledWires[garbledGates[i].input0*2];
		input0Both[1] = garbledWires[garbledGates[i].input0 * 2 + 1];

		input1Both[0] = garbledWires[garbledGates[i].input1 *2];
		input1Both[1] = garbledWires[garbledGates[i].input1 * 2 + 1];

		
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

		block tweak = _mm_set_epi32(0, 0, 0, i);

		//generate the keys array
		block keys[4];
		for (int firstIndex = 0; firstIndex<2; firstIndex++){
			//get the key from the already calculated wire
			block A = input0Both[firstIndex];

			//Shift left to double A for security (actually the 2 64 bit are shifted and not the whole 128 bit block
			block twoA = _mm_slli_epi64(A, 1);

			for (int secondIndex = 0; secondIndex<2; secondIndex++){

				//get the key from the already calculated wire
				block B = input1Both[secondIndex];

				//Shift right instead of shifting left twice.This is secure since the alignment is broken
				block fourB = _mm_srli_epi64(B, 1);


				//deduce the key to encrypt
				keys[2 * firstIndex + secondIndex] = _mm_xor_si128(_mm_xor_si128(twoA, fourB), tweak);
			}
		}


		//generate the keys array as well as the encryptedKeys array
		block encryptedKeys[4];
		//Encrypt the 4 keys in one chunk to gain pipelining and puts the answer in encryptedKeys block array
		AES_ecb_encrypt_blks_4_in_out(keys, encryptedKeys, &aesFixedKey);

		//declare temp variables to store the 0-wire key and the 1-wire key
		block k0;
		block k1;
		
		//flags that indicateif we have already calcaulated the keys before
		bool isK0Set = false;
		bool isK1Set = false;

		for (int firstIndex = 0; firstIndex<2; firstIndex++){
			//get the signal bit of A from the pre-claculated array
			int a = wire0signalBitsArray[firstIndex];
			for (int secondIndex = 0; secondIndex<2; secondIndex++){

				//check the result for the indices firstIndex and secondIndex in the truth table of the gate
				r = garbledGates[i].truthTableBits[2 * firstIndex + secondIndex];

				int rowIndex;//the row in the current garbled table 

				//get the signal bit of A from the pre-claculated array
				int b = wire1signalBitsArray[secondIndex];
					
				rowIndex = 2 * a + b;//the row in the current garbled table.

				if (r == 0){
					//create the 0-wire key using the garbled table.
					k0 = _mm_xor_si128(_mm_xor_si128(encryptedKeys[2 * firstIndex + secondIndex], keys[2 * firstIndex + secondIndex]), garbledTables[4 * i + rowIndex]);
					if (isK0Set == false){
						//put the 0-key in the output table.
						garbledWires[garbledGates[i].output*2] = k0;
						//set the flag to true
						isK0Set = true;
					}
					else{//Key1 was already cretaed, check that it is the same as the one created one
						if (!(equalBlocks(k0, garbledWires[garbledGates[i].output * 2])))
							return false;
					}
				}
				else{
					//create the 1-wire key using the garbled table.
					k1 = _mm_xor_si128(_mm_xor_si128(encryptedKeys[2 * firstIndex + secondIndex], keys[2 * firstIndex + secondIndex]), garbledTables[4 * i + rowIndex]);
					if (isK1Set == false){
						//put the 1-key in the output table.
						garbledWires[garbledGates[i].output * 2+1] = k1;
						//set the flag to true
						isK1Set = true;
					}
					else{//Key1 was already cretaed, check that it is the same as the one created now
						if (!(equalBlocks(k1, garbledWires[garbledGates[i].output * 2 + 1])))
							return false;
					}
				}
			}
		}

	}

	//copy the output keys to return to the caller of the function
	for (int i = 0; i < numberOfOutputs; i++) {
		emptyBothWireOutputKeys[2 * i] = garbledWires[outputIndices[i]*2];
		emptyBothWireOutputKeys[2 * i + 1] = garbledWires[outputIndices[i]*2 + 1];
		

	}

	return isVerified;

}
