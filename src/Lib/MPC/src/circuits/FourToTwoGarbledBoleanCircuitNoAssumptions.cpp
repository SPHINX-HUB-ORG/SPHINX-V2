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
#include "../../include/circuits/intrinsic.h"
#include "../../include/circuits/GarbledGate.h"
#include "../../include/circuits/FourToTwoGarbledBoleanCircuitNoAssumptions.h"

using namespace std;


FourToTwoGarbledBoleanCircuitNoAssumptions::FourToTwoGarbledBoleanCircuitNoAssumptions(void)
{
}
FourToTwoGarbledBoleanCircuitNoAssumptions::~FourToTwoGarbledBoleanCircuitNoAssumptions(void)
{

	if (garbledWires != nullptr){
		garbledWires--;
		garbledWires--;
		_aligned_free(garbledWires);
	}

	if (encryptedChunkKeys != nullptr)
		_aligned_free(encryptedChunkKeys);

	if (indexArray != nullptr)
		_aligned_free(indexArray);
}

FourToTwoGarbledBoleanCircuitNoAssumptions::FourToTwoGarbledBoleanCircuitNoAssumptions(const char* fileName)
{
	//create the needed memory for this circuit
	createCircuitMemory(fileName);
}

void FourToTwoGarbledBoleanCircuitNoAssumptions::createCircuitMemory(const char* fileName, bool isNonXorOutputsRequired) {

	//call the base class to create circuit function
	createCircuit(fileName, false);


	//create this memory and initialize it in construction time to gain performance

	//allocate the garbled table as follows: 2 blocks + one unsigned char for each AND gate and 1 block for xor gate (we add one just to be on the safe side)
	garbledTables = (block *)_aligned_malloc(sizeof(block) * (((numberOfGates - numOfXorGates - numOfNotGates) * 33) / 16 + 1 + numOfXorGates), 16);

	if (garbledTables == nullptr) {
		cout << "garbled tables could not be allocated";
		exit(0);
	}
	memset(garbledTables, 0, (sizeof(block) * (((numberOfGates - numOfXorGates - numOfNotGates) * 33) / 16 + 1 + numOfXorGates)));

	garbledWires = (block *)_aligned_malloc(sizeof(block) * ((lastWireIndex + 1) * 2 + 2), 16);

	if (garbledWires == nullptr) {
		cout << "garbledWires could not be allocated";
		exit(0);
	}
	memset(garbledWires, 0, sizeof(block) * ((lastWireIndex + 1) * 2 + 2));

	garbledWires++;
	garbledWires++;

	//prepare randomness for the input keys and one byte for each AND gate for the signal bit (could use this for 8 gates, but it is fater and clearer like
	//this)
	encryptedChunkKeys = (block *)_aligned_malloc(sizeof(block) *(2 * numberOfInputs + (numberOfGates - numOfXorGates - numOfNotGates) / SIZE_OF_BLOCK + 1), 16);
	if (encryptedChunkKeys == nullptr) {
		cout << "encryptedChunkKeys could not be allocated";
		exit(0);
	}
	memset(encryptedChunkKeys, 0, sizeof(block) * (2 * numberOfInputs + (numberOfGates - numOfXorGates - numOfNotGates) / SIZE_OF_BLOCK + 1));

	indexArray = (block *)_aligned_malloc(sizeof(block) * (2 * numberOfInputs + (numberOfGates - numOfXorGates - numOfNotGates) / SIZE_OF_BLOCK + 1), 16);
	if (indexArray == nullptr) {
		cout << "indexArray could not be allocated";
		exit(0);
	}

	//we put the indices ahead of time to encrypt the whole chunk in one call.
	for (int i = 0; i < 2 * numberOfInputs + (numberOfGates - numOfXorGates - numOfNotGates) / SIZE_OF_BLOCK + 1; i++){

		indexArray[i] = _mm_set_epi32(0, 0, 0, i);

	
	}

}






void FourToTwoGarbledBoleanCircuitNoAssumptions::garble(block *emptyBothInputKeys, block *emptyBothOutputKeys, vector<byte> & emptyTranslationTable, block seed){

	this->seed = seed;

	//init the aes encryptions of the seed and the fixed key. Fill the input wires
	initAesEncryptionsAndInputKeys(emptyBothInputKeys);

	int nonXorIndex = 0;
	int xorIndex = 0;
	ROUND_KEYS* KEYS = (ROUND_KEYS *)_aligned_malloc(4 * 256, 16);


	for (int i = 0; i < numberOfGates; i++){

		if (garbledGates[i].truthTable == XOR_GATE && garbledGates[i].input1 == -1){//This is a NOT gate

			//switch the garbled wires
			garbledWires[garbledGates[i].output * 2] = garbledWires[garbledGates[i].input0 * 2 + 1];
			garbledWires[garbledGates[i].output * 2 + 1] = garbledWires[garbledGates[i].input0 * 2];


		}
		else{

			//get the keys from the input wires of the gate
			block keys[4];

			keys[0] = garbledWires[garbledGates[i].input0 * 2];
			keys[1] = garbledWires[garbledGates[i].input0 * 2 + 1];;

			keys[2] = garbledWires[garbledGates[i].input1 * 2];
			keys[3] = garbledWires[garbledGates[i].input1 * 2 + 1];

			//An array of signal bits the 0-wire. This prevents from calling the function getSignalBitOf more than
			//once for each 0-wire in the for loop below
			int wire0signalBitsArray[2];
			wire0signalBitsArray[0] = getSignalBitOf(keys[0]);
			wire0signalBitsArray[1] = 1 - wire0signalBitsArray[0];


			//An array of signal bits the 0-wire. This prevents from calling the function getSignalBitOf more than
			//once for each 0-wire in the for loop below
			int wire1signalBitsArray[2];
			wire1signalBitsArray[0] = getSignalBitOf(keys[2]);
			wire1signalBitsArray[1] = 1 - wire1signalBitsArray[0];



			if (garbledGates[i].truthTable == XOR_GATE){

				block plaintext[4];
				//prepare the plaintext 
				plaintext[0] = _mm_set_epi32(wire0signalBitsArray[0], 0, 0, i);
				plaintext[1] = _mm_set_epi32(wire0signalBitsArray[1], 0, 0, i);
				plaintext[2] = _mm_set_epi32(wire1signalBitsArray[0], 0, 0, i);
				plaintext[3] = _mm_set_epi32(wire1signalBitsArray[1], 0, 0, i);

				block ciphertext[4];

				//encrypt 4ks_senc
				intrin_sequential_ks4_enc4((const unsigned char*)plaintext, (unsigned char*)ciphertext, 1, (unsigned char*)KEYS, (unsigned char*)keys, nullptr);


				block deltaOutput = _mm_xor_si128(ciphertext[0], ciphertext[1]);

				//this code is according to the pseudo code of the paper
				if (wire1signalBitsArray[0] == 0){
					garbledWires[garbledGates[i].output * 2] = _mm_xor_si128(ciphertext[0], ciphertext[2]);

				}
				else{
					garbledWires[garbledGates[i].output * 2] = _mm_xor_si128(ciphertext[1], ciphertext[3]);
				}

				//set the first row of the garbled table
				garbledTables[2 * nonXorIndex + xorIndex] = _mm_xor_si128(_mm_xor_si128(ciphertext[2], ciphertext[3]), deltaOutput);


				//make the signal bit be 1.
				*((unsigned char *)(&deltaOutput)) |= 1;

				//we now need to do some signal bits fixing
				int theRightSignalBit = wire0signalBitsArray[0] ^ wire1signalBitsArray[0];
				int outputCurrentSignalBit = getSignalBitOf(garbledWires[garbledGates[i].output * 2]);

				//only if the signal bits are not matching fix the output key signal bit
				if (theRightSignalBit != outputCurrentSignalBit){
					//flip the signal bit
					*((unsigned char *)(&garbledWires[garbledGates[i].output * 2])) = *((unsigned char *)(&garbledWires[garbledGates[i].output * 2])) ^ 1;
				}

				//since we have fixed the deltaOutput we can now safely do the xor and get the right signal bit
				garbledWires[garbledGates[i].output * 2 + 1] = _mm_xor_si128(garbledWires[garbledGates[i].output * 2], deltaOutput);

				xorIndex++;

				continue;
			}

			else{//This is an AND gate

				block T1, T2;


				//We crete the signal bits of input0 and input 1 by 2*signalBit(wire0) + signalBit(wire1)
				int signalBits[4];
				signalBits[0] = 2 * wire0signalBitsArray[0] + wire1signalBitsArray[0];
				signalBits[1] = 2 * wire0signalBitsArray[0] + wire1signalBitsArray[1];
				signalBits[2] = 2 * wire0signalBitsArray[1] + wire1signalBitsArray[0];
				signalBits[3] = 2 * wire0signalBitsArray[1] + wire1signalBitsArray[1];

				block plainText[8];
				block cipherText[8];

				//set the plaintexts to be the signal bit and the tweak
				for (int j = 0; j < 4; j++){
					plainText[j] = _mm_set_epi32(signalBits[j], 0, 0, i);
				}
				plainText[4] = plainText[0];
				plainText[5] = plainText[2];
				plainText[6] = plainText[1];
				plainText[7] = plainText[3];


				//encrypt the plaintext by 4 key schedules and 8 encryptions
				intrin_sequential_ks4_enc8((const unsigned char*)plainText, (unsigned char*)cipherText, 4, (unsigned char*)KEYS, (unsigned char*)keys, nullptr);

				block cipherText2[4];
				cipherText2[0] = cipherText[4 + 0];
				cipherText2[1] = cipherText[4 + 2];
				cipherText2[2] = cipherText[4 + 1];
				cipherText2[3] = cipherText[4 + 3];

				block entryXor[4];
				unsigned char lastBit[4];

				//get the last bit of the ciphers
				for (int j = 0; j < 4; j++){
					entryXor[j] = _mm_xor_si128(cipherText[signalBits[j]], cipherText2[signalBits[j]]);
					lastBit[j] = getSignalBitOf(entryXor[j]);
				}

				for (int j = 0; j < 4; j++){

					//set the last bit to zero
					if (getSignalBitOf(entryXor[j]) != 0)
						*((unsigned char *)(&entryXor[j])) = *((unsigned char *)(&entryXor[j])) ^ 1;
				}

				//compute T1
				if (wire0signalBitsArray[0] == 0){//the cases of 0001 and 0010
					T1 = _mm_xor_si128(entryXor[0], entryXor[1]);
				}
				else{//the cases of 0100 and 1000
					T1 = _mm_xor_si128(entryXor[2], entryXor[3]);
				}

				//compute T2
				if (wire1signalBitsArray[0] == 0){//the cases of 0001 and 0100
					T2 = _mm_xor_si128(entryXor[0], entryXor[2]);
				}
				else{
					T2 = _mm_xor_si128(entryXor[1], entryXor[3]);
				}

				//get the random bit generated by the seed
				unsigned char output0SignalBit = ((unsigned char *)encryptedChunkKeys)[SIZE_OF_BLOCK * 2 * numberOfInputs + nonXorIndex] % 2;
				unsigned char output1SignalBit = 1 - output0SignalBit;

				//create the mask table for the evaluator to retrieve the right signal bit
				unsigned char mask = 0;

				mask |= (lastBit[signalBits[3]] ^ output1SignalBit) << signalBits[3];
				mask |= (lastBit[signalBits[2]] ^ output0SignalBit) << signalBits[2];
				mask |= (lastBit[signalBits[1]] ^ output0SignalBit) << signalBits[1];
				mask |= (lastBit[signalBits[0]] ^ output0SignalBit) << signalBits[0];




				//put the masks in the end of the garbled table 
				((unsigned char*)garbledTables)[((numberOfGates - numOfXorGates- numOfNotGates) * 2 + numOfXorGates) * 16 + nonXorIndex] = mask;


				//now create the garbled table wich is T1 and T2
				garbledTables[2 * nonXorIndex + xorIndex] = T1;
				garbledTables[2 * nonXorIndex + xorIndex + 1] = T2;


				//generate the garbled wires according to the case of the signal bits
				if (signalBits[0] != 3){
					*((unsigned char *)(&entryXor[0])) = *((unsigned char *)(&entryXor[0])) ^ output0SignalBit;
					garbledWires[2 * garbledGates[i].output] = entryXor[0];

					garbledWires[2 * garbledGates[i].output + 1] = _mm_xor_si128(_mm_xor_si128(entryXor[1], entryXor[2]), entryXor[3]);
					*((unsigned char *)(&garbledWires[2 * garbledGates[i].output + 1])) = *((unsigned char *)(&garbledWires[2 * garbledGates[i].output + 1])) ^ output1SignalBit;
				}
				else{

					*((unsigned char *)(&entryXor[0])) = *((unsigned char *)(&entryXor[0])) ^ output1SignalBit;
					garbledWires[2 * garbledGates[i].output + 1] = entryXor[0];

					garbledWires[2 * garbledGates[i].output] = _mm_xor_si128(_mm_xor_si128(entryXor[1], entryXor[2]), entryXor[3]);
					*((unsigned char *)(&garbledWires[2 * garbledGates[i].output])) = *((unsigned char *)(&garbledWires[2 * garbledGates[i].output])) ^ output0SignalBit;
				}

				nonXorIndex++;
			}
		}

	}


	translationTable.clear();
	//copy the output keys to get back to the caller of the function as well as filling the translation table.
	//The input keys were already filled in the initialization of the function.
	for (int i = 0; i < numberOfOutputs; i++) {
		emptyBothOutputKeys[2 * i] = garbledWires[outputIndices[i] * 2];
		emptyBothOutputKeys[2 * i + 1] = garbledWires[outputIndices[i] * 2 + 1];

		translationTable.push_back(getSignalBitOf(emptyBothOutputKeys[2 * i]));
		emptyTranslationTable.push_back(getSignalBitOf(emptyBothOutputKeys[2 * i]));
		
	}

	_aligned_free(KEYS);

}


int FourToTwoGarbledBoleanCircuitNoAssumptions::getGarbledTableSize()
{
	
	if (isNonXorOutputsRequired == true) {
		return (sizeof(block) * (((numberOfGates - numOfXorGates - numOfNotGates) * 33) / 16 + 1 + numOfXorGates) + 2 * numberOfOutputs);
	}
	else {
		return (sizeof(block) * (((numberOfGates - numOfXorGates - numOfNotGates) * 33) / 16 + 1 + numOfXorGates));
	}


}

void FourToTwoGarbledBoleanCircuitNoAssumptions::initAesEncryptionsAndInputKeys(block* emptyBothInputKeys){

	//create the aes with the seed as the key. This will be used for encrypting the input keys
	AES_set_encrypt_key((const unsigned char *)&seed, 128, &aesSeedKey);


	//generate randomness for the input keys as well as the signal bits for the AND gates

	AES_ecb_encrypt_chunk_in_out(indexArray,
		encryptedChunkKeys,
		(2 * numberOfInputs + (numberOfGates - numOfXorGates - numOfNotGates) / SIZE_OF_BLOCK + 1),
		&aesSeedKey);


	/*AES_ECB_encrypt((const unsigned char *)indexArray,
		(unsigned char *)encryptedChunkKeys,
		SIZE_OF_BLOCK * (2 * numberOfInputs + (numberOfGates - numOfXorGates - numOfNotGates) / SIZE_OF_BLOCK + 1),
		(const unsigned char *)aesSeedKey->rd_key,
		aesSeedKey->rounds);
		*/

	//put the values of zero and a random encryption of -1 in the begining of the garbled wires for future use of the NOT gates
	block index = _mm_set_epi32(0, 0, 0, -1);

	garbledWires[-1] = ZERO_BLOCK;

	AES_encryptC(&index, &garbledWires[-2], &aesSeedKey);

	//set the input keys
	for (int i = 0; i<numberOfInputs; i++){

		emptyBothInputKeys[2 * i] = encryptedChunkKeys[2 * i];
		emptyBothInputKeys[2 * i] = encryptedChunkKeys[2 * i + 1];

		setSignalBit(&(emptyBothInputKeys[2 * i]), &(emptyBothInputKeys[2 * i + 1]));

		//copy the input keys to the garbledWires array
		garbledWires[inputIndices[i] * 2] = emptyBothInputKeys[2 * i];
		garbledWires[inputIndices[i] * 2 + 1] = emptyBothInputKeys[2 * i + 1];

	}

}

void  FourToTwoGarbledBoleanCircuitNoAssumptions::compute(block * singleWiresInputKeys, block * Output)
{

	ROUND_KEYS* KEY = (ROUND_KEYS *)_aligned_malloc(4 * 256, 16);
	int nonXorIndex = 0;
	int xorIndex = 0;
	for (int i = 0; i<numberOfInputs; i++){

		//get the input keys into the computed wires array
		computedWires[inputIndices[i]] = singleWiresInputKeys[i];
	}
	
	//start computing the circuit by going over the gates in topological order
	for (int i = 0; i<numberOfGates; i++){

		if (garbledGates[i].truthTable == XOR_GATE && garbledGates[i].input1 == -1){//This is a NOT gate

			//the signal bits are fliped in the garble (by switching the garbled wires) and thus this is actually NOT gate.
			computedWires[garbledGates[i].output] = computedWires[garbledGates[i].input0];
		}
		else{

			block keys[2];

			//get the keys from the already calculated wires
			keys[0] = computedWires[garbledGates[i].input0];
			keys[1] = computedWires[garbledGates[i].input1];

			//Get the signal bits of the computed inputs
			int wire0SignalBit = getSignalBitOf(keys[0]);
			int wire1SignalBit = getSignalBitOf(keys[1]);

			//create the ciphertext
			block ciphertext[2];
			block plaintext[2];

			if (garbledGates[i].truthTable == XOR_GATE){//handle xor gates

				//prepare the plaintext
				plaintext[0] = _mm_set_epi32(wire0SignalBit, 0, 0, i);
				plaintext[1] = _mm_set_epi32(wire1SignalBit, 0, 0, i);

				intrin_sequential_ks2_enc2((const unsigned char*)plaintext, (unsigned char*)ciphertext, 2, (unsigned char*)KEY, (unsigned char*)keys, nullptr);

				//check the psudocode of the paper for more information
				if (wire1SignalBit == 1){
					computedWires[garbledGates[i].output] = _mm_xor_si128(_mm_xor_si128(ciphertext[0], ciphertext[1]), garbledTables[2 * nonXorIndex + xorIndex]);
				}
				else{		
					computedWires[garbledGates[i].output] = _mm_xor_si128(ciphertext[0], ciphertext[1]);
				}


				//we now need to do some signal bits fixing
				int theRightSignalBit = wire0SignalBit ^ wire1SignalBit;
				int outputCurrentSignalBit = getSignalBitOf(computedWires[garbledGates[i].output]);


				if (theRightSignalBit != outputCurrentSignalBit){
					//flip the signal bit
					*((unsigned char *)(&computedWires[garbledGates[i].output])) = *((unsigned char *)(&computedWires[garbledGates[i].output])) ^ 1;
				}

				xorIndex++;

			}

			else{


				plaintext[0] = _mm_set_epi32(2 * wire0SignalBit + wire1SignalBit, 0, 0, i);
				plaintext[1] = plaintext[0];


				intrin_sequential_ks2_enc2((const unsigned char*)plaintext, (unsigned char*)ciphertext, 2, (unsigned char*)KEY, (unsigned char*)keys, nullptr);



				block entryXor = _mm_xor_si128(ciphertext[0], ciphertext[1]);

				unsigned char lastBit = getSignalBitOf(entryXor);


				//now correct the signal bit , first get the mask
				unsigned char mask = ((unsigned char*)garbledTables)[((numberOfGates - numOfXorGates-numOfNotGates) * 2 + numOfXorGates) * 16 + nonXorIndex];
				//get the bit of the mask
				int index = 2 * wire0SignalBit + wire1SignalBit;
				unsigned char theRightBit = ((mask >> index) & 1) ^ lastBit;


				switch (index) {

				case 0:
					computedWires[garbledGates[i].output] = entryXor;
					break;
				case 1:
					computedWires[garbledGates[i].output] = _mm_xor_si128(entryXor, garbledTables[2 * nonXorIndex + xorIndex]);
					break;
				case 2:
					computedWires[garbledGates[i].output] = _mm_xor_si128(entryXor, garbledTables[2 * nonXorIndex + xorIndex + 1]);
					break;
				case 3:
					computedWires[garbledGates[i].output] = _mm_xor_si128(_mm_xor_si128(entryXor, garbledTables[2 * nonXorIndex + xorIndex]), garbledTables[2 * nonXorIndex + xorIndex + 1]);
					break;

				default:
					;//do nothing

				}



				unsigned char  outputCurrentSignalBit = getSignalBitOf(computedWires[garbledGates[i].output]);

				//if the current signal bit is not the signal generated using the mask than flip the signal bit
				if (theRightBit != outputCurrentSignalBit){
					//flip the signal bit
					*((unsigned char *)(&computedWires[garbledGates[i].output])) = *((unsigned char *)(&computedWires[garbledGates[i].output])) ^ 1;
				}



				//increment the nonXor gates number only for the AND gates. 
				nonXorIndex++;
			}
		}
	}


	//copy the output wire keys which are the result the user is interested in.
	for (int i = 0; i < numberOfOutputs; i++) {
		Output[i] = computedWires[outputIndices[i]];

	}

	_aligned_free(KEY);



}


bool FourToTwoGarbledBoleanCircuitNoAssumptions::internalVerify(block *bothInputKeys, block *emptyBothWireOutputKeys){

	int nonXorIndex = 0;
	int xorIndex = 0;
	ROUND_KEYS* KEYS = (ROUND_KEYS *)_aligned_malloc(4 * 256, 16);


	for (int i = 0; i < numberOfGates; i++){

		if (garbledGates[i].truthTable == XOR_GATE && garbledGates[i].input1 == -1){//This is a NOT gate

			//switch the garbled wires
			garbledWires[garbledGates[i].output * 2] = garbledWires[garbledGates[i].input0 * 2 + 1];
			garbledWires[garbledGates[i].output * 2 + 1] = garbledWires[garbledGates[i].input0 * 2];


		}
		else{

			//get the keys from the input wires of the gate
			block keys[4];

			keys[0] = garbledWires[garbledGates[i].input0 * 2];
			keys[1] = garbledWires[garbledGates[i].input0 * 2 + 1];;

			keys[2] = garbledWires[garbledGates[i].input1 * 2];
			keys[3] = garbledWires[garbledGates[i].input1 * 2 + 1];

			//An array of signal bits the 0-wire. This prevents from calling the function getSignalBitOf more than
			//once for each 0-wire in the for loop below
			int wire0signalBitsArray[2];
			wire0signalBitsArray[0] = getSignalBitOf(keys[0]);
			wire0signalBitsArray[1] = 1 - wire0signalBitsArray[0];


			//An array of signal bits the 0-wire. This prevents from calling the function getSignalBitOf more than
			//once for each 0-wire in the for loop below
			int wire1signalBitsArray[2];
			wire1signalBitsArray[0] = getSignalBitOf(keys[2]);
			wire1signalBitsArray[1] = 1 - wire1signalBitsArray[0];



			if (garbledGates[i].truthTable == XOR_GATE){

				block plaintext[4];
				//prepare the plaintext 
				plaintext[0] = _mm_set_epi32(wire0signalBitsArray[0], 0, 0, i);
				plaintext[1] = _mm_set_epi32(wire0signalBitsArray[1], 0, 0, i);
				plaintext[2] = _mm_set_epi32(wire1signalBitsArray[0], 0, 0, i);
				plaintext[3] = _mm_set_epi32(wire1signalBitsArray[1], 0, 0, i);

				block ciphertext[4];

				//encrypt 4ks_senc
				intrin_sequential_ks4_enc4((const unsigned char*)plaintext, (unsigned char*)ciphertext, 1, (unsigned char*)KEYS, (unsigned char*)keys, nullptr);


				block deltaOutput = _mm_xor_si128(ciphertext[0], ciphertext[1]);

				//if deltaOutput has 1 signal bit, than fine
				//else flip ciphertext[1] signal bit.

				if (wire1signalBitsArray[0] == 0){
					garbledWires[garbledGates[i].output * 2] = _mm_xor_si128(ciphertext[0], ciphertext[2]);

				}
				else{
					garbledWires[garbledGates[i].output * 2] = _mm_xor_si128(ciphertext[1], ciphertext[3]);
				}

				if (!equalBlocks(garbledTables[2 * nonXorIndex + xorIndex], _mm_xor_si128(_mm_xor_si128(ciphertext[2], ciphertext[3]), deltaOutput)))
					return false;


				//make the signal bit be 1.
				*((unsigned char *)(&deltaOutput)) |= 1;

				//we now need to do some signal bits fixing
				int theRightSignalBit = wire0signalBitsArray[0] ^ wire1signalBitsArray[0];
				int outputCurrentSignalBit = getSignalBitOf(garbledWires[garbledGates[i].output * 2]);

				//only if the signal bits are not matching fix the output key signal bit
				if (theRightSignalBit != outputCurrentSignalBit){
					//flip the signal bit
					*((unsigned char *)(&garbledWires[garbledGates[i].output * 2])) = *((unsigned char *)(&garbledWires[garbledGates[i].output * 2])) ^ 1;
				}

				//since we have fixed the deltaOutput we can now safely do the xor and get the right signal bit
				garbledWires[garbledGates[i].output * 2 + 1] = _mm_xor_si128(garbledWires[garbledGates[i].output * 2], deltaOutput);


				xorIndex++;

				continue;
			}

			//Since the seed is not supplied, the check is on the garbled wires and not the garbled tables.
			//The signal bit is 
			else{//This is an AND gate. 

				//We crete the signal bits of input0 and input 1 by 2*signalBit(wire0) + signalBit(wire1)
				//In this case we avoid calling getSignalBitOf twice as much.
				int signalBits[4];
				signalBits[0] = 2 * wire0signalBitsArray[0] + wire1signalBitsArray[0];
				signalBits[1] = 2 * wire0signalBitsArray[0] + wire1signalBitsArray[1];
				signalBits[2] = 2 * wire0signalBitsArray[1] + wire1signalBitsArray[0];
				signalBits[3] = 2 * wire0signalBitsArray[1] + wire1signalBitsArray[1];

				//generate the keys array as well as the encryptedKeys array
				block plainText[8];
				block cipherText[8];
				//Encrypt the 4 keys in one chunk to gain pipelining and puts the answer in encryptedKeys block array
				//AES_ecb_encrypt_blks_4_in_out(keys, encryptedKeys, aesFixedKey);

				for (int j = 0; j < 4; j++){
					plainText[j] = _mm_set_epi32(signalBits[j], 0, 0, i);
				}
				plainText[4] = plainText[0];
				plainText[5] = plainText[2];
				plainText[6] = plainText[1];
				plainText[7] = plainText[3];


				//create the plaintext which is the ks4_ec8
				intrin_sequential_ks4_enc8((const unsigned char*)plainText, (unsigned char*)cipherText, 4, (unsigned char*)KEYS, (unsigned char*)keys, nullptr);

				block cipherText2[4];
				cipherText2[0] = cipherText[4 + 0];
				cipherText2[1] = cipherText[4 + 2];
				cipherText2[2] = cipherText[4 + 1];
				cipherText2[3] = cipherText[4 + 3];

				block entryXor[4];
				unsigned char lastBit[4];

				block k0;//the 0-value that is kept to compare with future 0-values and check that they are infact equal
				bool isK0Set = false;

				//get the last bit of the ciphers
				for (int j = 0; j < 4; j++){
					entryXor[j] = _mm_xor_si128(cipherText[j], cipherText2[j]);
					lastBit[j] = getSignalBitOf(entryXor[j]);
				}

				//get the mask for this gate
				unsigned char mask = ((unsigned char*)garbledTables)[((numberOfGates - numOfXorGates - numOfNotGates) * 2 + numOfXorGates) * 16 + nonXorIndex];


				for (int j = 0; j < 4; j++){
					//get the bit of the mask
					int index = signalBits[j];
					unsigned char theRightBit = ((mask >> index) & 1) ^ lastBit[j];

					if (j != 3){//the 0 value's of the AND gate
						switch (index) {

						case 0:
							garbledWires[garbledGates[i].output*2] = entryXor[j];
							break;
						case 1:
							garbledWires[garbledGates[i].output * 2] = _mm_xor_si128(entryXor[j], garbledTables[2 * nonXorIndex + xorIndex]);
							break;
						case 2:
							garbledWires[garbledGates[i].output * 2] = _mm_xor_si128(entryXor[j], garbledTables[2 * nonXorIndex + xorIndex + 1]);
							break;
						case 3:
							garbledWires[garbledGates[i].output * 2] = _mm_xor_si128(_mm_xor_si128(entryXor[j], garbledTables[2 * nonXorIndex + xorIndex]), garbledTables[2 * nonXorIndex + xorIndex + 1]);
							break;

						default:
							;//do nothing

						}



						unsigned char  outputCurrentSignalBit = getSignalBitOf(garbledWires[garbledGates[i].output*2]);
						//int theRightBit = getSignalBitOf(entryXor) ^ signalBit;

						if (theRightBit != outputCurrentSignalBit){
							//flip the signal bit
							*((unsigned char *)(&garbledWires[garbledGates[i].output*2])) = *((unsigned char *)(&garbledWires[garbledGates[i].output*2])) ^ 1;
						}

						if (isK0Set == false){
							k0 = garbledWires[garbledGates[i].output * 2];
							isK0Set = true;
						}
						else{
							if (!(equalBlocks(k0, garbledWires[garbledGates[i].output*2])))
								return false;
							
						}
					}
					else{//this is the 1-value, since in AND gate it is the only 1-value, just set the garbled wire of the output
						switch (index) {

						case 0:
							garbledWires[garbledGates[i].output *2 + 1] = entryXor[j];
							break;
						case 1:
							garbledWires[garbledGates[i].output * 2 + 1] = _mm_xor_si128(entryXor[j], garbledTables[2 * nonXorIndex + xorIndex]);
							break;
						case 2:
							garbledWires[garbledGates[i].output * 2 + 1] = _mm_xor_si128(entryXor[j], garbledTables[2 * nonXorIndex + xorIndex + 1]);
							break;
						case 3:
							garbledWires[garbledGates[i].output * 2 + 1] = _mm_xor_si128(_mm_xor_si128(entryXor[j], garbledTables[2 * nonXorIndex + xorIndex]), garbledTables[2 * nonXorIndex + xorIndex + 1]);
							break;

						default:
							;//do nothing

						}



						unsigned char  outputCurrentSignalBit = getSignalBitOf(garbledWires[garbledGates[i].output * 2 + 1]);
						//int theRightBit = getSignalBitOf(entryXor) ^ signalBit;

						if (theRightBit != outputCurrentSignalBit){
							//flip the signal bit
							*((unsigned char *)(&garbledWires[garbledGates[i].output * 2 + 1])) = *((unsigned char *)(&garbledWires[garbledGates[i].output * 2 + 1])) ^ 1;
						}
					}
				}
				nonXorIndex++;
				
			}
		}

	}

	//copy the output keys to return to the caller of the function
	for (int i = 0; i < numberOfOutputs; i++) {
		emptyBothWireOutputKeys[2 * i] = garbledWires[outputIndices[i] * 2];
		emptyBothWireOutputKeys[2 * i + 1] = garbledWires[outputIndices[i] * 2 + 1];


	}

	return true;
}
