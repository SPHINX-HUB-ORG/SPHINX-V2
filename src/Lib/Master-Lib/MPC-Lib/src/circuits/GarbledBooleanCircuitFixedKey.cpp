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

#include "../../include/circuits/Compat.h"
#include "../../include/circuits/Config.h"
#include "../../include/circuits/GarbledGate.h"
#include "../../include/circuits/TedKrovetzAesNiWrapperC.h"
#include "../../include/circuits/GarbledBooleanCircuitFixedKey.h"

using namespace std;

GarbledBooleanCircuitFixedKey::GarbledBooleanCircuitFixedKey(void)
{
}

void GarbledBooleanCircuitFixedKey::createCircuit(const char* fileName, bool isFreeXor, bool isNonXorOutputsRequired){
	
	//Set the fixed key.
	fixedKey = _mm_set_epi8(36, -100,50, -22, 92, -26, 49, 9,-82 , -86, -51, -96, 98, -20, 29,  -13);


	//create the round keys for the fixed key.
	AES_set_encrypt_key((const unsigned char *)&fixedKey, 128, &aesFixedKey);

	GarbledBooleanCircuit::createCircuit(fileName, isFreeXor, isNonXorOutputsRequired);


}




int GarbledBooleanCircuitFixedKey::getGarbledTableSize()
{
	
	if (isNonXorOutputsRequired == true) {
		return sizeof(block) * ((numberOfGates - numOfXorGates - numOfNotGates) * getNumOfRows() + 2 * numberOfOutputs);
	}
	else {
		return sizeof(block) * (numberOfGates - numOfXorGates - numOfNotGates) * getNumOfRows();
	}


}

void  GarbledBooleanCircuitFixedKey::compute(block * singleWiresInputKeys, block * Output)
{
	int nonXorIndex= 0;
	for(int i=0; i<numberOfInputs;i++){

		//get the input keys into the computed wires array
		computedWires[inputIndices[i]] =  singleWiresInputKeys[i];
	}

	int jumpInGarblesTable = getNumOfRows();//the jump in the garbled table we need to make. 3 for row reduction, as the row reduction has only 3 values in each garbled table
	//and 4 for a regular circuit that holds garbled tables with all 4 values	

	for(int i=0; i<numberOfGates; i++){

		if ((garbledGates[i].truthTable == XOR_GATE ||  garbledGates[i].truthTable == XOR_NOT_GATE) && isFreeXor==true){
			//create the output key by xoring the computed keys if the first input wire and the second input wire
			computedWires[garbledGates[i].output] = _mm_xor_si128(computedWires[garbledGates[i].input0], computedWires[garbledGates[i].input1]);
			continue;

		}
		
		else{

			block encryptedKey;
			//get the keys from the already calculated wires
			block A = computedWires[garbledGates[i].input0];
			block B = computedWires[garbledGates[i].input1];

			//Shift left to double A for security (actually the 2 64 bit are shifted and not the whole 128 bit block
			block twoA = _mm_slli_epi64(A,1);
			//Shift right instead of shifting left twice.This is secure since the alignment is broken
			block fourB = _mm_srli_epi64(B,1);

			//Get the signal bits of A and B which are the input keys computed.
			int a = getSignalBitOf(A);
			int b = getSignalBitOf(B);

			//Calc the tweak
			block tweak =  _mm_set_epi32(0,0,0,i);

			//Deduce the key to encrypt
			block key = _mm_xor_si128(_mm_xor_si128(twoA, fourB), tweak);
			//encryptedKey = key;

			int rowIndex;//The row in the current garbled table for the specific gate.
			
			if(jumpInGarblesTable == 3){//row reduction
				rowIndex = 2*a + b - 1;//the row index in the garbled table of row reduction is should be minus one of a regular circuit since we only have 3 rows.
				
			}
			else{
				rowIndex = 2*a + b;
			}

			//ancrypt 2A+4B+T.
			AES_encryptC(&key, &encryptedKey, &aesFixedKey);

			//For row reduction and the first row compute the calculated row.
			if(jumpInGarblesTable == 3 && rowIndex==-1){
				//the output of the gate is computaed rather than calclulated using the garbled table
				computedWires[garbledGates[i].output] = _mm_xor_si128(encryptedKey, key);
			}
			else{//get the computedWire key using Xor'ss with the related row in the garbled table.
				
				//calc the output
				computedWires[garbledGates[i].output] = _mm_xor_si128(_mm_xor_si128(encryptedKey, key), garbledTables[jumpInGarblesTable* nonXorIndex + rowIndex]);
			}
			//increment the nonXor gates number only for the non-xor (not XOR or XOR_NOT) gates. For circuits
			//That do not use FreeXor optimization it will be incremented for every gate
			nonXorIndex++;
		}
		
	}
	

	if (isNonXorOutputsRequired){//check if the user requires that the output keys will not have a fixed delta xor between pair of keys of a wire.

		//call the function that returns the Output where xoring with the other wire key will not have fixed delta for all the outputs
		computeOutputWiresToNoFixedDelta(nonXorIndex, Output);
	}

	else{
		//copy the output wire keys which are the result the user is interested in.
		for (int i = 0; i < numberOfOutputs; i++) {
			Output[i] = computedWires[outputIndices[i]];

		}
	}


}


void GarbledBooleanCircuitFixedKey::computeOutputWiresToNoFixedDelta(int nonXorIndex, block * Output){
	
	for (int i = 0; i < numberOfOutputs; i++){
		
		block twoA = _mm_slli_epi64(computedWires[outputIndices[i]], 1);//make one shift
		block tweak = _mm_set_epi32(0, 0, 0, numberOfGates - numOfXorGates + i);//contine the tweak from the point we have stoped to make sure we do
																				//not use the same tweak twice
		//create the key "2A XOR Tweak"
		block key = _mm_xor_si128(twoA, tweak);
		block encryptedKey;
		//encrypt the key to retrieve from the garbled table the computed key
		AES_encryptC(&key, &encryptedKey, &aesFixedKey);


		int jumpInGarblesTable = getNumOfRows();


		//get the computedWires using the garbled table that contain "enc(key) XOR key Xor output"
		if (getSignalBitOf(computedWires[outputIndices[i]]) == 0){//in case the 0-wire has 0 signal bit
			computedWires[lastWireIndex + 1 + i] = _mm_xor_si128(encryptedKey, _mm_xor_si128(key, garbledTables[jumpInGarblesTable* nonXorIndex + i * 2]));
		}
		else{//in case the 0-wire has 1 signal bit
			computedWires[lastWireIndex + 1 + i] = _mm_xor_si128(encryptedKey, _mm_xor_si128(key, garbledTables[jumpInGarblesTable* nonXorIndex + i * 2 + 1]));
		}

		//finally 
		Output[i] = computedWires[lastWireIndex + 1 + i];

	}

}

void GarbledBooleanCircuitFixedKey::verifyOutputWiresToNoFixedDelta(block *bothOutputsKeys){

	//The result of chunk encrypting indexArray.
	block* encryptedChunkKeys = (block *)_aligned_malloc(sizeof(block)* numberOfOutputs, 16);

	//An array that holds the number numberOfGates - numOfXorGates to the number of numberOfGates - numOfXorGates + numberOfOutputs.
	//The purpuse of this array is to encrypt all the number of outputs in one chucnk. This gains piplining
	block* indexArray = (block *)_aligned_malloc(sizeof(block)* numberOfOutputs, 16);

	//Since we are using ecb mode, the plaintext must be different for every encryption
	for (int i = 0; i < numberOfOutputs; i++){
		indexArray[i] = _mm_set_epi32(0, 0, 0, numberOfGates - numOfXorGates + i);
	}

	//Encrypt the entire array to have random variablesto use for the output wires
	AES_ecb_encrypt_chunk_in_out(indexArray,
		encryptedChunkKeys,
		numberOfOutputs,
		&aesSeedKey);




	//update the output to be without fixed delta between all the wires of each key.
	for (int i = 0; i < numberOfOutputs; i++) {

		//build the garbled wires of the identity gates, note that the wire with signal bit 0 stays the same
		if (getSignalBitOf(bothOutputsKeys[2 * i]) == 0){
			*((unsigned char *)(&encryptedChunkKeys[i])) |= 1;
			bothOutputsKeys[2 * i + 1] = encryptedChunkKeys[i];
		}
		else{
			*((unsigned char *)(&encryptedChunkKeys[i])) &= 0;
			bothOutputsKeys[2 * i] = encryptedChunkKeys[i];
		}

	}

}



void GarbledBooleanCircuitFixedKey::garbleOutputWiresToNoFixedDelta(block *deltaFreeXor, int nonXorIndex, block *emptyBothOutputKeys){

	//The result of chunk encrypting indexArray.
	block* encryptedChunkKeys = (block *)_aligned_malloc(sizeof(block)* numberOfOutputs, 16);

	//An array that holds the number numberOfGates - numOfXorGates to the number of numberOfGates - numOfXorGates + numberOfOutputs.
	//The purpuse of this array is to encrypt all the number of outputs in one chucnk. This gains piplining
	block* indexArray = (block *)_aligned_malloc(sizeof(block)* numberOfOutputs, 16);

	//Since we are using ecb mode, the plaintext must be different for every encryption
	for (int i = 0; i < numberOfOutputs; i++){
		indexArray[i] = _mm_set_epi32(0, 0, 0, numberOfGates - numOfXorGates + i);
	}

	//Encrypt the entire array to have random variablesto use for the output wires
	AES_ecb_encrypt_chunk_in_out(indexArray,
		encryptedChunkKeys,
		numberOfOutputs,
		&aesSeedKey);

	int jumpInGarblesTable = getNumOfRows();

	//make a nother layer of identity gates to make the output wire have different delta xor between them.
	for (int i = 0; i < numberOfOutputs; i++) {

		//build the garbled wires of the identity gates
		if (getSignalBitOf(garbledWires[outputIndices[i]]) == 0){
			garbledWires[lastWireIndex + 1 + 2 * i] = garbledWires[outputIndices[i]];
			*((unsigned char *)(&encryptedChunkKeys[i])) |= 1;
			garbledWires[lastWireIndex + 1 + 2 * i + 1] = encryptedChunkKeys[i];
		}
		else{
			*((unsigned char *)(&encryptedChunkKeys[i])) &= 0;
			garbledWires[lastWireIndex + 1 + 2 * i] = encryptedChunkKeys[i];
			garbledWires[lastWireIndex + 1 + 2 * i + 1] = garbledWires[outputIndices[i]];
		}

		block TwoA[2];
		block keys[2];
		block encryptedKeys[2];


		//Shift int inputs of the identity gates (the output of the freeXor circuit) by one
		TwoA[0] = _mm_slli_epi64(garbledWires[outputIndices[i]], 1);
		TwoA[1] = _mm_slli_epi64(_mm_xor_si128(garbledWires[outputIndices[i]], *deltaFreeXor), 1);

		//Calc the keys "2A XOR tweak"
		keys[0] = _mm_xor_si128(TwoA[0], indexArray[i]);
		keys[1] = _mm_xor_si128(TwoA[1], indexArray[i]);

		//encrypt the keys to use in the garbled tables
		AES_encryptC(&keys[0], &encryptedKeys[0], &aesFixedKey);
		AES_encryptC(&keys[1], &encryptedKeys[1], &aesFixedKey);

		//create the garbled table with 2 entries for each identity gate
		if (getSignalBitOf(garbledWires[outputIndices[i]]) == 0){
			garbledTables[jumpInGarblesTable * nonXorIndex + 2 * i] = _mm_xor_si128(encryptedKeys[0], _mm_xor_si128(keys[0], garbledWires[lastWireIndex + 1 + 2 * i]));
			garbledTables[jumpInGarblesTable * nonXorIndex + 2 * i + 1] = _mm_xor_si128(encryptedKeys[1], _mm_xor_si128(keys[1], garbledWires[lastWireIndex + 1 + 2 * i + 1]));
		}
		else{
			garbledTables[jumpInGarblesTable * nonXorIndex + 2 * i + 1] = _mm_xor_si128(encryptedKeys[0], _mm_xor_si128(keys[0], garbledWires[lastWireIndex + 1 + 2 * i]));
			garbledTables[jumpInGarblesTable * nonXorIndex + 2 * i] = _mm_xor_si128(encryptedKeys[1], _mm_xor_si128(keys[1], garbledWires[lastWireIndex + 1 + 2 * i + 1]));

		}

		//copy the new output keys to get back to the caller of the function.
		emptyBothOutputKeys[2 * i] = garbledWires[lastWireIndex + 1 + 2 * i];
		emptyBothOutputKeys[2 * i + 1] = garbledWires[lastWireIndex + 1 + 2 * i + 1];

	}

}
