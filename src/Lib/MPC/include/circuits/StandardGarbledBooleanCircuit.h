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

#pragma once
#include "GarbledBooleanCircuitFixedKey.h"
#include <vector>

/**
*The StandardGarbledBooleanCircuit is a standard garbled circuit that does not use optimizations such as FreeXor and row reduction, only fixed key.
* The 0-wire key and the 1-wire key are not related in any way and are random.
*
* Note that there is some similar code that looks duplicated, but due to performance reasons the duplication is not refactored into
* functions. Calling functions for numerous times decreses the performance.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
*
*/
class StandardGarbledBooleanCircuit :
	public GarbledBooleanCircuitFixedKey
{
public:
	StandardGarbledBooleanCircuit(const char* fileName);
	StandardGarbledBooleanCircuit();
	~StandardGarbledBooleanCircuit();


	
private:
	
	block* indexArray;

public:

	/**
	* This function behaves exactly as the verify method except the last phase.
	* The verify function verifies that the translation table matches the resulted output garbled values, while this function does not, rather,
	* it returns the resulted output garbled values.
	*
	* bothWiresInputKeys : both keys for each input wire. This array must be filled with both input keys
	* emptyBothWireOutputKeys :This array will be filled with both output keys during the process of the function. It must be empty.
	*
	* returns : true if the garbled table of this circuit is complied with the given input keys, false otherwise.
	*/
	bool internalVerify(block *bothInputKeys, block *emptyBothWireOutputKeys) override;

	int getGarbledTableSize() override;

protected:


	/*
	* Creates the memory needed for this class in addition to the memory that is allocated by the base class.
	*/
	void createCircuitMemory(const char* fileName, bool isNonXorOutputsRequired = false) override;
private:

	/*
	* This method generates both keys for each wire and creates the garbled table according to those values.
	* The keys for each wire are not saved. The input keys and the output keys that were created are returned to the
	* user. The user usually saves these value for later use. The user also gets the generated translation table, which is
	* the signal bits of the output wires.
	*
	* emptyBothInputKeys : An empty block array that will be filled with both input keys generated in garble.
	* emptyBothOutputKeys : An empty block array that will be filled with both output keys generated in garble.
	* emptyTranslationTable : An empty char array that will be filled with 0/1 signal bits that we chosen in random in this function.
	*/
	void garble(block *emptyBothInputKeys, block *emptyBothOutputKeys, std::vector<unsigned char> & emptyTranslationTable, block seed) override;

	/*
	* This function inits the keys for all the wires in the circuit and initializes the seed aes encryptions. It also choses
	* the input keys at random using the aes with seed. It also creates memory for the translation table.
	*/
	void initAesEncryptionsAndAllKeys(block* emptyBothInputKeys);

	

};