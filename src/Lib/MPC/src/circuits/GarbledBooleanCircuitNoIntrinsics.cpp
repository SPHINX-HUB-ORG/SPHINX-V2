//
// Created by moriya on 19/10/17.
//


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

#include "../../include/circuits/GarbledBooleanCircuitNoIntrinsics.h"

GarbledBooleanCircuitNoIntrinsics::GarbledBooleanCircuitNoIntrinsics(const char* fileName, bool isNonXorOutputsRequired){
    //create the needed memory for this circuit
    createCircuitMemory(fileName, isNonXorOutputsRequired);
}

void GarbledBooleanCircuitNoIntrinsics::createCircuitMemory(const char* fileName, bool isNonXorOutputsRequired){

    createCircuit(fileName, true, isNonXorOutputsRequired);
    numOfRows = 2;

    if (isNonXorOutputsRequired == true){
        garbledTables = new byte[KEY_SIZE * ((numberOfGates - numOfXorGates - numOfNotGates) * 2 + 2 * numberOfOutputs)];
        if (garbledTables == nullptr) {
            cout << "garbledTables could not be allocated";
            exit(0);
        }
        memset(garbledTables, 0, (KEY_SIZE * ((numberOfGates - numOfXorGates - numOfNotGates) * 2 + 2 * numberOfOutputs)));

        garbledWires = new byte[KEY_SIZE * ((lastWireIndex + 1) + 1 + 2 * numberOfOutputs)];

        if (garbledWires == nullptr) {
            cout << "garbledWires could not be allocated";
            exit(0);
        }
        memset(garbledWires, 0, KEY_SIZE * ((lastWireIndex + 1) + 1 + 2 * numberOfOutputs));
        garbledWires = garbledWires+ KEY_SIZE;
    }
    else{
        garbledTables = new byte[KEY_SIZE * (numberOfGates - numOfXorGates - numOfNotGates) * 2];

        if (garbledTables == nullptr) {
            cout << "garbled tables could not be allocated";
            exit(0);
        }
        memset(garbledTables, 0, (KEY_SIZE * (numberOfGates - numOfXorGates - numOfNotGates) * 2));

        garbledWires = new byte[KEY_SIZE * ((lastWireIndex + 1) + 1)];

        if (garbledWires == nullptr) {
            cout << "garbledWires could not be allocated";
            exit(0);
        }
        memset(garbledWires, 0, KEY_SIZE * ((lastWireIndex + 1) + 1));
        garbledWires = garbledWires+ KEY_SIZE;
    }
    encryptedChunkKeys.resize(KEY_SIZE * numberOfInputs);

//    if (encryptedChunkKeys.size() == 0) {
//        cout << "encryptedChunkKeys could not be allocated";
//        exit(0);
//    }

    memset(encryptedChunkKeys.data(), 0, KEY_SIZE * numberOfInputs);

    indexArray.resize(KEY_SIZE * numberOfInputs);

    //we put the indices ahead of time to encrypt the whole chunk in one call.
    for (int i = 0; i < numberOfInputs; i++){

        ((long*)(&indexArray[i*KEY_SIZE]))[1] = i;

    }

}

GarbledBooleanCircuitNoIntrinsics::~GarbledBooleanCircuitNoIntrinsics(void)
{
    if (garbledGates != nullptr) {
        delete[] garbledGates;
    }

    if (garbledTables != nullptr) {
        delete  [] garbledTables;
        garbledTables = nullptr;
    }

    if (computedWires != nullptr){
        computedWires = computedWires - KEY_SIZE;
        delete [] computedWires;
        computedWires = nullptr;
    }

    if (garbledWires != nullptr){
        garbledWires = garbledWires - KEY_SIZE;
        delete [] garbledWires;
    }


}

void GarbledBooleanCircuitNoIntrinsics::createCircuit(const char* fileName, bool isFreeXor, bool isNonXorOutputsRequired){

    //Set the fixed key.
    byte fixedKey [] = {(byte)36, (byte)-100, (byte)50, (byte)-22, (byte)92, (byte)-26, (byte)49, (byte)9, (byte)-82 , (byte)-86, (byte)-51, (byte)-96, (byte)98, (byte)-20, 29,  (byte)-13};
    aesFixedKey = SecretKey(fixedKey, KEY_SIZE, "AES");

    //create the round keys for the fixed key.
    aes.setKey(aesFixedKey);

    //AES_set_encrypt_key((const unsigned char *)&fixedKey, 128, &aesFixedKey);

    this->isFreeXor = isFreeXor;
    this->isNonXorOutputsRequired = isNonXorOutputsRequired;

    //init all the variable to either nullptr or 0 for integers.
    lastWireIndex = 0;
    numberOfGates = 0;
    numOfXorGates = 0;
    numOfNotGates = 0;
    numberOfParties = 0;
    numberOfInputs = 0;
    numberOfOutputs = 0;

    garbledTables = nullptr;
    garbledGates = nullptr;
    garbledWires = nullptr;
    computedWires = nullptr;

    //read the file and fill the gates, number of parties, input indices, output indices and so on.
    readCircuitFromFile(fileName);

    int sizeOfWires;
    if (isNonXorOutputsRequired) {
        sizeOfWires = (lastWireIndex + 1) + 1 + numberOfOutputs;
        computedWires = new byte[KEY_SIZE * sizeOfWires];//the wires that have been already computed. It is assumed that when a gate is handled the
    } else {
        sizeOfWires = (lastWireIndex + 1) + 1;
        computedWires = new byte[KEY_SIZE * sizeOfWires];//the wires that have been already computed. It is assumed that when a gate is handled the
    }
    if (computedWires== nullptr) {
        cout<<"computedWires could not be allocated";
        exit(0);
    }
    memset(computedWires, 0, KEY_SIZE * sizeOfWires);
    computedWires = computedWires + KEY_SIZE;

    //allocate memory for the translation table
    translationTable.reserve(numberOfOutputs);
}

tuple<byte*, byte*, vector<unsigned char> > GarbledBooleanCircuitNoIntrinsics::garble(byte *seed)
{
    byte *allInputWireValues = new byte[KEY_SIZE * 2 * numberOfInputs];
    byte *allOutputWireValues = new byte[KEY_SIZE * 2 * numberOfOutputs];
    vector<unsigned char> translationTable;

    if (seed == nullptr) {

        byte* seedLocl = new byte[KEY_SIZE];

        if (!RAND_bytes(seedLocl, KEY_SIZE))
            throw runtime_error("key generation failed");
        seed = seedLocl;
    }


    garble(allInputWireValues, allOutputWireValues, translationTable, seed);

    return make_tuple(allInputWireValues, allOutputWireValues, translationTable);
}

void GarbledBooleanCircuitNoIntrinsics::garble(byte *emptyBothInputKeys, byte *emptyBothOutputKeys,
        vector<unsigned char> & emptyTranslationTable, byte* seed){

    this->seed = seed;

    //init encryption key of the seed and calc all the wire keys
    initAesEncryptionsAndAllKeys(emptyBothInputKeys);
    delete [] seed;

    aes.setKey(aesFixedKey);
    //declare some variables that will be used for garbling
    int nonXorIndex = 0;

    //two different tweaks one for input0 and the other for input1
    byte* tweak = new byte[KEY_SIZE];
    byte* tweak2 = new byte[KEY_SIZE];

    //create input arrays in order to get the inputs immedietly and not invoke unneeded xor's
    byte* inputs = new byte[KEY_SIZE * 4];
    byte* tempInputs = new byte[KEY_SIZE * 4];

    //two temporary values that will eventually be XORed together to calculate the output0 zero wire
    byte* tempK0 = new byte[KEY_SIZE];
    byte* tempK1 = new byte[KEY_SIZE];

    //go over all the gates in the circuit
    for (int i = 0; i < numberOfGates; i++){

        if (garbledGates[i].truthTable == XOR_GATE){
            //create the 0-key by xoring the two 0-keys of the input
            for (int j=0; j<KEY_SIZE; j++){
                garbledWires[garbledGates[i].output*KEY_SIZE + j] = garbledWires[garbledGates[i].input0*KEY_SIZE + j] ^ garbledWires[garbledGates[i].input1*KEY_SIZE+ j];
            }

            continue;
        }
        else if (garbledGates[i].truthTable == XOR_NOT_GATE){
            //create the 0-key by xoring the two 0-keys of the input and xoring that with the delta.
            for (int j=0; j<KEY_SIZE; j++) {
                garbledWires[garbledGates[i].output * KEY_SIZE + j] = garbledWires[garbledGates[i].input0 * KEY_SIZE + j]
                                                                      ^ garbledWires[garbledGates[i].input1 * KEY_SIZE + j]
                                                                      ^ deltaFreeXor[j];
            }
        }

        else{
            //two different tweaks
            ((long*)(tweak))[0] = 0;
            ((long*)(tweak2))[0] = 0;
            ((long*)tweak)[1] = i;
            ((long*)tweak2)[1] = i+numberOfGates;

            memcpy(inputs, garbledWires + garbledGates[i].input0*KEY_SIZE, KEY_SIZE);
            memcpy(inputs + 2*KEY_SIZE, garbledWires + garbledGates[i].input1*KEY_SIZE, KEY_SIZE);


            for (int j=0; j<KEY_SIZE; j++){
                inputs[KEY_SIZE + j] = inputs[j] ^ deltaFreeXor[j];
                inputs[3*KEY_SIZE + j] = inputs[2*KEY_SIZE + j] ^ deltaFreeXor[j];
            }


            //signal bits of wire 0 of input0 and wire 0 of input1
            int wire0signalBitsArray = getSignalBitOf(inputs);
            int wire1signalBitsArray = getSignalBitOf(inputs + 2*KEY_SIZE);
            //generate the keys array
            vector<byte> keys(4*KEY_SIZE);

            //generate K = H(input) = 2Input XOR tweak
            //Multiply the input by 2
            for (int j=0; j<8; j++){
                ((long*)tempInputs)[j] = ((long*)inputs)[j]<<1;
            }


            for (int j=0; j<KEY_SIZE; j++){
                keys[j] = tempInputs[j] ^ tweak[j];
                keys[KEY_SIZE + j] = tempInputs[KEY_SIZE + j] ^ tweak[j];
                keys[2 * KEY_SIZE + j] = tempInputs[2 * KEY_SIZE + j] ^ tweak2[j];
                keys[3 * KEY_SIZE + j] = tempInputs[3 * KEY_SIZE + j] ^ tweak2[j];
            }


            //generate the keys array as well as the encryptedKeys array
            vector<byte> encryptedKeys(4 * KEY_SIZE);
            //Encrypt the 4 keys in one chunk to gain pipelining and puts the answer in encryptedKeys block array
            //AES_ecb_encrypt_blks_4_in_out((block*)keys, (block*)encryptedKeys, &aesFixedKey);
            aes.optimizedCompute(keys, encryptedKeys);


            if (wire1signalBitsArray == 0){//signal bit of wire 0 of input1 is zero
                for (int j=0; j<KEY_SIZE; j++){
                    garbledTables[2 * nonXorIndex * KEY_SIZE + j] = encryptedKeys[j] ^ keys[j] ^ encryptedKeys[KEY_SIZE + j] ^ keys[KEY_SIZE + j];
                }

            }
            else{//signal bit of wire 0 of input1 is one
                for (int j=0; j<KEY_SIZE; j++) {
                    garbledTables[2 * nonXorIndex * KEY_SIZE + j] = encryptedKeys[j] ^ keys[j] ^ encryptedKeys[KEY_SIZE + j] ^ keys[KEY_SIZE + j] ^ deltaFreeXor[j];
                }
            }

            if (wire0signalBitsArray == 0){//signal bit of wire 0 of input0 is zero
                for (int j=0; j<KEY_SIZE; j++) {
                    tempK0[j] = encryptedKeys[j] ^ keys[j];
                }
            }
            else{//signal bit of wire 0 of input0 is one
                for (int j=0; j<KEY_SIZE; j++) {
                    tempK0[j] = encryptedKeys[j] ^ keys[j] ^ garbledTables[2 * nonXorIndex*KEY_SIZE + j];
                }
            }


            for (int j=0; j<KEY_SIZE; j++) {
                garbledTables[(2 * nonXorIndex + 1) * KEY_SIZE + j] = encryptedKeys[2*KEY_SIZE + j] ^ keys[2*KEY_SIZE  + j] ^
                                      encryptedKeys[3 * KEY_SIZE + j] ^ keys[3 * KEY_SIZE + j] ^ inputs[j];
            }
            if (wire1signalBitsArray == 0){
                for (int j=0; j<KEY_SIZE; j++) {
                    tempK1[j] = encryptedKeys[2*KEY_SIZE + j] ^ keys[2*KEY_SIZE + j];
                }
            }
            else {
                for (int j=0; j<KEY_SIZE; j++) {
                    tempK1[j] = encryptedKeys[2 * KEY_SIZE + j] ^ keys[2* KEY_SIZE + j] ^ garbledTables[(2 * nonXorIndex + 1) * KEY_SIZE + j] ^ inputs[j];
                }
            }
            for (int j=0; j<KEY_SIZE; j++)
                garbledWires[garbledGates[i].output * KEY_SIZE + j] = tempK0[j] ^ tempK1[j];
            nonXorIndex++;
        }

    }

    delete [] tweak;
    delete [] tweak2;
    delete []  inputs;
    delete []  tempInputs;
    delete []  tempK0;
    delete []  tempK1;

    if (isNonXorOutputsRequired){
        //check if the user requires that the output keys will not have a fixed delta xor between pair of keys of a wire.
        //call the function that returns the emptyBothOutputKeys without deltaFreeXor between each pair of wires
        // garbleOutputWiresToNoFixedDelta(deltaFreeXor, nonXorIndex, emptyBothOutputKeys);
    }
    else{
        //copy the output keys to get back to the caller of the function as well as filling the translation table.
        //The input keys were already filled in the initialization of the function.
        for (int i = 0; i < numberOfOutputs; i++){
            memcpy(emptyBothOutputKeys + 2 * i * KEY_SIZE, garbledWires + outputIndices[i]*KEY_SIZE, KEY_SIZE);
            for (int j=0; j<KEY_SIZE; j++) {
                emptyBothOutputKeys[(2 * i + 1)*KEY_SIZE + j] = emptyBothOutputKeys[2 * i* KEY_SIZE + j] ^ deltaFreeXor[j];
            }
        }
    }

    translationTable.clear();
    //update the translation table
    for (int i = 0; i < numberOfOutputs; i++){
        translationTable.push_back(getSignalBitOf(emptyBothOutputKeys + 2 * i * KEY_SIZE));
        emptyTranslationTable.push_back(getSignalBitOf(emptyBothOutputKeys + 2 * i * KEY_SIZE));
    }

}

int GarbledBooleanCircuitNoIntrinsics::binaryTodecimal(int n){

    int output = 0;
    int pow = 1;

    //turns the string of the truth table that was taken as a decimal number into a number between 0 and 15 which represents the truth table
    //0 means the truth table of 0000 and 8 means 1000 and so on. The functions returns the decimal representation of the thruth table.
    for(int i=0; n > 0; i++) {

        if(n % 10 == 1) {

            output += pow;
        }
        n /= 10;

        pow = pow*2;
    }
    return output;
}


vector<int> GarbledBooleanCircuitNoIntrinsics::getInputWireIndices(int partyNumber) {

    //get the starting position in the inputs indices vector
    int startingIndex = 0;
    for (int i = 1; i<partyNumber; i++)
        startingIndex += getNumberOfInputs(i);

    //get the number on inputs for this party
    int numberOfInputsForThisParty = getNumberOfInputs(partyNumber);

    //get iterators to the desired location
    vector<int>::iterator first = inputIndices.begin() + startingIndex;
    vector<int>::iterator last = inputIndices.begin() + startingIndex + numberOfInputsForThisParty;

    //copy just the needed sub vector
    vector<int> copyOfInputIndices(first, last);


    return copyOfInputIndices;
}


int GarbledBooleanCircuitNoIntrinsics::getRowTruthTableResult(int i, int j, unsigned char truthTable){

    //get the row of the table starting from 0
    int rowNumber = 2*i + j;

    //return the result of row i,j.
    return truthTable & integerPow(3-rowNumber);
}


int GarbledBooleanCircuitNoIntrinsics::integerPow(int p) {

    switch( p ) {
        case(0):
            return 1;
        case(1):
            return 2;
        case(2):
            return 4;
        default:
            return 8;

    }

}


void GarbledBooleanCircuitNoIntrinsics::translate(byte *outputKeys, unsigned char* answer){


    for(int i=0; i<numberOfOutputs;i++){

        //The answer of i'th position is the signal bit of the XOr between the related translation table location and the related outputKey array position
        answer[i] = getSignalBitOf(outputKeys + i*KEY_SIZE) ^ translationTable[i];
        //cout<<(int)answer[i];

    }

    //cout<<"\n";

}

void GarbledBooleanCircuitNoIntrinsics::initAesEncryptionsAndAllKeys(byte* emptyBothInputKeys){

    //reserve memory for the translation table
    translationTable.reserve(numberOfOutputs);

    SecretKey aesSeedKey(seed, KEY_SIZE, "AES");

    ///create the aes with the seed as the key. This will be used for encrypting the input keys
    aes.setKey(aesSeedKey);

    //create the delta for the free Xor. Encrypt zero twice. We get a good enough random delta by encrypting twice
    deltaFreeXor.resize(KEY_SIZE);
    memset(deltaFreeXor.data(), 0, KEY_SIZE);

    aes.computeBlock(deltaFreeXor, 0, deltaFreeXor, 0);
    aes.computeBlock(deltaFreeXor, 0, deltaFreeXor, 0);

    //set the last bit of the first char to 1
    deltaFreeXor[0] |= 1;

    aes.optimizedCompute(indexArray, encryptedChunkKeys);

    //create the input keys. We encrypt using the aes with the seed as index and encrypt the index of the input wire,
    for (int i = 0; i<numberOfInputs; i++){
        memcpy(garbledWires + inputIndices[i]*KEY_SIZE, encryptedChunkKeys.data() + i*KEY_SIZE, KEY_SIZE);
        memcpy(emptyBothInputKeys + 2 * i *KEY_SIZE, encryptedChunkKeys.data() + i*KEY_SIZE, KEY_SIZE);
        for (int j=0; j<KEY_SIZE; j++) {
            emptyBothInputKeys[(2 * i + 1)*KEY_SIZE + j] = encryptedChunkKeys[i*KEY_SIZE + j] ^ deltaFreeXor[j];
        }
    }

    //set the fixed -1 wire to delta, this way we turn a not gate into a xor gate.
    memcpy(garbledWires - KEY_SIZE, deltaFreeXor.data(), KEY_SIZE);

}

void GarbledBooleanCircuitNoIntrinsics::setTranslationTable(vector<unsigned char> & translationTable) {

    this->translationTable = translationTable;
}


void GarbledBooleanCircuitNoIntrinsics::setGarbledTables(byte* garbledTables) {

    if (this->garbledTables != nullptr && this->garbledTables != garbledTables)
        delete [] this->garbledTables;

    this->garbledTables = garbledTables;
}


vector<int> GarbledBooleanCircuitNoIntrinsics::getNumOfInputsForEachParty(){
    return numOfInputsForEachParty;
}


bool GarbledBooleanCircuitNoIntrinsics::verify(byte *bothInputKeys){

    byte *emptyBothWireOutputKeys = new byte[KEY_SIZE * numberOfOutputs*2];

    //Call the internal internalVerify function that verifies all the gates but does not check the translation table.
    bool isVerified = internalVerify(bothInputKeys,emptyBothWireOutputKeys);

    //Check that the results of the internal verify comply with the translation table.
    if(isVerified==true){
        isVerified = verifyTranslationTable(emptyBothWireOutputKeys);

    }

    //Free the localy allocated memory
    delete [] emptyBothWireOutputKeys;
    return isVerified;

}


bool  GarbledBooleanCircuitNoIntrinsics::equalBlocks(byte* a, byte* b)
{
    //A function that checks if two blocks are equal by casting to double size long array and check each half of a block
    for (int i=0; i<KEY_SIZE; i++) {
        if (a[i] != b[i])
            return 0;
    }

    return 1;

}


bool GarbledBooleanCircuitNoIntrinsics::verifyTranslationTable(byte * bothWireOutputKeys)
{
    bool isVerified = true;
    //go over the output key results and make sure that they comply with the translation table
    for (int i=0; i<numberOfOutputs;i++) {
        byte* zeroBlock = bothWireOutputKeys + 2*i*KEY_SIZE;
        byte* oneBlock = bothWireOutputKeys + (2*i+1)*KEY_SIZE;

        unsigned char translatedZeroValue = translationTable[i] ^ getSignalBitOf(zeroBlock);
        unsigned char translatedOneValue = translationTable[i] ^ getSignalBitOf(oneBlock);

        //Verify that the translatedZeroValue is actually 0 and that translatedOneValue is indeed 1
        if (translatedZeroValue != 0 || translatedOneValue != 1) {
            isVerified = false;
            break;
        }
    }	return isVerified;
}

void GarbledBooleanCircuitNoIntrinsics::readCircuitFromFile(const char* fileName)
{

    int inFan, outFan, input0, input1, output, type, typeBin, numOfinputsForParty;
    int currentPartyNumber;
    ifstream myfile;


    myfile.open(fileName);


    vector<vector<int>> partiesInputs;

    if (myfile.is_open())
    {

        myfile >> numberOfGates;//get the gates
        myfile >> numberOfParties;

        numOfInputsForEachParty.resize(numberOfParties);
        partiesInputs.resize(numberOfParties);

        for(int j=0 ; j<numberOfParties; j++){
            myfile >> currentPartyNumber;

            myfile >> numOfinputsForParty;
            numOfInputsForEachParty[currentPartyNumber - 1] = numOfinputsForParty;

            partiesInputs[currentPartyNumber-1].resize(numOfInputsForEachParty[currentPartyNumber-1]);

            for(int i = 0; i<numOfInputsForEachParty[currentPartyNumber-1]; i++){
                myfile >>partiesInputs[currentPartyNumber-1][i];
            }
        }


        //get the number of outputs
        myfile >> numberOfOutputs;

        //allocate memory for the output number of wires and get each wire number into the array of outputs indices
        outputIndices.reserve(numberOfOutputs);

        int currentOutput;
        for(int i=0;i < numberOfOutputs;i++){
            myfile >> currentOutput;
            outputIndices.push_back(currentOutput);
        }


        //calculate the total number of inputs
        for(int i=0; i<numberOfParties;i++){
            numberOfInputs+=numOfInputsForEachParty[i];
        }

        //allocate memory for the gates, We add one gate for the all-one gate whose output is always 1 and thus have a wire who is always 1 without the 
        //involvement of the user. This will be useful to turn a NOT gate into a XORGate
        garbledGates = new GarbledGate[numberOfGates];


        //write the inputs to the inputs array of the garbled circuit
        inputIndices.reserve(numberOfInputs);

        int index = 0;
        for(int i=0;i <numberOfParties; i++){
            for(int j=0; j< numOfInputsForEachParty[i]; j++){

                inputIndices.push_back(partiesInputs[i][j]);
                index++;
            }
        }

        //create a gate whose output is always 1. This gate number will be -1 and we will move the poiter one place 
        //go over the file and create gate by gate
        for(int i=0; i<numberOfGates;i++)
        {

            //get  each row that represents a gate
            myfile >> inFan;
            myfile >> outFan;
            myfile >> input0;

            if (inFan != 1)//a 2 input 1 output gate - regualr gate, else we have a not gate
            {
                myfile >> input1;
            }


            myfile >> output;
            myfile >> typeBin;


            if(lastWireIndex < output){
                lastWireIndex = output;
            }

            if (inFan == 1)//NOT gate
            {
                input1 = -1;
                type = XOR_GATE;

                garbledGates[i].truthTable = type;
            }
            else{
                type = binaryTodecimal(typeBin);

                garbledGates[i].truthTable = type;
            }


            //Just garbled require that the first input number would be less than the second one. If this is the case, we need to switch between bit2 and bit3 in order
            //to switch the labels and still get the required truth table


            //transform the binary string to a decimal number between 0-15. That is if the truth table string was "0110", typeBin gets the value 110 in decimal since it 
            //is an int. This function transforms it to the decimal number 6 (XOR_GATE).


            //we build the truth table in a way that we only need to get a specific row instead of doing a lot of shifts
            garbledGates[i].truthTableBits[0] = getRowTruthTableResultShifts(0, type);
            garbledGates[i].truthTableBits[1] = getRowTruthTableResultShifts(1, type);
            garbledGates[i].truthTableBits[2] = getRowTruthTableResultShifts(2, type);
            garbledGates[i].truthTableBits[3] = getRowTruthTableResultShifts(3, type);

            garbledGates[i].input0 = input0;
            garbledGates[i].input1 = input1;
            garbledGates[i].output = output;

            if (type == XOR_GATE || type == XOR_NOT_GATE){
                if (garbledGates[i].input1 == -1){
                    numOfNotGates++;
                }
                else{
                    numOfXorGates++;
                }
            }

        }

    }
    myfile.close();
}

int GarbledBooleanCircuitNoIntrinsics::getGarbledTableSize()
{

    if (isNonXorOutputsRequired == true) {
        return KEY_SIZE * ((numberOfGates - numOfXorGates - numOfNotGates) * getNumOfRows() + 2 * numberOfOutputs);
    }
    else {
        return KEY_SIZE * (numberOfGates - numOfXorGates - numOfNotGates) * getNumOfRows();
    }

}

void  GarbledBooleanCircuitNoIntrinsics::compute(byte * singleWiresInputKeys, byte * Output)
{
    int nonXorIndex = 0;
    for (int i = 0; i < numberOfInputs; i++){

        //get the input keys into the computed wires array
        memcpy(computedWires + inputIndices[i]*KEY_SIZE, singleWiresInputKeys + i*KEY_SIZE, KEY_SIZE);
    }

    byte* keys = new byte[2*KEY_SIZE];
    byte* tweak = new byte[KEY_SIZE];
    byte* tweak2 = new byte[KEY_SIZE];
    byte* tempK0 = new byte[KEY_SIZE];
    byte* tempK1 = new byte[KEY_SIZE];

    for (int i = 0; i < numberOfGates; i++){

        if (garbledGates[i].truthTable == XOR_GATE || garbledGates[i].truthTable == XOR_NOT_GATE){
            //create the output key by xoring the computed keys if the first input wire and the second input wire
//            cout<<"gate "<<i<<endl;
//            cout<<"inputs wires : "<<garbledGates[i].input0<<" "<<garbledGates[i].input1<<endl;
//            cout<<"computedWires[-1]:"<<endl;
//            for (int j=0; j<KEY_SIZE; j++) {
//                cout<<(int)computedWires[garbledGates[i].input1 * KEY_SIZE + j]<<" ";
//            }
//            cout<<endl;
//            cout<<"output key:"<<endl;
            for (int j=0; j<KEY_SIZE; j++) {
                computedWires[garbledGates[i].output * KEY_SIZE + j] = computedWires[garbledGates[i].input0 * KEY_SIZE + j] ^
                                                                       computedWires[garbledGates[i].input1 * KEY_SIZE + j];
//                cout<<(int)computedWires[garbledGates[i].output * KEY_SIZE + j]<<" ";
            }
//            cout<<endl;
            continue;

        }

        else{
//            cout<<"gate "<<i<<endl;

            vector<byte> keys2(2*KEY_SIZE);
            //get the keys from the already calculated wires
            memcpy(keys, computedWires + garbledGates[i].input0*KEY_SIZE, KEY_SIZE);
            memcpy(keys + KEY_SIZE, computedWires + garbledGates[i].input1*KEY_SIZE, KEY_SIZE);

//            cout<<"input keys"<<endl;
//            for (int j=0; j<2; j++){
//                for (int k=0; k<KEY_SIZE; k++){
//                    cout<<(int)keys[j*KEY_SIZE + k]<<" ";
//                }
//                cout<<endl;
//            }
            //Get the signal bits of A and B which are the input keys computed.
            int wire0SignalBit = getSignalBitOf(keys);
            int wire1SignalBit = getSignalBitOf(keys + KEY_SIZE);

//            cout<<"wire0SignalBit = "<<wire0SignalBit<<endl;
//            cout<<"wire1SignalBit = "<<wire1SignalBit<<endl;

            //Calc the tweak
            ((long*)(tweak))[0] = 0;
            ((long*)(tweak2))[0] = 0;
            ((long*)(tweak))[1] = i;
            ((long*)(tweak2))[1] = i + numberOfGates;

            //Deduce the key to encrypt
            //Multiply the input by 2
            for (int j=0; j<4; j++){
                ((long*)keys2.data())[j] = ((long*)keys)[j]<<1;
            }

//            cout<<"input keys after shifting"<<endl;
//            for (int j=0; j<2; j++){
//                for (int k=0; k<KEY_SIZE; k++){
//                    cout<<(int)keys[j*KEY_SIZE + k]<<" ";
//                }
//                cout<<endl;
//            }

            for (int j=0; j<KEY_SIZE; j++){
                keys2[j] = keys2[j] ^ tweak[j];
                keys2[KEY_SIZE + j] = keys2[KEY_SIZE + j] ^ tweak2[j];

            }
//            cout<<"keys"<<endl;
//            for (int j=0; j<2; j++){
//                for (int k=0; k<KEY_SIZE; k++){
//                    cout<<(int)keys2[j*KEY_SIZE + k]<<" ";
//                }
//                cout<<endl;
//            }

            //generate the keys array as well as the encryptedKeys array
            vector<byte> encryptedKeys(2*KEY_SIZE);
            //Encrypt the 2 keys in one chunk to gain pipelining and puts the answer in encryptedKeys block array
//            AES_ecb_encrypt_blks_2_in_out((block*)keys2, (block*)encryptedKeys, &aesFixedKey);
            aes.optimizedCompute(keys2, encryptedKeys);

//            cout<<"garble gate "<<i<<endl;
//            cout<<"encrypted keys"<<endl;
//            for (int j=0; j<2; j++){
//                for (int k=0; k<KEY_SIZE; k++){
//                    cout<<(int)encryptedKeys[j*KEY_SIZE + k]<<" ";
//                }
//                cout<<endl;
//            }

            //for more information look at the pseudo-code of "Two Halves Make a Whole Reducing Data Transfer in Garbled Circuits using Half Gates" page 9
            if (wire0SignalBit == 0){
                for (int j=0; j<KEY_SIZE; j++) {
                    tempK0[j] = encryptedKeys[j] ^ keys2[j];
                }
            }
            else{
                for (int j=0; j<KEY_SIZE; j++) {
                    tempK0[j] = encryptedKeys[j] ^ keys2[j] ^ garbledTables[2 * nonXorIndex * KEY_SIZE + j];
                }
            }

//            cout<<"k0:"<<endl;
//            for (int k=0; k<KEY_SIZE; k++){
//                cout<<(int)tempK0[k]<<" ";
//            }
//            cout<<endl;

            if (wire1SignalBit == 0){
                for (int j=0; j<KEY_SIZE; j++) {
                    tempK1[j] = encryptedKeys[KEY_SIZE + j] ^ keys2[KEY_SIZE + j];
                }
            }
            else{
                for (int j=0; j<KEY_SIZE; j++) {
                    tempK1[j] = encryptedKeys[KEY_SIZE + j] ^  keys2[KEY_SIZE + j] ^ garbledTables[(2 * nonXorIndex + 1) * KEY_SIZE + j] ^ keys[j];
                }
            }
//            cout<<"garbled table:"<<endl;
//            for (int j=0; j<2; j++) {
//                for (int k = 0; k < KEY_SIZE; k++) {
//                    cout << (int) garbledTables[(2 * nonXorIndex + j) * KEY_SIZE + k] << " ";
//                }
//            }
//            cout<<endl;
//
//            cout<<"k1:"<<endl;
//            for (int k=0; k<KEY_SIZE; k++){
//                cout<<(int)tempK1[k]<<" ";
//            }
//            cout<<endl;

//            cout<<"output key:"<<endl;
            for (int j=0; j<KEY_SIZE; j++) {
                computedWires[garbledGates[i].output*KEY_SIZE + j] = tempK0[j] ^ tempK1[j];
//                cout<<(int)computedWires[garbledGates[i].output * KEY_SIZE + j]<<" ";
            }
//            cout<<endl;
            //increment the nonXor gates number only for the non-xor (not XOR or XOR_NOT) gates. For circuits
            //That do not use FreeXor optimization it will be incremented for every gate
            nonXorIndex++;
        }

    }

    delete [] keys;
    delete [] tweak;
    delete [] tweak2;
    delete [] tempK0;
    delete [] tempK1;

    if (isNonXorOutputsRequired){//check if the user requires that the output keys will not have a fixed delta xor between pair of keys of a wire.

        //call the function that returns the Output where xoring with the other wire key will not have fixed delta for all the outputs
//        computeOutputWiresToNoFixedDelta(nonXorIndex, Output);
    }

    else{
        //copy the output wire keys which are the result the user is interested in.
        for (int i = 0; i < numberOfOutputs; i++) {
            for (int j=0; j<KEY_SIZE; j++) {
                memcpy(Output + i*KEY_SIZE + j,  computedWires + outputIndices[i]*KEY_SIZE + j, KEY_SIZE);
            }
        }
    }
}


/*void GarbledBooleanCircuitNoIntrinsics::computeOutputWiresToNoFixedDelta(int nonXorIndex, byte * Output){

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
        if (getSignalBitOf(computedWires + outputIndices[i]*KEY_SIZE) == 0){//in case the 0-wire has 0 signal bit
            computedWires[lastWireIndex + 1 + i] = _mm_xor_si128(encryptedKey, _mm_xor_si128(key, garbledTables[jumpInGarblesTable* nonXorIndex + i * 2]));
        }
        else{//in case the 0-wire has 1 signal bit
            computedWires[lastWireIndex + 1 + i] = _mm_xor_si128(encryptedKey, _mm_xor_si128(key, garbledTables[jumpInGarblesTable* nonXorIndex + i * 2 + 1]));
        }

        //finally
        Output[i] = computedWires[lastWireIndex + 1 + i];

    }

}


void GarbledBooleanCircuitNoIntrinsics::verifyOutputWiresToNoFixedDelta(byte *bothOutputsKeys){

    //The result of chunk encrypting indexArray.
    byte* encryptedChunkKeys = new byte[KEY_SIZE * numberOfOutputs];

    //An array that holds the number numberOfGates - numOfXorGates to the number of numberOfGates - numOfXorGates + numberOfOutputs.
    //The purpuse of this array is to encrypt all the number of outputs in one chucnk. This gains piplining
    byte* indexArray = new byte[KEY_SIZE * numberOfOutputs];

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
        if (getSignalBitOf(bothOutputsKeys + 2 * i * KEY_SIZE) == 0){
            *((unsigned char *)(&encryptedChunkKeys[i*KEY_SIZE])) |= 1;
            for (int j=0; j<KEY_SIZE; j++)
                bothOutputsKeys[(2 * i + 1)*KEY_SIZE + j] = encryptedChunkKeys[i*KEY_SIZE + j];
        }
        else{
            *((unsigned char *)(&encryptedChunkKeys[i*KEY_SIZE])) &= 0;
            for (int j=0; j<KEY_SIZE; j++)
                bothOutputsKeys[2 * i *KEY_SIZE + j] = encryptedChunkKeys[i*KEY_SIZE + j];
        }

    }

}

void GarbledBooleanCircuitNoIntrinsics::garbleOutputWiresToNoFixedDelta(byte *deltaFreeXor, int nonXorIndex, byte *emptyBothOutputKeys){

    //The result of chunk encrypting indexArray.
    byte* encryptedChunkKeys = new byte[KEY_SIZE * numberOfOutputs];

    //An array that holds the number numberOfGates - numOfXorGates to the number of numberOfGates - numOfXorGates + numberOfOutputs.
    //The purpuse of this array is to encrypt all the number of outputs in one chucnk. This gains piplining
    byte* indexArray = new byte[KEY_SIZE * numberOfOutputs];

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
        if (getSignalBitOf(garbledWires + outputIndices[i] * KEY_SIZE) == 0){
            garbledWires[lastWireIndex + 1 + 2 * i] = garbledWires[outputIndices[i]];
            *((unsigned char *)(&encryptedChunkKeys[i])) |= 1;
            garbledWires[lastWireIndex + 1 + 2 * i + 1] = encryptedChunkKeys[i];
        }
        else{
            *((unsigned char *)(&encryptedChunkKeys[i])) &= 0;
            garbledWires[lastWireIndex + 1 + 2 * i] = encryptedChunkKeys[i];
            garbledWires[lastWireIndex + 1 + 2 * i + 1] = garbledWires[outputIndices[i]];
        }

        byte* TwoA = new byte[2*KEY_SIZE];
        byte* keys = new byte[2*KEY_SIZE];
        byte* encryptedKeys = new byte[2*KEY_SIZE];


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
        if (getSignalBitOf(garbledWires + outputIndices[i]*KEY_SIZE) == 0){
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

}*/

bool GarbledBooleanCircuitNoIntrinsics::internalVerify(byte *bothInputKeys, byte *emptyBothWireOutputKeys){

    int nonXorIndex = 0;

    //set the delta to be the xor between the first 2 inputs
    for (int j=0;j<KEY_SIZE; j++) {
        deltaFreeXor[j] = bothInputKeys[j] ^ bothInputKeys[KEY_SIZE + j];
    }


    //copy the 0-wire input keys.
    for (int i = 0; i<numberOfInputs; i++){

        //get the input keys into the computed wires array
        memcpy(garbledWires + inputIndices[i]*KEY_SIZE, bothInputKeys + 2 * i*KEY_SIZE, KEY_SIZE);
    }

    byte* tweak = new byte[KEY_SIZE];
    byte* tweak2 = new byte[KEY_SIZE];
    byte* inputs = new byte[KEY_SIZE * 4];
    //declare temp variables to store the 0-wire key and the 1-wire key
    byte* k0 = new byte[KEY_SIZE];
    byte* tempK0 = new byte[KEY_SIZE];
    byte* tempK1 = new byte[KEY_SIZE];


    for (int i = 0; i<numberOfGates; i++){

        if (garbledGates[i].truthTable == XOR_GATE){
            //Create the 0-key of the output
            for (int j=0;j<KEY_SIZE; j++) {
                garbledWires[garbledGates[i].output * KEY_SIZE + j] = garbledWires[garbledGates[i].input0 * KEY_SIZE + j] ^
                                                                      garbledWires[garbledGates[i].input1 * KEY_SIZE + j];
            }
            continue;

        }
        else if (garbledGates[i].truthTable == XOR_NOT_GATE){
            //create the 0-key by xoring the two 0-keys of the input and xoring that with the delta.
            for (int j=0;j<KEY_SIZE; j++) {
                garbledWires[garbledGates[i].output * KEY_SIZE + j] = garbledWires[garbledGates[i].input0 * KEY_SIZE + j] ^
                                                                      garbledWires[garbledGates[i].input1 * KEY_SIZE + j] ^
                                                                      deltaFreeXor[j];
            }

        }

        else{

            //Calc the tweak

            //two different tweaks
            ((long*)tweak)[1] = i;
            ((long*)tweak2)[1] = i+numberOfGates;

            //create input arrays in order to get the inputs immedietly and not invoke unneeded xor's

            memcpy(inputs, garbledWires + garbledGates[i].input0*KEY_SIZE, KEY_SIZE);
            memcpy(inputs + 2*KEY_SIZE, garbledWires + garbledGates[i].input1*KEY_SIZE, KEY_SIZE);

            for (int j=0; j<KEY_SIZE; j++){
                inputs[KEY_SIZE + j] = inputs[j] ^ deltaFreeXor[j];
                inputs[3*KEY_SIZE + j] = inputs[2*KEY_SIZE + j] ^ deltaFreeXor[j];
            }

            //generate the keys array
            vector<byte> keys(4*KEY_SIZE);

            //signal bits of input0 and input1
            int wire0SignalBit, wire1SignalBit;

            //generate K = H(input) = 2Input XOR tweak
            //Multiply the input by 2
            for (int j=0; j<8; j++){
                ((long*)inputs)[j] = ((long*)inputs)[j]<<1;
            }

            for (int j=0; j<KEY_SIZE; j++){
                keys[j] = inputs[j] ^ tweak[j];
                keys[KEY_SIZE + j] = inputs[KEY_SIZE + j] ^ tweak[j];
                keys[2 * KEY_SIZE + j] = inputs[2 * KEY_SIZE + j] ^ tweak2[j];
                keys[3 * KEY_SIZE + j] = inputs[3 * KEY_SIZE + j] ^ tweak2[j];
            }

            //generate the keys array as well as the encryptedKeys array
            vector<byte> encryptedKeys(4*KEY_SIZE);
            //Encrypt the 4 keys in one chunk to gain pipelining and puts the answer in encryptedKeys block array
//            AES_ecb_encrypt_blks_4_in_out((block*)keys, (block*)encryptedKeys, &aesFixedKey);
            aes.optimizedCompute(keys, encryptedKeys);

            //for more information look at the pseudo-code of compute.
            for (int index0 = 0; index0< 2; index0++){
                wire0SignalBit = getSignalBitOf(inputs + index0*KEY_SIZE);
                for (int j = 0; j < 2; j++){

                    //last iteration, this should compute the k1 value, but since it is the only wire 1 key that is computed, there is no value to
                    //compare it to, since the gate can only be an AND gate.
                    if (index0 == 1 && j == 1){
                        continue;
                    }

                    wire1SignalBit = getSignalBitOf(inputs + (j+2)*KEY_SIZE);


                    if (wire0SignalBit == 0){
                        for (int k=0; k<KEY_SIZE; k++) {
                            tempK0[k] = encryptedKeys[index0 * KEY_SIZE + k] ^ keys[index0 * KEY_SIZE + k];
                        }
                    }
                    else{
                        for (int k=0; k<KEY_SIZE; k++) {
                            tempK0[k] = encryptedKeys[index0 * KEY_SIZE + k] ^ keys[index0 * KEY_SIZE + k] ^
                                        garbledTables[2 * nonXorIndex * KEY_SIZE + k];
                        }
                    }

                    if (wire1SignalBit == 0){
                        for (int k=0; k<KEY_SIZE; k++) {
                            tempK1[k] = encryptedKeys[(j + 2) * KEY_SIZE + k] ^ keys[(j + 2) * KEY_SIZE + k];
                        }
                    }
                    else{
                        for (int k=0; k<KEY_SIZE; k++) {
                            tempK1[k] = encryptedKeys[(j + 2) * KEY_SIZE + k] ^ keys[(j + 2) * KEY_SIZE + k] ^
                                        garbledTables[(2 * nonXorIndex + 1) * KEY_SIZE + k] ^ inputs[index0 * KEY_SIZE + k];
                        }
                    }

                    //first iteration that computes the k0 wire
                    if (index0 == 0 && j == 0){//this is a zero value output
                        for (int k=0; k<KEY_SIZE; k++) {
                            k0[k] = tempK0[k] ^ tempK1[k];
                            garbledWires[garbledGates[i].output*KEY_SIZE + k] = k0[k];
                        }
                    }
                        //cases 0,1 and 1,0. These cases should also compute k0, we compare it to the k0 calculated in the first iteration.
                    else {
                        for (int k=0; k<KEY_SIZE; k++) {
                            k0[k] = tempK0[k] ^ tempK1[k];
                        }
                        if (!(equalBlocks(k0, garbledWires + garbledGates[i].output*KEY_SIZE)))
                            return false;
                    }
                }

            }

            //increment the nonXor gates number only for the non-xor (not XOR or XOR_NOT) gates.
            nonXorIndex++;
        }
    }

    delete [] tweak;
    delete [] tweak2;
    delete [] inputs;
    //declare temp variables to store the 0-wire key and the 1-wire key
    delete [] k0;
    delete [] tempK0;
    delete [] tempK1;

    //copy the output keys to return to the caller of the function
    for (int i = 0; i < numberOfOutputs; i++) {
        memcpy(emptyBothWireOutputKeys + 2 * i * KEY_SIZE, garbledWires +outputIndices[i]*KEY_SIZE, KEY_SIZE);
        for (int k=0; k<KEY_SIZE; k++) {
            emptyBothWireOutputKeys[(2 * i + 1) * KEY_SIZE + k] = emptyBothWireOutputKeys[2 * i * KEY_SIZE + k] ^ deltaFreeXor[k];
        }
    }

    return true;

}