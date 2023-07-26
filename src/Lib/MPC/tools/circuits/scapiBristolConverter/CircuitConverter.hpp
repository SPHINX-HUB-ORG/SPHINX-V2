//
// Created by moriya on 19/02/17.
//

#pragma once

#include <string>
#include <iostream>
#include <fstream>
#include <set>

using namespace std;

/**
 * The GarbledGate class is a software representation of a circuit's gate, that is the structure of the boolean circuit and not the actuall values assigned.
 * It contains a truth table that performs a function on the values of the input wires (input0 and input1)  and assigns
 * that value to the output wire.
 *
 * author: Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*/
struct Gate
{
    int in, out; //number of input and output wires.
    int input0;//the 0-wire index
    int input1;//the 1-wire index
    int output;//the output index
    string type; //the type of the gate
};


class CircuitConverter {
public:
    /**
     * Converts the given circuit from bristol format into scapi format.
     * @param bristolFileName The original file to convert
     * @param scapiFileName The destination file to create
     */
    static void convertBristolToScapi(string bristolFileName, string scapiFileName, int numParties, bool isMultiParty);

    /**
    * Converts the given circuit from scapi format into bristol format.
    * @param scapiFileName The original file to convert
    * @param bristolFileName The destination file to create
    */
    static void convertScapiToBristol(string scapiFileName, string bristolFileName, bool isMultiParty);

    static int binaryTodecimal(int n);
};

