//
// Created by moriya on 19/02/17.
//

#include "CircuitConverter.hpp"
#include <vector>

 void CircuitConverter::convertBristolToScapi(string bristolFileName, string scapiFileName, int numParties, bool isMultiParty){
    
    int inFan, outFan, input0   , output, numberOfGates, numberOfOutputs, numberOfWires;
     vector<int> numInputsPerParty(numParties);
    string type;

    ifstream bristolfile;
    ofstream scapiFile;

    bristolfile.open(bristolFileName);
    scapiFile.open(scapiFileName);

    if (bristolfile.is_open() && scapiFile.is_open()) {

        bristolfile >> numberOfGates;//get the gates
        scapiFile << numberOfGates << " "; //print number of gates
        scapiFile << numParties << endl; //print number of parties

        bristolfile >> numberOfWires; //number of wires

        int index = 0;
        for (int i=0; i<numParties; i++){
            bristolfile >> numInputsPerParty[i];
            scapiFile << i+1 << " "<< numInputsPerParty[i] << endl;
            for(int j = 0; j<numInputsPerParty[i]; j++){
                scapiFile << index + j << endl;
            }
            index += numInputsPerParty[i];
        }

        //get the number of outputs
        bristolfile >> numberOfOutputs;

        if (!isMultiParty){
            scapiFile << numberOfOutputs <<endl;
            for (int j=0; j<numberOfOutputs; j++){
                scapiFile << numberOfWires - numberOfOutputs + j << endl;
            }

        } else{
            for (int i=0; i<numParties; i++){
                scapiFile << i+1 << " " << numberOfOutputs << endl;

                for (int j=0; j<numberOfOutputs; j++){
                    scapiFile << numberOfWires - numberOfOutputs + j << endl;
                }
            }

        }

        for(int i=0; i<numberOfGates;i++) {

            //read from the file and print the exat values
            bristolfile >> inFan;
            scapiFile << inFan << " ";

            bristolfile >> outFan;
            scapiFile << outFan << " ";

            for (int j=0; j<inFan; j++){
                bristolfile >> input0;
                scapiFile << input0 << " ";
            }

            for (int j=0; j<outFan; j++){
                bristolfile >> output;
                scapiFile << output << " ";
            }

            bristolfile >> type;

            if (type == "INV")//NOT gate
            {
                scapiFile << "10" << endl;
            } else if (type == "XOR") {
                scapiFile << "0110" << endl;
            } else if (type == "AND") {
                scapiFile << "0001" << endl;
            } else if (type == "OR") {
                scapiFile << "0111" << endl;
            }else if (type == "SPLIT") {
                scapiFile << "0000" << endl;
            }
        }
    }
    bristolfile.close();
    scapiFile.close();

}

/**
* Converts the given circuit from scapi format into bristol format.
* @param scapiFileName The original file to convert
* @param bristolFileName The destination file to create
*/
 void CircuitConverter::convertScapiToBristol(string scapiFileName, string bristolFileName, bool isMultiParty){

    int typeBin, numOfinputsForParty0, numOfinputsForParty1, numberOfGates, numberOfOutputs, type, numParties, numWires;

    int* inputs0, *inputs1;

    ifstream scapiFile;
    ofstream bristolFile;

    scapiFile.open(scapiFileName);
    bristolFile.open(bristolFileName);

    int temp;
    if (scapiFile.is_open() && bristolFile.is_open())
    {
        scapiFile >> numberOfGates;//get the gates
        bristolFile << numberOfGates << " "; //print number of gates

        scapiFile >> numParties; //read number of parties

        scapiFile >> temp; //p1
        scapiFile >> numOfinputsForParty0;

        inputs0 = new int[numOfinputsForParty0];
        for(int i = 0; i<numOfinputsForParty0; i++){
            scapiFile >> inputs0[i];
        }

        scapiFile >> temp;//p2
        scapiFile >> numOfinputsForParty1;
        inputs1 = new int[numOfinputsForParty1];
        for(int i = 0; i<numOfinputsForParty1; i++){
            scapiFile >> inputs1[i];
        }

        numWires = numOfinputsForParty0 + numOfinputsForParty1 + numberOfGates;
        bristolFile << numWires << endl;//print number of wires
        bristolFile << numOfinputsForParty0 << " " <<numOfinputsForParty1<<" ";

        set<int> outputValues;

        if (isMultiParty){
            //Each party can have different output wires. In order to get the number of all outputs, we insert each value to a set.
            //This way, if we have multiple output wires, they will be calculated once.
            for (int i=0; i<numParties; i++){

                //party number
                scapiFile >> temp;
                //get the number of outputs of this party
                scapiFile >> numberOfOutputs;
                //insert each output value to the set.
                for (int i = 0; i < numberOfOutputs; i++) {
                    scapiFile >> temp;
                    outputValues.insert(temp);
                }
            }
            numberOfOutputs = outputValues.size();

        } else {
            //get the number of outputs
            scapiFile >> numberOfOutputs;
            //read the outputs
            for (int i = 0; i < numberOfOutputs; i++) {
                scapiFile >> temp;
                outputValues.insert(temp);
            }
        }
        //print the number of outputs
        bristolFile << numberOfOutputs << endl;

        Gate* gates = new Gate[numberOfGates];
        for(int i=0; i<numberOfGates;i++) {
            //read from the file and print the exat values
            scapiFile >> gates[i].in;
            scapiFile >> gates[i].out;
            scapiFile >> gates[i].input0;
            if (gates[i].in != 1)//a 2 input 1 output gate - regualr gate, else we have a not gate
            {
                scapiFile >> gates[i].input1;
            }

            scapiFile >> gates[i].output;
            scapiFile >> typeBin;
            type = binaryTodecimal(typeBin);

            if (gates[i].in == 1)//NOT gate
            {
                gates[i].type = "INV";
            } else if (type == 6) {
                gates[i].type = "XOR" ;
            } else if (type == 1) {
                gates[i].type = "AND";
            } else if (type == 7) {
                gates[i].type = "OR";
            }
        }

        auto outputsIter = outputValues.cbegin();

        //We need to convert the output wires to start at number and end with number of inputs.
        for (int i= numWires - numberOfOutputs; i < numWires; i++, outputsIter++){
            //input wire i should be replaced with i
            temp = *outputsIter;
            //If they are the same, nothing should be done
            if (temp == i)
                continue;
            //they are not the same, replace every place where there is a "temp" with "i" and vice versa.
            for (int j=0; j<numberOfGates; j++){
                if (gates[j].output == temp){
                    gates[j].output = i;
                } else if (gates[j].output == i){
                    gates[j].output = temp;
                }
                if (gates[j].input0 == temp) {

                    gates[j].input0 = i;
                } else if (gates[j].input0 == i){
                    gates[j].input0 = temp;
                }
                if (gates[j].input1 == temp){
                    gates[j].input1 = i;
                } else if (gates[j].input1 == i){
                    gates[j].input1 = temp;
                }
            }
        }

        //Create an array that hold all input wires
        int numberOfInputs = numOfinputsForParty0 + numOfinputsForParty1;
        int allInputWires[numberOfInputs];
        for (int i=0; i<numOfinputsForParty0; i++){
            allInputWires[i] = inputs0[i];
        }
        for (int i=0; i<numOfinputsForParty1; i++){
            allInputWires[numOfinputsForParty0 + i] = inputs1[i];
        }
        delete inputs0;
        delete inputs1;

        //We need to convert the input wires to start at 0 and end with number of inputs.
        for (int i=0; i<numberOfInputs; i++){
            //input wire i should be replaced with i
            temp = allInputWires[i];
            //If they are the same, nothing should be done
            if (temp == i)
                continue;
            //they are not the same, replace every place where there is a "temp" with "i" and vice versa.
            for (int j=0; j<numberOfGates; j++){
                if (gates[j].input0 == temp){
                    gates[j].input0 = i;
                } else if (gates[j].input0 == i){
                    gates[j].input0 = temp;
                }
                if (gates[j].input1 == temp){
                    gates[j].input1 = i;
                } else if (gates[j].input1 == i){
                    gates[j].input1 = temp;
                }
                if (gates[j].output == i){
                    gates[j].output = temp;
                }
            }

            for (int j=i + 1; j<numberOfInputs; j++){
                if (allInputWires[j] == i){
                    allInputWires[j] = temp;
                }
            }
        }

        for (int i=0; i<numberOfGates; i++){
            bristolFile << gates[i].in << " ";
            bristolFile << gates[i].out << " ";
            bristolFile << gates[i].input0 << " ";

            if (gates[i].in != 1){
                bristolFile << gates[i].input1 << " ";
            }

            bristolFile << gates[i].output << " ";
            bristolFile << gates[i].type << endl;
        }
        delete [] gates;
    }
    scapiFile.close();
    bristolFile.close();
}

int CircuitConverter::binaryTodecimal(int n){

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
