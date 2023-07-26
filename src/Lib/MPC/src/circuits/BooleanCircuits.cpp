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

#include "../../include/circuits/BooleanCircuits.hpp"

/****************************************************/
/*                    Gate                          */
/****************************************************/
void Gate::compute(map<int, Wire> & computedWires) {
	// we call the calculateIndexOfTruthTable method to tell us the position of the output value in the truth table 
	// and look up the value at that position.
	bool bVal = truthTable.at(calculateIndexOfTruthTable(computedWires));
	byte outputValue = (byte)(bVal ? 1 : 0);
	int numberOfOutputs = outputWireIndices.size();

	// assigns output value to each of this gate's output Wires.
	for (int i = 0; i < numberOfOutputs; i++)
		computedWires[outputWireIndices[i]] = Wire(outputValue);
}

bool Gate::operator==(const Gate &other) const {
	// first we verify that the gates' numbers are the same.
	if (gateNumber_ != other.gateNumber_)
		return false;

	// next we verify that the gates' respective truth tables are the same.
	if (truthTable != other.truthTable)
		return false;

	// next we verify that the number of input and output wires to the two respective gates are equal.
	if ((inputWireIndices.size() != other.inputWireIndices.size()) || (outputWireIndices.size() != other.outputWireIndices.size()))
		return false;

	/*
	* Having determined that the number of input Wire's are the same, we now check that corresponding input wires
	* have the same index. As we demonstrated above (in the comments on the imputWireIndices field), the order of the
	* wires is significant as not all functions are symmetric. So not only do we care that Wire have the same indices,
	* but we also care that the wires with the same index are in the same position of the inputWireIndices array.
	*/
	int numberOfInputs = inputWireIndices.size();
	for (int i = 0; i < numberOfInputs; i++)
		if (inputWireIndices[i] != other.inputWireIndices[i])
			return false;

	/*
	* Having determined that the number of output Wire's are the same, we now check that corresponding output wires have
	* the same index.
	*/
	int numberOfOutputs = outputWireIndices.size();
	for (int i = 0; i < numberOfOutputs; i++)
		if (outputWireIndices[i] != other.outputWireIndices[i])
			return false;

	// If we've reached this point, then the Gate's are equal so we return true.
	return true;
}

int Gate::calculateIndexOfTruthTable(map<int, Wire> computedWires) const {
	/*
	* Since a truth tables order is the order of binary counting, the index of a desired row can be calculated as follows:
	* For a truth table with L inputs whose input columns are labeled aL...ai...a2,a1,
	* the output index for a given input set is given by: summation from 0 to L : ai *2^i.
	* This is calculated below:
	*/
	int truthTableIndex = 0;
	int numberOfInputs = inputWireIndices.size();
	for (int i = numberOfInputs - 1, j = 0; j < numberOfInputs; i--, j++)
		truthTableIndex += (int) computedWires[inputWireIndices[i]].getValue() * pow(2, j);

	return truthTableIndex;
}

/****************************************************/
/*                BooleanCircuit                    */
/****************************************************/

BooleanCircuit::BooleanCircuit(scannerpp::Scanner s) {
	//Read the number of gates.
	int numberOfGates = atoi(read(s).c_str());
	gates.resize(numberOfGates);
	//Read the number of parties.
	numberOfParties = atoi(read(s).c_str());
	isInputSet.resize(numberOfParties);
	
	//For each party, read the party's number, number of input wires and their indices.
	for (int i = 0; i < numberOfParties; i++) {
		if (atoi(read(s).c_str()) != i + 1) {//add 1 since parties are indexed from 1, not 0
			throw runtime_error("Circuit file format is wrong");
		}
		//Read the number of input wires.
		int numberOfInputsForCurrentParty = atoi(read(s).c_str());
		if (numberOfInputsForCurrentParty < 0) {
			throw runtime_error("Circuit file format is wrong");
		}
		bool isThisPartyInputSet = numberOfInputsForCurrentParty == 0 ? true : false;
		isInputSet[i] = isThisPartyInputSet;

		vector<int> currentPartyInput(numberOfInputsForCurrentParty);
		//Read the input wires indices.
		for (int j = 0; j < numberOfInputsForCurrentParty; j++) {
			currentPartyInput[j] = atoi(read(s).c_str());
		}
		eachPartysInputWires.push_back(currentPartyInput);
	}
	
	/*
	* The ouputWireIndices are the outputs from this circuit. However, this circuit may actually be a single layer of a
	* larger layered circuit. So this output can be part of the input to another layer of the circuit.
	*/
    if (numberOfParties == 2){
        int numberOfCircuitOutputs = atoi(read(s).c_str());

        vector<int> currentPartyOutput(numberOfCircuitOutputs);
        //Read the input wires indices.
        for (int j = 0; j < numberOfCircuitOutputs; j++) {
            currentPartyOutput[j] = atoi(read(s).c_str());
        }
        eachPartysOutputWires.push_back(currentPartyOutput);
    } else {
        //For each party, read the party's number, number of output wires and their indices.
        for (int i = 0; i < numberOfParties; i++) {
            if (atoi(read(s).c_str()) != i + 1) {//add 1 since parties are indexed from 1, not 0
                throw runtime_error("Circuit file format is wrong");
            }
            //Read the number of input wires.
            int numberOfOutputForCurrentParty = atoi(read(s).c_str());
            if (numberOfOutputForCurrentParty < 0) {
                throw runtime_error("Circuit file format is wrong");
            }

            vector<int> currentPartyOutput(numberOfOutputForCurrentParty);
            //Read the input wires indices.
            for (int j = 0; j < numberOfOutputForCurrentParty; j++) {
                currentPartyOutput[j] = atoi(read(s).c_str());
            }
            eachPartysOutputWires.push_back(currentPartyOutput);
        }
    }

	int numberOfGateInputs, numberOfGateOutputs;
	//For each gate, read the number of input and output wires, their indices and the truth table.
	for (int i = 0; i < numberOfGates; i++) {
		numberOfGateInputs = atoi(read(s).c_str());
		numberOfGateOutputs = atoi(read(s).c_str());
		vector<int> inputWireIndices(numberOfGateInputs);
		vector<int> outputWireIndices(numberOfGateOutputs);
		for (int j = 0; j < numberOfGateInputs; j++) {
			inputWireIndices[j] = atoi(read(s).c_str());
		}
		for (int j = 0; j < numberOfGateOutputs; j++) {
			outputWireIndices[j] = atoi(read(s).c_str());
		}

		/*
		* We create a BitSet representation of the truth table from the 01 String
		* that we read from the file.
		*/
		vector<bool> truthTable;
		string tTable = read(s);
		for (size_t j = 0; j < tTable.length(); j++) {
			if (tTable.at(j) == '1') 
				truthTable.push_back(true);
			else 
				truthTable.push_back(false);
		}
		//Construct the gate.
		gates[i] = Gate(i, truthTable, inputWireIndices, outputWireIndices);
	}
}

void BooleanCircuit::setInputs(const map<int, Wire> & presetInputWires, int partyNumber) {
	if (partyNumber < 1 || partyNumber > numberOfParties)
		throw NoSuchPartyException("wrong number of party. got: " + to_string(partyNumber));

	if (!isInputSet[partyNumber - 1]) {
		computedWires.insert(presetInputWires.begin(), presetInputWires.end());
	} else {

		int numberOfInputWires = getNumberOfInputs(partyNumber);
		auto inputIndices = getInputWireIndices(partyNumber);

		for (int i = 0; i < numberOfInputWires; i++) {
			computedWires[inputIndices[i]] = presetInputWires.at(inputIndices[i]).getValue();
		}

	}

	isInputSet[partyNumber - 1] = true;
}

void BooleanCircuit::setInputs(scannerpp::File * inputWiresFile, int partyNumber) {
	if (partyNumber < 1 || partyNumber > numberOfParties)
		throw NoSuchPartyException("wrong number of party. got: " + to_string(partyNumber));
	scannerpp::Scanner s(inputWiresFile);
	int numberOfInputWires = getNumberOfInputs(partyNumber);
	auto inputIndices = getInputWireIndices(partyNumber);
	map<int, Wire> presetInputWires;
	for (int i = 0; i < numberOfInputWires; i++) {
        presetInputWires[inputIndices[i]] = Wire(stoi(read(s)));
    }

		
	setInputs(presetInputWires, partyNumber);
}

map<int, Wire> BooleanCircuit::compute() {
	for (int i = 0; i < numberOfParties; i++)
		if (!isInputSet[i])
			throw NotAllInputsSetException("not all inputs set");

	/* Computes each Gate.
	* Since the Gates are provided in topological order, by the time the compute function on a given Gate is called,
	* its input Wires will have already been assigned values
	*/
	for (Gate g : getGates())
		g.compute(computedWires);

	/*
	* The computedWires array contains all the computed wire values, even those that it is no longer necessary to retain.
	* So, we create a new Map called outputMap which only stores the Wires that are output Wires to the circuit.
	* We return outputMap.
	*/
	map<int, Wire> outputMap;
    for (int i=0; i<numberOfParties; i++) {
        auto outputWireIndices = eachPartysOutputWires[i];
        for (int w : outputWireIndices)
            outputMap[w] = computedWires[w];
    }
	return outputMap;
}

bool BooleanCircuit::operator==(const BooleanCircuit &other) const {
	// first tests to see that the number of Gates is the same for each circuit. If it's not, then the two are not equal.
	if (getGates().size() != other.getGates().size()) {
		return false;
	}
	// calls the equals method of the Gate class to compare each corresponding Gate. 
	// if any of them return false, the circuits are not the same.
	for (size_t i = 0; i < getGates().size(); i++) 
		if ( getGates()[i]!= other.getGates()[i] )
			return false;

	return true;
}

vector<int> BooleanCircuit::getInputWireIndices(int partyNumber) const {
	if (partyNumber < 1 || partyNumber > numberOfParties) 
		throw NoSuchPartyException("wrong number of party. got: " + to_string(partyNumber));
	// we subtract one from the party number since the parties are indexed beginning from one, but the ArrayList is indexed from 0
	return eachPartysInputWires[partyNumber - 1];
}

vector<int> BooleanCircuit::getOutputWireIndices(int partyNumber) const {
    if (partyNumber < 1 || partyNumber > numberOfParties)
        throw NoSuchPartyException("wrong number of party. got: " + to_string(partyNumber));
    // we subtract one from the party number since the parties are indexed beginning from one, but the ArrayList is indexed from 0
    return eachPartysOutputWires[partyNumber - 1];
}

vector<int> BooleanCircuit::getOutputWireIndices() const {
   if (numberOfParties != 2){
       throw IllegalStateException("This function should be called in case of two party only");
   }
    // we subtract one from the party number since the parties are indexed beginning from one, but the ArrayList is indexed from 0
    return eachPartysOutputWires[0];
}

int BooleanCircuit::getNumberOfInputs(int partyNumber) const {
	if (partyNumber < 1 || partyNumber > numberOfParties)
		throw NoSuchPartyException("wrong number of party. got: " + to_string(partyNumber));
	// we subtract one from the party number since the parties are indexed beginning from one, but the ArrayList is indexed from 0
	return (int) eachPartysInputWires[partyNumber - 1].size();
}

string BooleanCircuit::read(scannerpp::Scanner s) {
	string token = s.next();
	while (boost::starts_with(token, "#")) {
		s.nextLine();
		token = s.next();
	}
	return token;
}

void BooleanCircuit::write(string outputFileName){

	ofstream outputFile;
	outputFile.open(outputFileName);

	if (outputFile.is_open()) {
		//write the number of gates.
		int numberOfGates = gates.size();
		outputFile << numberOfGates << endl;
		//write the number of parties.
		outputFile << numberOfParties << endl;
		outputFile << endl;

		//For each party, read the party's number, number of input wires and their indices.
		for (int i = 0; i < numberOfParties; i++) {
			outputFile << i+1 << " ";//add 1 since parties are indexed from 1, not 0

			int numberOfInputsForCurrentParty = eachPartysInputWires[i].size();
			//Read the number of input wires.
			outputFile << numberOfInputsForCurrentParty << endl;

			//Read the input wires indices.
			for (int j = 0; j < numberOfInputsForCurrentParty; j++) {
				outputFile << eachPartysInputWires[i][j] << endl;
			}
			outputFile << endl;
		}

		//Write the outputs number
        if (numberOfParties == 2) {
            int numberOfOutputs = eachPartysOutputWires[0].size();
            outputFile << numberOfOutputs << endl;

            //Write the output wires indices.
            for (int i = 0; i < numberOfOutputs; i++) {
                outputFile << eachPartysOutputWires[0][i] << endl;
            }
        } else {
            //For each party, read the party's number, number of input wires and their indices.
            for (int i = 0; i < numberOfParties; i++) {
                outputFile << i+1 << " ";//add 1 since parties are indexed from 1, not 0

                int numberOfOutputForCurrentParty = eachPartysOutputWires[i].size();
                //Read the number of input wires.
                outputFile << numberOfOutputForCurrentParty << endl;

                //Read the input wires indices.
                for (int j = 0; j < numberOfOutputForCurrentParty; j++) {
                    outputFile << eachPartysOutputWires[i][j] << endl;
                }
                outputFile << endl;
            }
        }

		outputFile << endl;

		//For each gate, write the number of input and output wires, their indices and the truth table.
		int numberOfGateInputs, numberOfGateOutputs;
		for (int i = 0; i < numberOfGates; i++) {

			numberOfGateInputs = gates[i].getInputWireIndices().size();
			numberOfGateOutputs = gates[i].getOutputWireIndices().size();
			outputFile << numberOfGateInputs << " ";
			outputFile << numberOfGateOutputs << " ";

			for (int j = 0; j < numberOfGateInputs; j++) {
				outputFile << gates[i].getInputWireIndices()[j] << " ";
			}
			for (int j = 0; j < numberOfGateOutputs; j++) {
				outputFile << gates[i].getOutputWireIndices()[j] << " ";
			}

			/*
			* We create a BitSet representation of the truth table from the 01 String
			* that we read from the file.
			*/
			auto tTable = gates[i].getTruthTable();
			for (size_t j = 0; j < tTable.size(); j++) {
				if (tTable[j])
					outputFile << "1";
				else
					outputFile <<"0";
			}
			outputFile << endl;
		}
	}
	outputFile.close();
}
