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
#include "../infra/Common.hpp"
#include "../infra/Scanner.hpp"
#include <fstream>
#include <iostream>
#include <map>


class NoSuchPartyException : public logic_error
{
public:
	NoSuchPartyException(const string & msg) : logic_error(msg) {};
	virtual char const * what() const throw() { return "No Such Party"; }
};

class InvalidInputException : public logic_error
{
public:
	InvalidInputException(const string & msg) : logic_error(msg) {};
	virtual char const * what() const throw() { return "Invalid input"; }
};
class NotAllInputsSetException : public logic_error
{
public:
	NotAllInputsSetException(const string & msg) : logic_error(msg) {};
	virtual char const * what() const throw() { return "Not all input is set"; };
};


/**
* The {@code Wire} class is a software representation of a {@code Wire} in a circuit. <p>
* As these are {@code Wire}s for Boolean circuit's, each {@code Wire} can be set to either 0 or 1.
*/
class Wire {
public:
	Wire() {};
	/**
	* Creates a {@code Wire} and sets it to the specified value.
	*
	* @param value The value to set this {@code Wire} to. Must be either 0 or 1.
	*/
	Wire(byte value) {
		// Ensures that the Wire is only set to a legal value (i.e. 0 or 1)
		if (value != 0 && value != 1)
			throw invalid_argument("Wire value can only be 0 or 1");
		else
			this->value = value;
	};
	/**
	* @return the value (0 or 1) that this {@code Wire} is set to.
	*/
	byte getValue() const { return value; };
	
private:
	/**
	* The value that this wire carries. It can be set to either 0 or 1
	*/
	byte value;
};

/**
* The {@code Gate} class is a software representation of a circuit's gate.<p>
* It contains a truth table that performs a function on the values of the input {@code Wire}s and assigns
* that value to the output {@code Wire}(s).
*/
class Gate {
public:
	Gate() {};

	/**
	* Sets the given values.
	* @param gateNumber The gate's number (in a circuit all gates will be numbered).
	* @param truthTable A BitSet representation of the final column of a truth table( i.e. the output of the function being computed).
	* @param inputWireIndices An array containing the indices of the gate's input {@code Wire}s.
	* @param outputWireIndices An array containing the indices of the gate's input {@code Wire}(s).
	* There will generally be a single output {@code Wire}. However in instances in which fan-out of the output {@code Wire} is >1,
	* we left the option for treating this as multiple {@code Wire}s.
	*/
	Gate(const int gateNumber, const vector<bool> & truthTable, const vector<int> & inputWireIndices, const vector<int> & outputWireIndices) {
		this->gateNumber_ = gateNumber;
		this->truthTable = truthTable;
		this->inputWireIndices = inputWireIndices;
		this->outputWireIndices = outputWireIndices;
	};

	/**
	* Compute the gate operation.<p>
	* @param computedWires A {@code Map} that maps an integer wire index to the Wire.
	* The values of these {@code Wire}s has already been set (it has been <b>computed</b>--hence the name computedWires).
	*/
	void compute(map<int, Wire>& computedWires);

	/**
	* @param obj A gate that is to be tested for equality to the current {@code Gate}.
	* @return {@code true} if the gates are equivalent and {@code false} otherwise.
	*/
	bool operator==(const Gate &other) const;
	bool operator!=(const Gate &other) const { return !(*this == other);};

	/**
	* Returns an array containing the indices of the input {@code Wire}s to this {@code Gate}.
	*/
	vector<int> getInputWireIndices() const { return inputWireIndices; };

	/**
	* Returns the indices of the {@link Wire}s that are the output of this {@code Gate}. <p>
	* In most circuit designs, this will contain a single wire.
	* However, in the case of fan-out > 1, some circuit designers may treat each as separate wires.
	*/
	vector<int> getOutputWireIndices() const { return outputWireIndices; };

	/**
	* Returns the {@code Gate}'s truth table.
	*/
	vector<bool> getTruthTable() const { return truthTable; };

private:
	/**
	* A BitSet representation of the final column of a truth table (i.e. the output of the function being computed).
	*/
	vector<bool> truthTable;

	/**
	* An array containing the indices of the input Wires of this gate. <P>
	* The order of the {@code Wire}s in this array is significant as not all functions are symmetric.
	*/
	/*
	* Note that the ordering of these Wires must be the same also since some functions are not symmetric.
	* For example consider the function ~y v x and the following truth table:
	* x       y    ~y v x
	* 0       0       1
	* 0       1       0
	* 1       0       1
	* 1       1       1
	*/
	vector<int> inputWireIndices;

	/**
	* An array containing the indices of the output {@code Wire}(s).
	*/
	vector<int> outputWireIndices;

	/**
	* The number of this {@code Gate}. This number is used to order {@code Gate}s in a {@link BooleanCircuit}.
	*/
	int gateNumber_;

	/**
	* This is a helper method that calculates the index of the output value on a truth table corresponding to
	* the values of the input {@code Wire}s.
	*
	* @param computedWires A {@code Map} that maps an integer wire index to the Wire.
	* The values of these {@code Wire}s have already been set (they has been <b>computed</b>--hence the name computedWires).
	* @return the index of the Truth table output corresponding to the values of the input {@code Wire}s.
	*/
	int calculateIndexOfTruthTable(map<int, Wire> computedWires) const;

	/**
	* Returns the {@code Gate}'s number.
	*/
	int getGateNumber() const { return gateNumber_; };
};

/**
* A software representation of a boolean circuit. <p>
* The circuit is constructed from {@code Wire}s and {@code Gate}s. Once input has been set, the compute() function performs the
* computation and returns the computed output {@code Wire}s.
* The equals function verifies that two gates are equivalent.
*/
class BooleanCircuit {
public:
	/**
	* Constructs a BooleanCircuit from a Scanner. <p>
	* The Scanner's underyling contents contains a lists the number of {@code Gate}s, then the number of parties. <p>
	* Then for each party: party number, the number of inputs for that party, and following there is a list of indices of each of these input {@code Wire}s.<p>
	* Next it lists the number of output {@code Wire}s followed by the index of each of these {@code Wires}. <p>
	* Then for each gate, we have the following: number of inputWires, number of OutputWires inputWireIndices OutputWireIndices and the gate's truth Table (as a 0-1 string).<P>
	* example file: 1 2 1 1 1 2 1 2 1 3 2 1 1 2 3 0001<p>
	*
	* @param s The {@link Scanner} from which the circuit is read.
	* @throws CircuitFileFormatException if there is a problem with the format of the circuit.
	*/
	BooleanCircuit(scannerpp::Scanner s);

	/**
	* Constructs a BooleanCircuit from a File. <p>
	* The File first lists the number of {@code Gate}s, then the number of parties. <p>
	* Then for each party: party number, the number of inputs for that party, and following there is a list of indices of each of these input {@code Wire}s.<p>
	* Next it lists the number of output {@code Wire}s followed by the index of each of these {@code Wires}. <p>
	* Then for each gate, we have the following: number of inputWires, number of OutputWires inputWireIndices OutputWireIndices and the gate's truth Table (as a 0-1 string).<P>
	* example file: 1 2 1 1 1 2 1 2 1 3 2 1 1 2 3 0001<p>
	*
	* @param f The {@link File} from which the circuit is read.
	* @throws FileNotFoundException if f is not found in the specified directory.
	* @throws CircuitFileFormatException if there is a problem with the format of the file.
	*/
	BooleanCircuit(scannerpp::File * fp) : BooleanCircuit(scannerpp::Scanner(fp)) {};

	/**
	* Constructs a {code BooleanCircuit} from an array of gates. <p>
	* Each gate keeps an array of the indices of its input and output wires. The constructor is provided with a list of which
	* {@link Wire}s are output {@link Wire}s of the {@code BooleanCircuit}.
	* This constructor is used in case of two party circuit only. In order to create a multi-party circuit use the constructor that accept
	* the output as vector of vectors.
	 *
	* @param gates An array of {@link Gate}s to create from which to construct the {@code BooleanCircuit}.
	* @param outputWireIndices An array containing the indices of the wires that will be output of the {@code BooleanCircuit}.
	* @param eachPartysInputWires An arrayList containing the indices of the input {@code Wire}s of this
	* {@code BooleanCircuit} indexed by the party number.
	*/
	BooleanCircuit(const vector<Gate> & gates, const vector<int> & outputWireIndices, const vector<vector<int>> & eachPartysInputWires) :
		isInputSet(eachPartysInputWires.size())
	{
		this->gates = gates;
        numberOfParties = eachPartysInputWires.size();
        if (numberOfParties > 2) {
            throw InvalidInputException("This constructor should be used in case of two-party only");
        }

        int outputSize = outputWireIndices.size();
        vector<int> circuitOutput(outputSize);
        //Read the input wires indices.
        for (int j = 0; j < outputSize; j++) {
            circuitOutput[j] = outputWireIndices[j];
        }
        eachPartysOutputWires.push_back(circuitOutput);
        this->eachPartysInputWires = eachPartysInputWires;
	}

    /**
	* Constructs a {code BooleanCircuit} from an array of gates. <p>
	* Each gate keeps an array of the indices of its input and output wires. The constructor is provided with a list of which
	* {@link Wire}s are output {@link Wire}s of the {@code BooleanCircuit}.
	*
	* @param gates An array of {@link Gate}s to create from which to construct the {@code BooleanCircuit}.
	* @param outputWireIndices An array containing the indices of the wires that will be output of the {@code BooleanCircuit}.
	* @param eachPartysInputWires An arrayList containing the indices of the input {@code Wire}s of this
	* {@code BooleanCircuit} indexed by the party number.
	*/
    BooleanCircuit(const vector<Gate> & gates, const vector<vector<int>> & eachPartysOutputWires, const vector<vector<int>> & eachPartysInputWires) :
            isInputSet(eachPartysInputWires.size())
    {
        this->gates = gates;
        numberOfParties = eachPartysInputWires.size();
        this->eachPartysOutputWires = eachPartysOutputWires;
        this->eachPartysInputWires = eachPartysInputWires;
    }

	/**
	* Sets the specified party's input to the circuit from a map containing constructed and set {@link Wire}s. <p>
	* It updates that this party's input has been set.
	* Once the input is set for all parties that have input, the circuit is ready to be computed.
	*
	* @param presetInputWires The circuit's input wires whose values have been previously set.
	* @throws NoSuchPartyException if the party number is negative or bigger then the given number of parties.
	*/
	void setInputs(const map<int, Wire> & presetInputWires, int partyNumber);

	/**
	* Sets the input to the circuit by reading it from a file. <p>
	* Written in the file is a list that contains the number of input {@link Wire}s followed by rows of {@link Wire} numbers and values.
	*
	* @param inputWires The {@link File} containing the representation of the circuit's input.
	* @throws FileNotFoundException
	* @throws InvalidInputException
	* @throws NoSuchPartyException
	*/
	void setInputs(scannerpp::File * inputWiresFile, int partyNumber);

	/**
	* Computes the circuit if the input has been set.<p>
	* @return a {@link Map} that maps the output {@link Wire} index to the computed {@link Wire}.
	* @throws NotAllInputsSetException in case there is a party that has no input.
	*/
	map<int, Wire> compute();
	
	/**
	* The verify method tests the circuits for equality returning {@code true} if they are and {@code false}if they are not. <p>
	* In order to be considered equal, {@code Gate}s and {@code Wire}s must be indexed identically and {@code Gate}s must contain
	* the same truth table.
	*
	* @param obj A {@code BooleanCircuit} to be tested for equality to this {@code BooleanCircuit}
	* @return {@code true} if the given {@code BooleanCircuit} is equivalent to this {@code Boolean Circuit}, {@code false} otherwise.
	*/
	bool operator==(const BooleanCircuit &other) const;
	
	/**
	* @return an array of the {@link Gate}s of this circuit.
	*/
	vector<Gate> getGates() const { return gates; };

	/**
	* @return an array of the output{@link Wire} indices of this circuit.
	*/
	vector<int> getOutputWireIndices(int partyNumber) const;

    /**
	* @return an array of the output{@link Wire} indices of this circuit.
	*/
    vector<int> getOutputWireIndices() const;

	/**
	* @param partyNumber The number of the party whose input wires will be returned.
	* @return an ArrayList containing the input {@link Wire} indices of the specified party.
	* @throws NoSuchPartyException if the given party number is less than 1 and greater than the given number of parties.
	*/
	vector<int> getInputWireIndices(int partyNumber) const;

	/**
	* @param partyNumber The number of the party whose number of input wires will be returned.
	* @return the number of input wires for the specified party.
	* @throws NoSuchPartyException if the given party number is less than 1 and greater than the given number of parties.
	*/
	int getNumberOfInputs(int partyNumber) const;
	
	/**
	* Returns the number of parties of this boolean circuit.
	*/
	int getNumberOfParties() { return numberOfParties; };

	void write(string outputFileName);

private:
	/**
	* An array of boolean flags set to {@code true} if and only if the input has been set for the indexed party or the indexed party has no inputs.
	*/
	vector<bool> isInputSet;

	/**
	* A {@code Map} that maps the number of a {@code Wire} to the previously set {@code Wire}.
	* Only {@code Wire}s whose value has been set will be on this map.
	*/
	map<int, Wire> computedWires;

	/**
	* An array of the {@code Gate}s of this {@code BooleanCircuit} sorted topologically.
	*/
	vector<Gate> gates;

	/**
	* An array containing the indices of the output {@code Wire}s of this {@code BooleanCircuit}.
	*/
	vector<vector<int>> eachPartysOutputWires;

	/**
	* The number of parties that are interacting (i.e. receiving input and/or output) with this circuit.
	*/
	int numberOfParties;

	/**
	* An arrayList containing the indices of the input {@code Wire}s of this {@code BooleanCircuit} indexed by the party number.
	*/
	vector<vector<int>> eachPartysInputWires;

	string read(scannerpp::Scanner s);


};
