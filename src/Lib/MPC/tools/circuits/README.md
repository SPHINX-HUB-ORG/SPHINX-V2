SCAPI CIRCUITS TOOL
--------------------

This directory manage the creation of circuits.
Scapi uses two types of circuits: Boolean circuits and Arythmetic circuits.
The circuits format will be described later in this document.

The directory contains circuit generators along with some converters for various of circuit formats.

Currently, the circuit generator generate a synthetic arythmetic circuit and the supported converters are:
* Bristol format to Scapi format
* Scapi format to Bristol format
* Scapi format to NEC format


BOOLEAN CIRCUITS
----------------
Scapi uses the following format for boolean circuits:

1. number of gates
2. number of parties

for each party:
3. party id (starting from 1 to #parties)
4. number of inputs for this party
5. list of input wires indices of this party

for each party:
6. party id (starting from 1 to #parties)
7. number of output for this party
8. list of output wires indices of this party

[For backward compatibility reasons, we also support additional output management for two-party circuit.
In this case the output is common the both parties and the format should be:
6. number of output wires of the circuit
7. list of output wires of the circuit.]

for each gate:
9. number of input wires of this gate
10. number of output wires of this gate
11. list of input wires indices of this gate
12. list of output wires indices for this gate
13. truth table of this gate.

For example:

    1                   //One gate
    2                   //two parties
    1 1 0               //party one has one input wire labeled "0"
    2 1 1               //party two has one input wire labeled "1"
    1 1                 //party one has one output wire
    2                   //the output wire of party one labeled "2"
    2 0                 //party two has no output wire
    2 1 0 1 2 0001      //the first gate has two input wires, one output wire.
                        //The input wires labeled "0" and "1". The output wire labeled "2".
                        //The truth table of the gate is "0001", which is an AND gate.


ARITHMETIC CIRCUITS
-------------------


The format for arithmetic circuit is very similar to the (multiparty) boolean circuit format.
The only change is that instead of giving the truth table of the circuit, a number indicated the gate type os given.


1. number of gates
2. number of parties

for each party:
3. party id (starting from 1 to #parties)
4. number of inputs for this party
5. list of input wires indices of this party

for each party:
6. party id (starting from 1 to #parties)
7. number of output for this party
8. list of output wires indices of this party

for each gate:
9. number of input wires of this gate
10. number of output wires of this gate
11. list of input wires indices of this gate
12. list of output wires indices for this gate
13. a number indicates the gate. 

Possible gates numbers : 
* 1 - ADD
* 2 - MULTIPLY
* 5 - SCALAR MULTIPLICATION
* 6 - SUBSTRACT

For example:

    1                   //One gate
    2                   //two parties
    1 1 0               //party one has one input wire labeled "0"
    2 1 1               //party two has one input wire labeled "1"
    1 1                 //party one has one output wire
    2                   //the output wire of party one labeled "2"
    2 0                 //party two has no output wire
    2 1 0 1 2 2         //the first gate has two input wires, one output wire.
                        //The input wires labeled "0" and "1". The output wire labeled "2".
                        //The gate is a multiply gate.