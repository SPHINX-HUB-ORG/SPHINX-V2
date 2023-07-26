//
// Created by moriya on 26/03/17.
//

#include "CircuitConverter.h"

void CircuitConverter::convertScapiCircuit(string scapiFileName, string necFileName){

    Circuit* circuit = new Circuit();
    circuit->readCircuit(scapiFileName);
    ofstream necFile;
    necFile.open(necFileName);

    int maxWireIndex = circuit->getMaxWireIndex() + 1;
    if (necFile.is_open())
    {
        auto depths = circuit->getDepths();

        //print the number of rounds
        necFile << depths.size() << endl;
        //print the number of gates
        necFile << circuit->getNrOfGates() << endl;
        //print the number of wires

        //Nec protocol requires that the number of inputs and outputs will be a multiplication of 32 (size of int).
        //IOn case that the numbers are not in the required size, qe add dummy indices.
        int alignedInput = ((circuit->getNrOfInput() + 128 - 1) / 128) * 128;
        int alignedOutput = ((circuit->getNrOfOutput() + 128- 1) / 128) * 128;

        necFile << circuit->getNrOfGates() + alignedInput<< endl;
        //print the maximum number of and gates in round
        int max = 0;
        for (size_t i=0; i<depths.size(); i++){
            if (max < depths[i]){
                max = depths[i];
            }
        }
        necFile << max << endl;
        //print the number of input wires (aligned to 32)
        necFile<< alignedInput << endl;
        //print the number of output wires
        necFile << alignedOutput << endl;

        //print the input wires
        for (int i=0; i<circuit->getNrOfParties(); i++){
            auto partyInputs = circuit->getPartyInputs(i);
            for (size_t j=0; j<partyInputs.size(); j++){
                necFile << partyInputs[j] << endl;
            }
        }
        //print dummy input wires
        for (int i=circuit->getNrOfInput(); i<alignedInput; i++){
            necFile << maxWireIndex << endl; //the dummy indices are the indices after the last wire.
            maxWireIndex++;
        }

        int lastOutput;
        //print the output wires
        for (int i=0; i<circuit->getNrOfParties(); i++){
            auto partyOutputs = circuit->getPartyOutputs(i);
            for (size_t j=0; j<partyOutputs.size(); j++){
                necFile << partyOutputs[j] << endl;
                lastOutput = partyOutputs[j];
            }
        }
        cout<<"print dummy"<<endl;
        //print dummy output wires
        for (int i=circuit->getNrOfOutput(); i<alignedOutput; i++){
            necFile << lastOutput << endl; //the dummy indices are the last output wire.
        }
        cout<<"after"<<endl;

        auto gates = circuit->getGates();
        int andGateIndex = 0;
        int depthIndex = 0;
        for (int i=0; i<circuit->getNrOfGates(); i++){
            auto gate = gates[i];
            necFile<<gate.inFan<< " ";
            necFile << gate.outFan<< " ";
            necFile<< gate.inputIndex1 << " ";
            if (gate.inFan == 2){
                necFile << gate.inputIndex2 << " ";
            }
            necFile << gate.outputIndex << " ";

            //In the circuit implementation gate type 6 == XOR
            //                                        12 == NOT
            //                                        1 == AND
            if (gate.gateType == 6){
                necFile<< "1 -1"<<endl;
            } else if (gate.gateType == 12){
                necFile << "3 -1"<<endl;
            } else if (gate.gateType == 1){
                necFile << "2 ";
                necFile << andGateIndex << endl;
                andGateIndex++;
                if (depths[depthIndex] == andGateIndex){
                    necFile << "0 0 0 0 0 0" << endl;
                    depthIndex++;
                    andGateIndex = 0;
                }
            }
        }
    }

    necFile.close();
}