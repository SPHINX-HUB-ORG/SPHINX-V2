//
// Created by moriya on 26/03/17.
//

#ifndef CONVERTSCAPITONEC_CIRCUITCONVERTER_H
#define CONVERTSCAPITONEC_CIRCUITCONVERTER_H
#include <string>
#include "Circuit.h"
using namespace std;

class CircuitConverter {

public:
    static void convertScapiCircuit(string scapiFileName, string newFileName);
};


#endif //CONVERTSCAPITONEC_CIRCUITCONVERTER_H
