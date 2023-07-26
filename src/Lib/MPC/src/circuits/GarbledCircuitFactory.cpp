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


#include "../../include/circuits/GarbledCircuitFactory.hpp"
#include "../../include/circuits/RowReductionGarbledBooleanCircuit.h"
#include "../../include/circuits/StandardGarbledBooleanCircuit.h"
#include "../../include/circuits/FreeXorGarbledBooleanCircuit.h"
#include "../../include/circuits/HalfGatesGarbledBooleanCircuit.h"
#include "../../include/circuits/HalfGatesGarbledBoleanCircuitNoFixedKey.h"
#include "../../include/circuits/FourToTwoGarbledBoleanCircuitNoAssumptions.h"



GarbledBooleanCircuit* GarbledCircuitFactory::createCircuit(std::string fileName, CircuitType type,bool isNonXorOutputsRequired) {

	// create the fitting circuit type
	switch (type) {
	case CircuitType::FIXED_KEY_FREE_XOR_HALF_GATES:
		return new HalfGatesGarbledBooleanCircuit(fileName.c_str(), isNonXorOutputsRequired);

	case CircuitType::FIXED_KEY_FREE_XOR_ROW_REDUCTION:
		return new RowReductionGarbledBooleanCircuit(fileName.c_str(), isNonXorOutputsRequired);

	case CircuitType::FIXED_KEY_FREE_XOR_STANDARD:
		return new FreeXorGarbledBooleanCircuit(fileName.c_str(), isNonXorOutputsRequired);

	case CircuitType::FIXED_KEY_STANDARD:
		return new StandardGarbledBooleanCircuit(fileName.c_str());

	case CircuitType::NO_FIXED_KEY_FREE_XOR_HALF_GATES:
		return new HalfGatesGarbledBoleanCircuitNoFixedKey(fileName.c_str());

	case CircuitType::NO_FIXED_KEY_FOUR_TO_TWO:
		return new FourToTwoGarbledBoleanCircuitNoAssumptions(fileName.c_str());

	default:
		throw std::invalid_argument("got unknown circuit type");
		break;
	}
}
