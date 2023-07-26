//
// Created by moriya on 11/11/18.
//
#include "CircuitConverter.h"

int convert_usage()
{
    auto usage = R"(
To run the circuit converter:
./ScapiNecConverter scapi_to_nec <scapi_file_path> <nec_file_name>
				)";
    cerr << usage << endl;
    return 1;
}


int main(int argc, char* argv[]) {

    string convertType(argv[1]);
    if (convertType == "scapi_to_nec" && argc == 4) {
        CircuitConverter::convertScapiCircuit(argv[2], argv[3]);

    }
    else convert_usage();
    return 0;
}