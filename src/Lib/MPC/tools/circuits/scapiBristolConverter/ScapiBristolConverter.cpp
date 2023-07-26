//
// Created by moriya on 11/11/18.
//
#include "CircuitConverter.hpp"

int convert_usage()
{
    auto usage = R"(
To run the circuit converter:
./ScapiBristolConverter <convert_type> [args...]

convert_type can be one of the following:
	* scapi_to_bristol <scapi_file_path> <bristol_file_name> <is_multiparty>
	* bristol_to_scapi <bristol_file_path> <scapi_file_name> <parties_number> <is_multiparty>
				)";
    cerr << usage << endl;
    return 1;
}


int main(int argc, char* argv[]) {

    string convertType(argv[1]);
    bool multi;
    if (convertType == "scapi_to_bristol" && argc == 5) {
        multi = (string(argv[4]) == "false" ? false : true);
        CircuitConverter::convertScapiToBristol(argv[2], argv[3], multi);

    } else if (convertType == "bristol_to_scapi" && argc == 6){
        multi = (string(argv[5]) == "false" ? false : true);
        CircuitConverter::convertBristolToScapi(argv[2], argv[3], stoi(argv[4]), multi);

    }
    else convert_usage();
    return 0;
}