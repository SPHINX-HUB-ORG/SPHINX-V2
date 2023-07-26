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


#include "examples_main.hpp"

int exampleUsage()
{
	auto usage = R"(
To run an example:
./libscapi_examples <example_name> [args...]

example_name can one of the following: 
	* dlog
	* sha1
	* comm		  <party_number (1|2)> <config_file_path>
	* yao		  <party_number (1|2)> <config_file_path>
	* sigma		  <party_number (1|2)> <config_file_path>
	* commitment  <party_number (1|2)> <config_file_path>
	* ot  <party_number (1|2)> <config_file_path>
	* OTExtensionBristol <party_number (1|2)> (linux only)
	* OTExtensionLibote <party_number (1|2)>
				)";
	cerr << usage << endl;
	return 1;
}

int main(int argc, char* argv[]) {
	if (argc < 2)
		return exampleUsage();
	string exampleName(argv[1]);
	if (exampleName == "dlog")
		return mainDlog();
	if (exampleName == "sha1")
		return mainSha1();
	if(exampleName=="gmac")
		return mainGmac();
	if (argc == 2)
		return exampleUsage();

	if (argc != 4)
		return exampleUsage();
	if (exampleName == "comm") 
		return mainComm(argv[2], argv[3]);
	if (exampleName == "sigma")
		return mainSigma(argv[2], argv[3]);
	if (exampleName == "commitment")
		return mainCommitment(argv[2], argv[3]);
	if (exampleName == "ot")
		return mainOT(argv[2], argv[3]);

	
	
	return exampleUsage();
}



