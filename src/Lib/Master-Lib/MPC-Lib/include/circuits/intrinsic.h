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

#ifndef AES_KS4X_KS_Y_H
#define AES_KS4X_KS_Y_H

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct KEY_SCHEDULE
	{
		unsigned char KEY[16 * 15];
		unsigned int nr;
	} ROUND_KEYS;
	
	
	void intrin_sequential_ks4_enc8(const unsigned char* PT, unsigned char* CT, int test_length, unsigned char* KEYS, unsigned char* first_key, unsigned char* TEMP_BUF);
	void intrin_sequential_ks2_enc2(const unsigned char* PT, unsigned char* CT, int test_length, unsigned char* KEYS, unsigned char* first_key, unsigned char* TEMP_BUF);
	void intrin_parallel_ks1_enc1(const unsigned char* PT, unsigned char* CT, int test_length, unsigned char* KEYS, unsigned char* first_key, unsigned char* TEMP_BUF);
	void intrin_sequential_ks1_enc1(const unsigned char* PT, unsigned char* CT, int test_length, unsigned char* KEYS, unsigned char* first_key, unsigned char* TEMP_BUF);
	void intrin_sequential_ks4_enc4(const unsigned char* PT, unsigned char* CT, int test_length, unsigned char* KEYS, unsigned char* first_key, unsigned char* TEMP_BUF);



#ifdef __cplusplus
};
#endif
#endif