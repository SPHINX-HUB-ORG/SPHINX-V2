#include <stdio.h>
#include <iostream>
#include <string>
#include <chrono>
#include "../../sse/blake2.h"

using namespace std;
int main() {
	int outLen = 64;
	unsigned char out[64];
	string instr = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	const char *in = instr.c_str();
	int inLen = instr.size();
	blake2b_state S[1];
	int res = -1;
	auto s = chrono::system_clock::now();
	for (int i = 0; i < 100000; i++) {
		
		//blake2b_init(S, outLen);
		//blake2b_update(S, (const uint8_t *)in, inLen);
		//blake2b_final(S, out, outLen);
		res = blake2b(out, (unsigned char *)in, nullptr, outLen, inLen, 0);
	}
	auto t = chrono::system_clock::now();
	double elapsed_ms = chrono::duration_cast<std::chrono::microseconds>(t - s).count();
	cout << "***********\n***********\ntotal time: " << elapsed_ms << std::endl;
	printf("res: %d\n", res);
	for (int i = 0; i<64; i++)
		printf("%x ", out[i]);
	printf("\n");
	cout << "ss";
	return 0;
}