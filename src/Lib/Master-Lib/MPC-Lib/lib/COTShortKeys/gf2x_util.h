#include <NTL/GF2X.h>
#include <NTL/GF2XFactoring.h>
#include <iostream>
using namespace std;

//#define DEBUG_PRINT

#define MAX 64

class GF2X_Precomputed {
	
	public: 
	
	GF2X_Precomputed() {
		   	NTL::GF2X X = NTL::BuildIrred_GF2X(sizeof(uint64_t)*8);
		   	NTL::GF2X M = X;
		   	for (int i=0; i<MAX;i++) {
		   		precomputed[i] = to_s(M);
				M = M * X;
		   	}
#ifdef DEBUG_PRINT
			cout << "Precomputed X" << hex << endl;
   			for (int i=0; i<MAX;i++) {
				cout << precomputed[i] << " " << endl;
			}
			cout << endl;
#endif
		}
		
		uint64_t & get(int j) {return precomputed[j];}
	
	private:
	
		uint64_t to_s(NTL::GF2X & g) {
			uint64_t tmp;
			//BytesFromGF2X(unsigned char *p, const GF2X& a, long n);
			BytesFromGF2X((unsigned char *)&tmp, g, sizeof(uint64_t));
			return tmp;
		}
			
		uint64_t precomputed[MAX];

};
#ifdef DEBUG_PRINT
	#undef DEBUG_PRINT
#endif