#ifndef __TRANSPOSE_H__H___
#define __TRANSPOSE_H__H___

// Programs for computing the transpose of an 8x8 bit matrix.
// Max line length is 57 (sometimes), to fit in hacker.book.
// This has been tested on both AIX/xlc and Windows/gcc, and
// so is believed to be independent of endian mode and whether
// char is by default signed or unsigned.
#include <stdio.h>
#include <string.h>

//#define DEBUG_PRINT

/* This is transpose8r64 but using the GLS method of bit field swapping.
   Instruction counts for the calculation part, for a 64-bit machine:
    6 shifts
    3 ANDs
    9 XORs
    8 Mask generation
   --
   26 total (64-bit machine, recursive method with GLS bit swapping) */


inline void transpose8rS64(unsigned char* A, int m, int j, int n,
                    unsigned char* B) {
   unsigned long long x = 0L, t;
   int i;

   for (i = 0; i <= 7; i++)     // Load 8 bytes from the
      x = x << 8 | A[m*i+j];      // input array and pack
                                // them into x.

   t = (x ^ (x >> 7)) & 0x00AA00AA00AA00AALL;
   x = x ^ t ^ (t << 7);
   t = (x ^ (x >> 14)) & 0x0000CCCC0000CCCCLL;
   x = x ^ t ^ (t << 14);
   t = (x ^ (x >> 28)) & 0x00000000F0F0F0F0LL;
   x = x ^ t ^ (t << 28);

   for (i = 7; i >= 0; i--) {   // Store result into
      B[n*j+i] = x; x = x >> 8;}  // output array B.
}

#include <smmintrin.h>
#include <immintrin.h>

union matrix16x8
{
    __m128i whole;
    octet rows[16];

	void input(byte *input, int m_tag, int j);
    void transpose(uint16_t *output);
};

	
class square16
{
public:
    // 16x16 in two halves, 128 bits each
    matrix16x8 halves[2];

    void input(uint16_t *input, int m_tag, int j);
    void transpose(uint16_t * output, int j);
};

inline void matrix16x8::input(byte *input, int m_tag, int j)
{
    for (int l = 0; l < 16; l++)
        rows[l] = input[l*m_tag+j];
}

inline void square16::input(uint16_t * input,int m_tag, int j)
{
    halves[0].input((byte *)input, m_tag, j);
    halves[1].input((byte *)input, m_tag, j+1);
	
}

inline void matrix16x8::transpose(uint16_t * output)
{
    for (int j = 0; j < 8; j++)
    {
        int row = _mm_movemask_epi8(whole);
        whole = _mm_slli_epi64(whole, 1);
	
        // _mm_movemask_epi8 uses most significant bit, hence +7-j
	   output[j] = row;
    }
}

inline void square16::transpose(uint16_t * output, int j)
{
    halves[0].transpose(output+(16*j));
    halves[1].transpose(output+(16*j)+8);
}

inline void transpose( uint32_t lceil, unsigned char* A, int m_tag, unsigned char* B)
{
	bool set = false;
	
	if (lceil == 8) {
#ifdef DEBUG_PRINT
		cout << "Transpose lceil = " << dec << lceil << endl;
#endif 	
		set = true;
			for (int j = 0; j < m_tag; j++) {
			transpose8rS64 ( A , m_tag , j , 8 ,B);	
		}
	}
	if (lceil == 16) {
#ifdef DEBUG_PRINT
		cout << "Transpose lceil = " << dec << lceil << endl;
#endif 	
		set = true;
		square16 s16; 
		for (int j = 0; j < m_tag/2; j++) {
			s16.input((uint16_t *)A,m_tag,j);
			s16.transpose((uint16_t *)B, j);
		}
			
	}
		
	if (!set) {
		cout << "internal error not transposed ! " << endl;
	}
}

#ifdef DEBUG_PRINT
	#undef DEBUG_PRINT
#endif

#endif