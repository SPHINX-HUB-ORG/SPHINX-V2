/********************************************************************/
/* Copyright(c) 2014, Intel Corp.                                   */
/* Developers and authors: Shay Gueron (1) (2)                      */
/* (1) University of Haifa, Israel                                  */
/* (2) Intel, Israel                                                */
/* IPG, Architecture, Israel Development Center, Haifa, Israel      */
/********************************************************************/

#include <stdint.h>
#include <stdio.h>
#ifdef __x86_64__
#include <wmmintrin.h>
# include <emmintrin.h>
# include <smmintrin.h>
#elif __aarch64__
#include "../../include/infra/sse2neon.h"
#include "../../include/infra/aes_arm.h"
#endif


#if !defined (ALIGN16)
#if defined (__GNUC__)
#  define ALIGN16  __attribute__  ( (aligned (16)))
# else
#  define ALIGN16 __declspec (align (16))
# endif
#endif

typedef struct KEY_SCHEDULE
{
   ALIGN16 unsigned char KEY[16*15];
   unsigned int nr;
} ROUND_KEYS; 


#define KS_BLOCK(t, reg, reg2) {globAux=_mm_slli_epi64(reg, 32);\
								reg=_mm_xor_si128(globAux, reg);\
								globAux=_mm_shuffle_epi8(reg, con3);\
								reg=_mm_xor_si128(globAux, reg);\
								reg=_mm_xor_si128(reg2, reg);\
								}

#define KS_round(i) { x2 =_mm_shuffle_epi8(keyA, mask); \
	keyA_aux=_mm_aesenclast_si128 (x2, con); \
	KS_BLOCK(0, keyA, keyA_aux);\
	x2 =_mm_shuffle_epi8(keyB, mask); \
	keyB_aux=_mm_aesenclast_si128 (x2, con); \
	KS_BLOCK(1, keyB, keyB_aux);\
	con=_mm_slli_epi32(con, 1);\
	_mm_storeu_si128((__m128i *)(keys[0].KEY+i*16), keyA);\
	_mm_storeu_si128((__m128i *)(keys[1].KEY+i*16), keyB);	\
	}

#define KS_round_last(i) { x2 =_mm_shuffle_epi8(keyA, mask); \
	keyA_aux=_mm_aesenclast_si128 (x2, con); \
	x2 =_mm_shuffle_epi8(keyB, mask); \
	keyB_aux=_mm_aesenclast_si128 (x2, con); \
	KS_BLOCK(0, keyA, keyA_aux);\
	KS_BLOCK(1, keyB, keyB_aux);\
	_mm_storeu_si128((__m128i *)(keys[0].KEY+i*16), keyA);\
	_mm_storeu_si128((__m128i *)(keys[1].KEY+i*16), keyB);	\
	}

#define READ_KEYS(i) {keyA = _mm_loadu_si128((__m128i const*)(keys[0].KEY+i*16));\
	keyB = _mm_loadu_si128((__m128i const*)(keys[1].KEY+i*16));\
	}
	
#define ENC_round(i) {block1=_mm_aesenc_si128(block1, (*(__m128i const*)(keys[0].KEY+i*16))); \
	block2=_mm_aesenc_si128(block2, (*(__m128i const*)(keys[1].KEY+i*16))); \
}	
	
#define ENC_round_last(i) {block1=_mm_aesenclast_si128(block1, (*(__m128i const*)(keys[0].KEY+i*16))); \
	block2=_mm_aesenclast_si128(block2, (*(__m128i const*)(keys[1].KEY+i*16))); \
}
	

//#pragma intrinsic( _mm_lddqu_si128 )

void intrin_sequential_ks2_enc2(const unsigned char* PT, unsigned char* CT, int test_length, unsigned char* KEYS, unsigned char* first_key, unsigned char* TEMP_BUF){
	
	ROUND_KEYS *keys=(ROUND_KEYS *)KEYS;
    register __m128i keyA, keyB, con, mask, x2, keyA_aux, keyB_aux, globAux;
	int i;
	int _con1[4]={1,1,1,1};
	int _con2[4]={0x1b,0x1b,0x1b,0x1b};
	int _mask[4]={0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d};
	int _con3[4]={0x0ffffffff, 0x0ffffffff, 0x07060504, 0x07060504};
	__m128i con3=_mm_loadu_si128((__m128i const*)_con3);
	
	for (i=0;i<test_length;i+=2){
		keys[0].nr=10;
		keys[1].nr=10;

		keyA = _mm_loadu_si128((__m128i const*)(first_key));	
		keyB = _mm_loadu_si128((__m128i const*)(first_key+16));	
	
		_mm_storeu_si128((__m128i *)keys[0].KEY, keyA);	
		_mm_storeu_si128((__m128i *)keys[1].KEY, keyB);	
		
		con = _mm_loadu_si128((__m128i const*)_con1);	
		mask = _mm_loadu_si128((__m128i const*)_mask);	
		
		KS_round(1)
		KS_round(2)
		KS_round(3)
		KS_round(4)
		KS_round(5)
		KS_round(6)
		KS_round(7)
		KS_round(8)

		con = _mm_loadu_si128((__m128i const*)_con2);			

		KS_round(9)
		KS_round_last(10)

		keys+=2;
		first_key+=32;
	}	
	
	keys=(ROUND_KEYS *)KEYS;
	
	for (i=0;i<test_length;i+=2){
		register __m128i block1 = _mm_loadu_si128((__m128i const*)(0*16+PT));	
		register __m128i block2 = _mm_loadu_si128((__m128i const*)(1*16+PT));	
			
		READ_KEYS(0)
		
		block1 = _mm_xor_si128(keyA, block1);
		block2 = _mm_xor_si128(keyB, block2);
		
		ENC_round(1)
		ENC_round(2)
		ENC_round(3)
		ENC_round(4)
		ENC_round(5)
		ENC_round(6)
		ENC_round(7)
		ENC_round(8)
		ENC_round(9)
		ENC_round_last(10)
		
		_mm_storeu_si128((__m128i *)(CT+0*16), block1);	
		_mm_storeu_si128((__m128i *)(CT+1*16), block2);	
		
		PT+=32;
		CT+=32;
		
		keys+=2;
		
	}
}
