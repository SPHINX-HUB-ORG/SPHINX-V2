/********************************************************************/
/* Copyright(c) 2014, Intel Corp.                                   */
/* Developers and authors: Shay Gueron (1) (2)                      */
/* (1) University of Haifa, Israel                                  */
/* (2) Intel, Israel                                                */
/* IPG, Architecture, Israel Development Center, Haifa, Israel      */
/********************************************************************/


#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
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
	x2 =_mm_shuffle_epi8(keyC, mask); \
	keyC_aux=_mm_aesenclast_si128 (x2, con); \
	KS_BLOCK(2, keyC, keyC_aux);\
	x2 =_mm_shuffle_epi8(keyD, mask); \
	keyD_aux=_mm_aesenclast_si128 (x2, con); \
	KS_BLOCK(3, keyD, keyD_aux);\
	con=_mm_slli_epi32(con, 1);\
	_mm_storeu_si128((__m128i *)(keys[0].KEY+i*16), keyA);\
	_mm_storeu_si128((__m128i *)(keys[1].KEY+i*16), keyB);	\
	_mm_storeu_si128((__m128i *)(keys[2].KEY+i*16), keyC);	\
	_mm_storeu_si128((__m128i *)(keys[3].KEY+i*16), keyD);	\
	}

#define KS_round_last(i) { x2 =_mm_shuffle_epi8(keyA, mask); \
	keyA_aux=_mm_aesenclast_si128 (x2, con); \
	x2 =_mm_shuffle_epi8(keyB, mask); \
	keyB_aux=_mm_aesenclast_si128 (x2, con); \
	x2 =_mm_shuffle_epi8(keyC, mask); \
	keyC_aux=_mm_aesenclast_si128 (x2, con); \
	x2 =_mm_shuffle_epi8(keyD, mask); \
	keyD_aux=_mm_aesenclast_si128 (x2, con); \
	KS_BLOCK(0, keyA, keyA_aux);\
	KS_BLOCK(1, keyB, keyB_aux);\
	KS_BLOCK(2, keyC, keyC_aux);\
	KS_BLOCK(3, keyD, keyD_aux);\
	_mm_storeu_si128((__m128i *)(keys[0].KEY+i*16), keyA);\
	_mm_storeu_si128((__m128i *)(keys[1].KEY+i*16), keyB);	\
	_mm_storeu_si128((__m128i *)(keys[2].KEY+i*16), keyC);	\
	_mm_storeu_si128((__m128i *)(keys[3].KEY+i*16), keyD);	\
	}

#define READ_KEYS(i) {keyA = _mm_loadu_si128((__m128i const*)(keys[0].KEY+i*16));\
	keyB = _mm_loadu_si128((__m128i const*)(keys[1].KEY+i*16));\
	keyC = _mm_loadu_si128((__m128i const*)(keys[2].KEY+i*16));\
	keyD = _mm_loadu_si128((__m128i const*)(keys[3].KEY+i*16));\
	}
	
#define ENC_round(i) {block1=_mm_aesenc_si128(block1, (*(__m128i const*)(keys[0].KEY+i*16))); \
	block2=_mm_aesenc_si128(block2, (*(__m128i const*)(keys[0].KEY+i*16))); \
	block3=_mm_aesenc_si128(block3, (*(__m128i const*)(keys[1].KEY+i*16))); \
	block4=_mm_aesenc_si128(block4, (*(__m128i const*)(keys[1].KEY+i*16))); \
	block5=_mm_aesenc_si128(block5, (*(__m128i const*)(keys[2].KEY+i*16))); \
	block6=_mm_aesenc_si128(block6, (*(__m128i const*)(keys[2].KEY+i*16))); \
	block7=_mm_aesenc_si128(block7, (*(__m128i const*)(keys[3].KEY+i*16))); \
	block8=_mm_aesenc_si128(block8, (*(__m128i const*)(keys[3].KEY+i*16))); \
}	
	
#define ENC_round_last(i) {block1=_mm_aesenclast_si128(block1, (*(__m128i const*)(keys[0].KEY+i*16))); \
	block2=_mm_aesenclast_si128(block2, (*(__m128i const*)(keys[0].KEY+i*16))); \
	block3=_mm_aesenclast_si128(block3, (*(__m128i const*)(keys[1].KEY+i*16))); \
	block4=_mm_aesenclast_si128(block4, (*(__m128i const*)(keys[1].KEY+i*16))); \
	block5=_mm_aesenclast_si128(block5, (*(__m128i const*)(keys[2].KEY+i*16))); \
	block6=_mm_aesenclast_si128(block6, (*(__m128i const*)(keys[2].KEY+i*16))); \
	block7=_mm_aesenclast_si128(block7, (*(__m128i const*)(keys[3].KEY+i*16))); \
	block8=_mm_aesenclast_si128(block8, (*(__m128i const*)(keys[3].KEY+i*16))); \
}
	
void print128_num(__m128i var) 
{
    int64_t *v64val = (int64_t*) &var;
    printf("%.16" PRIu64 "%.16" PRIu64 "\n", v64val[1], v64val[0]);
}

//#pragma intrinsic( _mm_lddqu_si128 )

void intrin_sequential_ks4_enc8(const unsigned char* PT, unsigned char* CT, int test_length, unsigned char* KEYS, unsigned char* first_key, unsigned char* TEMP_BUF){
	
	ROUND_KEYS *keys=(ROUND_KEYS *)KEYS;
    register __m128i keyA, keyB, keyC, keyD, con, mask, x2, keyA_aux, keyB_aux, keyC_aux, keyD_aux, globAux;
	int i;
	int _con1[4]={1,1,1,1};
	int _con2[4]={0x1b,0x1b,0x1b,0x1b};
	int _mask[4]={0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d};
	int _con3[4]={0x0ffffffff, 0x0ffffffff, 0x07060504, 0x07060504};
	__m128i con3=_mm_loadu_si128((__m128i const*)_con3);
	
	for (i=0;i<test_length;i+=4){
		keys[0].nr=10;
		keys[1].nr=10;
		keys[2].nr=10;
		keys[3].nr=10;

		keyA = _mm_loadu_si128((__m128i const*)(first_key));	
		keyB = _mm_loadu_si128((__m128i const*)(first_key+16));	
		keyC = _mm_loadu_si128((__m128i const*)(first_key+32));	
		keyD = _mm_loadu_si128((__m128i const*)(first_key+48));	
	
		_mm_storeu_si128((__m128i *)keys[0].KEY, keyA);	
		_mm_storeu_si128((__m128i *)keys[1].KEY, keyB);	
		_mm_storeu_si128((__m128i *)keys[2].KEY, keyC);	
		_mm_storeu_si128((__m128i *)keys[3].KEY, keyD);	
		
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

		keys+=4;
		first_key+=64;
	}	
	
	keys=(ROUND_KEYS *)KEYS;
	
	for (i=0;i<test_length;i+=4){
		register __m128i block1 = _mm_loadu_si128((__m128i const*)(0*16+PT));	
		register __m128i block2 = _mm_loadu_si128((__m128i const*)(1*16+PT));	
		register __m128i block3 = _mm_loadu_si128((__m128i const*)(2*16+PT));	
		register __m128i block4 = _mm_loadu_si128((__m128i const*)(3*16+PT));	
		register __m128i block5 = _mm_loadu_si128((__m128i const*)(4*16+PT));	
		register __m128i block6 = _mm_loadu_si128((__m128i const*)(5*16+PT));	
		register __m128i block7 = _mm_loadu_si128((__m128i const*)(6*16+PT));	
		register __m128i block8 = _mm_loadu_si128((__m128i const*)(7*16+PT));	
			
		READ_KEYS(0)
		
		block1 = _mm_xor_si128(keyA, block1);
		block2 = _mm_xor_si128(keyA, block2);
		block3 = _mm_xor_si128(keyB, block3);
		block4 = _mm_xor_si128(keyB, block4);
		block5 = _mm_xor_si128(keyC, block5);
		block6 = _mm_xor_si128(keyC, block6);
		block7 = _mm_xor_si128(keyD, block7);
		block8 = _mm_xor_si128(keyD, block8);
		
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
		_mm_storeu_si128((__m128i *)(CT+2*16), block3);	
		_mm_storeu_si128((__m128i *)(CT+3*16), block4);	
		_mm_storeu_si128((__m128i *)(CT+4*16), block5);	
		_mm_storeu_si128((__m128i *)(CT+5*16), block6);	
		_mm_storeu_si128((__m128i *)(CT+6*16), block7);	
		_mm_storeu_si128((__m128i *)(CT+7*16), block8);	
		
		PT+=128;
		CT+=128;
		
		keys+=4;
		
	}
}

