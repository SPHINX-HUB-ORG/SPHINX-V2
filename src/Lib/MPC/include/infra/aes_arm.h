#include <stdio.h>
#include <stdint.h>
#include "sse2neon.h"

#define INT_AS_LONGLONG(a) (((long long)a) & 0xFFFFFFFF)

#define LL_SETR_EPI32(a, b) \
    INT_AS_LONGLONG(a) | (INT_AS_LONGLONG(b) << 32)

#define _MM_SETR_EPI32(a0, a1, a2, a3) \
    {LL_SETR_EPI32(a0, a1), LL_SETR_EPI32(a2, a3)} 

#define AES_BLK_SIZE 16

typedef unsigned int uint;
typedef unsigned char octet;
typedef uint8x16_t __mi128;

inline void aes_schedule( uint* RK, octet* K );

__mi128 _mm_aesenc_si128 (__mi128 a, __mi128 RoundKey);
__mi128 _mm_aesenclast_si128 (__mi128 a, __mi128 RoundKey);
__mi128 _mm_aesdec_si128 (__mi128 a, __mi128 RoundKey);
__mi128 _mm_aesdeclast_si128 (__mi128 a,  __mi128 RoundKey);
__mi128 _mm_aeskeygenassist_si128 (__mi128 a, const int imm8);
void enc_key_expansion(__mi128 key, __mi128* key_sched);
void dec_key_expansion(__mi128* enc_key_sched, __mi128* dec_key_sched);
__mi128 aes_encrypt(__mi128 data, __mi128 key);
__mi128 aes_decrypt(__mi128 data, __mi128 key);
void convertToBinary(unsigned int n);

inline __mi128 m128iTomi128(__m128i t);
inline __m128i mi128Tom128i(__mi128 t);
inline __mi128 int128Tomi128(__int128* data);
inline __mi128 uintTomi128(uint* data);
inline __mi128 octetTomi128(octet* data);
