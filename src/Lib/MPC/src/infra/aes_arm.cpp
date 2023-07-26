#ifdef __aarch64
#include "../../include/infra/aes_arm.h"

inline void aes_schedule( uint* RK, octet* K )
{ *RK = 0; *K = 0; }
inline void aes_encrypt( octet* C, octet* M, uint* RK )
{ *C = 0; *M = 0; *RK = 0; }

__mi128 _mm_aesenc_si128 (__mi128 a, __mi128 RoundKey)
{
    __mi128 cipher = vaesmcq_u8(vaeseq_u8(a, (__mi128){})) ^ RoundKey;
    return cipher;
}

__mi128 _mm_aesenclast_si128 (__mi128 a, __mi128 RoundKey)
{
	return vaeseq_u8(a, (__mi128){}) ^ RoundKey;
}

__mi128 _mm_aesdec_si128 (__mi128 a, __mi128 RoundKey)
{
	return vaesimcq_u8(vaesdq_u8(a, (__mi128){})) ^ RoundKey;
}

__mi128 _mm_aesdeclast_si128 (__mi128 a,  __mi128 RoundKey)
{
    return vaesdq_u8(a, (__mi128){}) ^ RoundKey;
}

__mi128 _mm_aeskeygenassist_si128 (__mi128 a, const int imm8)
{
	a = vaeseq_u8(a, (__mi128){});
    __mi128 dest = {
        a[0x4], a[0x1], a[0xE], a[0xB], // SubBytes(X1)
        a[0x1], a[0xE], a[0xB], a[0x4], // ROT(SubBytes(X1))
        a[0xC], a[0x9], a[0x6], a[0x3], // SubBytes(X3)
        a[0x9], a[0x6], a[0x3], a[0xC], // ROT(SubBytes(X3))
    };
    const uint32_t rcon = imm8 & 255;
    return dest ^ (__mi128)((uint32x4_t){0, rcon, 0, rcon});
}

void enc_key_expansion(__mi128 key, __mi128* key_sched) {
    key_sched[0] = key; 
    unsigned int imm = 1;
    for (int r = 1; r<=10; r++) {
        if (r==9) imm = 27;
        key_sched[r] = _mm_aeskeygenassist_si128(key_sched[r-1], imm);
        imm <<= 1;
    }
}

void dec_key_expansion(__mi128* enc_key_sched, __mi128* dec_key_sched) {
    dec_key_sched[0] = enc_key_sched[0]; 
    for (int r = 1; r<10; r++) {
        dec_key_sched[r] = vaesimcq_u8(enc_key_sched[r]); 
    }
    dec_key_sched[10] = enc_key_sched[10]; 
}

__mi128 aes_encrypt(__mi128 data, __mi128 key) {
    __mi128 key_sched[11];
    enc_key_expansion(key, key_sched);
    data ^= key_sched[0];
    for (int r=1; r<=9; r++) {
        data = _mm_aesenc_si128(data, key_sched[r]);
    }
    data = _mm_aesenclast_si128(data, key_sched[10]);
    return data;
}

__mi128 aes_decrypt(__mi128 data, __mi128 key) {
    __mi128 enc_key_sched[11];
    __mi128 dec_key_sched[11];
    enc_key_expansion(key, enc_key_sched);
    dec_key_expansion(enc_key_sched, dec_key_sched);
    data ^= dec_key_sched[10];
    for (int r=9; r>=1; r--) {
        data = _mm_aesdec_si128(data, dec_key_sched[r]);
    }
    data = _mm_aesdeclast_si128(data, dec_key_sched[0]);
    return data;
}


void convertToBinary(unsigned int n)
{
    if (n / 2 != 0) {
        convertToBinary(n / 2);
    }
    printf("%d", n % 2);
}

inline __mi128 m128iTomi128(__m128i t)
{
    __mi128 res;
    res[0] = t[0];
    res[4] = t[1];
    res[8] = t[2];
    res[12] = t[3];

    return res;
}

inline __m128i mi128Tom128i(__mi128 t)
{
    __m128i res;
    res[0] = t[0];
    res[1] = t[4];
    res[2] = t[8];
    res[3] = t[12];

    return res;
}


inline __mi128 int128Tomi128(__int128* data)
{
	__mi128 res;
    res[0] = data[0];
    res[8] = data[1];
    res[16] = data[2];
    res[24] = data[3];
    res[32] = data[4];
    res[40] = data[5];
    res[48] = data[6];
    res[56] = data[7];
    res[64] = data[8];
    res[72] = data[9];
    res[80] = data[10];
    res[88] = data[11];
    res[96] = data[12];
    res[104] = data[13];
    res[112] = data[14];
    res[120] = data[15];
    
    return res;
}

inline __mi128 uintTomi128(uint* data)
{
	__mi128 res;
    res[0] = data[0];
    res[8] = data[1];
    res[16] = data[2];
    res[24] = data[3];
    res[32] = data[4];
    res[40] = data[5];
    res[48] = data[6];
    res[56] = data[7];
    res[64] = data[8];
    res[72] = data[9];
    res[80] = data[10];
    res[88] = data[11];
    res[96] = data[12];
    res[104] = data[13];
    res[112] = data[14];
    res[120] = data[15];
    
    return res;
}

inline __mi128 octetTomi128(octet* data)
{
	__mi128 res;
    res[0] = data[0];
    res[8] = data[1];
    res[16] = data[2];
    res[24] = data[3];
    res[32] = data[4];
    res[40] = data[5];
    res[48] = data[6];
    res[56] = data[7];
    res[64] = data[8];
    res[72] = data[9];
    res[80] = data[10];
    res[88] = data[11];
    res[96] = data[12];
    res[104] = data[13];
    res[112] = data[14];
    res[120] = data[15];
    
    return res;
}

#endif