//
// Created by moriya on 01/10/17.
//

#ifndef LIBSCAPI_MERSENNE_H
#define LIBSCAPI_MERSENNE_H

#include "NTL/ZZ_p.h"
#include "NTL/ZZ.h"
#ifdef __x86_64__
#include <x86intrin.h>
#elif __aarch64__
#include "../infra/sse2neon.h"
#endif
#include <gmp.h>
#include "Prg.hpp"

using namespace std;
using namespace NTL;

class ZpMersenneIntElement {

//private:
public: //TODO return to private after tesing

    static const unsigned int p = 2147483647;
    unsigned int elem;

public:

    ZpMersenneIntElement(){elem = 0;};
    ZpMersenneIntElement(long elem)
    {
        if(elem<2*p) {
            this->elem = elem;
            if (this->elem < p) {
                return;
            }
            this->elem -= p;
            return;
        }
        else{
            //get the bottom 31 bit
            unsigned int bottom = elem & p;

            //get the top 31 bits
            unsigned int top = (elem>>31);

            this->elem = bottom + top;

            //maximim the value of 2p-2
            if(this->elem>=p)
                this->elem-=p;
        }
    }



    ZpMersenneIntElement& operator=(const ZpMersenneIntElement& other){elem = other.elem; return *this;};
    bool operator!=(const ZpMersenneIntElement& other){ return !(other.elem == elem); };
    bool operator==(const ZpMersenneIntElement& other){ return other.elem == elem; };

    ZpMersenneIntElement operator+(const ZpMersenneIntElement& f2)
    {
        ZpMersenneIntElement answer;

        answer.elem = (elem + f2.elem);

        if(answer.elem>=p)
            answer.elem-=p;

        return answer;
    }
    ZpMersenneIntElement operator-(const ZpMersenneIntElement& f2)
    {
        ZpMersenneIntElement answer;

        int temp =  (int)elem - (int)f2.elem;

        if(temp<0){
            answer.elem = temp + p;
        }
        else{
            answer.elem = temp;
        }

        return answer;
    }
    ZpMersenneIntElement operator/(const ZpMersenneIntElement& f2)
    {
        //code taken from NTL for the function XGCD
        int a = f2.elem;
        int b = p;
        long s;

        int  u, v, q, r;
        long u0, v0, u1, v1, u2, v2;

        int aneg = 0;

        if (a < 0) {
            if (a < -NTL_MAX_LONG) Error("XGCD: integer overflow");
            a = -a;
            aneg = 1;
        }

        if (b < 0) {
            if (b < -NTL_MAX_LONG) Error("XGCD: integer overflow");
            b = -b;
        }

        u1=1; v1=0;
        u2=0; v2=1;
        u = a; v = b;

        while (v != 0) {
            q = u / v;
            r = u % v;
            u = v;
            v = r;
            u0 = u2;
            v0 = v2;
            u2 =  u1 - q*u2;
            v2 = v1- q*v2;
            u1 = u0;
            v1 = v0;
        }

        if (aneg)
            u1 = -u1;


        s = u1;

        if (s < 0)
            s =  s + p;

        ZpMersenneIntElement inverse(s);

        return inverse* (*this);
    }

    ZpMersenneIntElement operator*(const ZpMersenneIntElement& f2)
    {
        ZpMersenneIntElement answer;

        long multLong = (long)elem * (long) f2.elem;

        //get the bottom 31 bit
        unsigned int bottom = multLong & p;

        //get the top 31 bits
        unsigned int top = (multLong>>31);

        answer.elem = bottom + top;

        //maximim the value of 2p-2
        if(answer.elem>=p)
            answer.elem-=p;

        //return ZpMersenneIntElement((bottom + top) %p);
        return answer;
    }

    ZpMersenneIntElement& operator+=(const ZpMersenneIntElement& f2){
        elem = (f2.elem + elem);

        if(elem>=p)
            elem-=p;

        return *this;
    };
    ZpMersenneIntElement& operator*=(const ZpMersenneIntElement& f2)
    {
        long multLong = (long)elem * (long) f2.elem;

        //get the bottom 31 bit
        unsigned int bottom = multLong & p;

        //get the top 31 bits
        unsigned int top = (multLong>>31) ;

        elem = bottom + top;

        //maximim the value of 2p-2
        if(elem>=p)
            elem-=p;

        return *this;
    }

    ZpMersenneIntElement sqrt()
    {
        //The algorithm for checking the square root of a value is as follows:
        //We know that 2^31 and 2^61 are both divisible by 4 (the results are 2^29 and 2^59 respectively). So 2^31-1=3 mod 4 and 2^61-1=3 mod 4.
        //So if we have b=x^2 (over Mersenne61) then we can compute x by b^{2^59}.
        //To do this, we can make about 58 field multiplications:
        //Set b_1 = b, then
        //For i=2...59:
        //compute b_i = (b_{i-1})^2.
        //So x1=b_59 and x2=-b_59 = 2^61-1-b_59
        //Check that x1^2 = b, if it does then output it, otherwise, it means that a cheat is detected.
        ZpMersenneIntElement answer = *this;
        for (int i=2; i<=30; i++){
            answer *= answer;
        }
        ZpMersenneIntElement check = answer*answer;

        if (check != *this){
            cout<<"CHEATING!!!"<<endl;
            return ZpMersenneIntElement(0);
        }

        return answer;
    }

};

inline ::ostream& operator<<(::ostream& s, const ZpMersenneIntElement& a){ return s << a.elem; };


#ifdef __x86_64__
class ZpMersenneLongElement {

//private:
public: //TODO return to private after tesing

    static const unsigned long p = 2305843009213693951;
    unsigned long elem;

public:

    ZpMersenneLongElement(){elem = 0;};
    ZpMersenneLongElement(unsigned long elem)
    {
        this->elem = elem;
        if(this->elem>=p){

            this->elem = (this->elem & p) + (this->elem>>61);

            if(this->elem >= p)
                this->elem-= p;

        }
    }

    inline ZpMersenneLongElement& operator=(const ZpMersenneLongElement& other)

    {elem = other.elem; return *this;};
    bool operator!=(const ZpMersenneLongElement& other){ return !(other.elem == elem); };
    bool operator==(const ZpMersenneLongElement& other){ return other.elem == elem; };

    ZpMersenneLongElement operator+(const ZpMersenneLongElement& f2)
    {
        ZpMersenneLongElement answer;

        answer.elem = (elem + f2.elem);

        if(answer.elem>=p)
            answer.elem-=p;

        return answer;
    }

    ZpMersenneLongElement operator-(const ZpMersenneLongElement& f2)
    {
        ZpMersenneLongElement answer;

        long temp =  (long)elem - (long)f2.elem;

        if(temp<0){
            answer.elem = temp + p;
        }
        else{
            answer.elem = temp;
        }

        return answer;
    }

    ZpMersenneLongElement operator/(const ZpMersenneLongElement& f2)
    {
        ZpMersenneLongElement answer;
        mpz_t d;
        mpz_t result;
        mpz_t mpz_elem;
        mpz_t mpz_me;
        mpz_init_set_str (d, "2305843009213693951", 10);
        mpz_init(mpz_elem);
        mpz_init(mpz_me);

        mpz_set_ui(mpz_elem, f2.elem);
        mpz_set_ui(mpz_me, elem);

        mpz_init(result);

        mpz_invert ( result, mpz_elem, d );

        mpz_mul (result, result, mpz_me);
        mpz_mod (result, result, d);


        answer.elem = mpz_get_ui(result);

        return answer;
    }

    ZpMersenneLongElement operator*(const ZpMersenneLongElement& f2)
    {
        ZpMersenneLongElement answer;

        unsigned long long high;
        unsigned long low = _mulx_u64(elem, f2.elem, &high);


        unsigned long low61 = (low & p);
        unsigned long low62to64 = (low>>61);
        unsigned long highShift3 = (high<<3);

        unsigned long res = low61 + low62to64 + highShift3;

        if(res >= p)
            res-= p;

        answer.elem = res;

        return answer;
    }

    ZpMersenneLongElement& operator+=(const ZpMersenneLongElement& f2)
    {
        elem = (elem + f2.elem);

        if(elem>=p)
            elem-=p;

        return *this;
    }

    ZpMersenneLongElement& operator*=(const ZpMersenneLongElement& f2)
    {
        unsigned long long high;
        unsigned long low = _mulx_u64(elem, f2.elem, &high);


        unsigned long low61 = (low & p);
        unsigned long low61to64 = (low>>61);
        unsigned long highShift3 = (high<<3);

        unsigned long res = low61 + low61to64 + highShift3;

        if(res >= p)
            res-= p;

        elem = res;

        return *this;
    }

    ZpMersenneLongElement sqrt()
    {
        //The algorithm for checking the square root of a value is as follows:
        //We know that 2^31 and 2^61 are both divisible by 4 (the results are 2^29 and 2^59 respectively). So 2^31-1=3 mod 4 and 2^61-1=3 mod 4.
        //So if we have b=x^2 (over Mersenne61) then we can compute x by b^{2^59}.
        //To do this, we can make about 58 field multiplications:
        //Set b_1 = b, then
        //For i=2...59:
        //compute b_i = (b_{i-1})^2.
        //So x1=b_59 and x2=-b_59 = 2^61-1-b_59
        //Check that x1^2 = b, if it does then output it, otherwise, it means that a cheat is detected.
        ZpMersenneLongElement answer = *this;
        for (int i=2; i<=60; i++){
            answer *= answer;
        }
        ZpMersenneLongElement check = answer*answer;

        if (check != *this){
            cout<<"CHEATING!!!"<<endl;
            return ZpMersenneLongElement(0);
        }

        return answer;
    }

};

inline ::ostream& operator<<(::ostream& s, const ZpMersenneLongElement& a){ return s << a.elem; };

//----------------------------------

class ZpMersenne127Element {

//private:
public: //TODO return to private after tesing

    //we use gcc 5.4 supported uint 128 bit type
    __uint128_t elem;
    static __uint128_t p;
    //the prime is 2^127-1

public:


    //as c++ does not support 127 digits in a const, currently we need to call init() on the class
    //to initialize p; TBD improve this
    void static init() {
        p = 0;
        uint64_t *p64 = (uint64_t*)&p;
        p64[1] = 0x8000000000000000;

        p-=1;
    }

    ZpMersenne127Element(){elem = 0;};
    ZpMersenne127Element(__uint128_t e)
    {
        this->elem = e;
        if(this->elem>=p){

            this->elem-= p;
        }
    }

    inline ZpMersenne127Element& operator=(const ZpMersenne127Element& other){
        elem = other.elem;
        return *this;
    }
    inline bool operator!=(const ZpMersenne127Element& other)

    { return !(other.elem == elem); };

    inline bool operator==(const ZpMersenne127Element& other)

    { return other.elem == elem; };

    ZpMersenne127Element operator+(const ZpMersenne127Element& f2)
    {
        ZpMersenne127Element answer;
        answer.elem = (elem + f2.elem);
        if(answer.elem>=p)
            answer.elem-=p;
        return answer;
    }

    ZpMersenne127Element operator-(const ZpMersenne127Element& f2)
    {
        ZpMersenne127Element answer;
        __int128_t temp =  (__int128_t)elem - (__int128_t)f2.elem;
        if(temp<0){
            answer.elem = temp + p;
        }
        else{
            answer.elem = temp;
        }
        return answer;
    }

    ZpMersenne127Element operator/(const ZpMersenne127Element& f2)
    {
        mp_limb_t* me = (mp_limb_t *) &elem;

        auto f2Eleme = f2.elem;
        mp_limb_t* elemOff2 = (mp_limb_t *) &(f2Eleme); //keep same naming convention as other ZpMersenne classes
        mp_limb_t *d = (mp_limb_t *) &p; //d is actually p
        mp_limb_t result_1[2]; //result is used a few times. we do not allow override in low-level, so more vars.
        mp_limb_t result_2[4]; //result of mult is 256 bits (limb is 64 bit)
        __uint128_t res;

        mp_limb_t tp[16]; //scratch space for invert
        mpn_sec_invert (result_1, elemOff2, d, 2, 256, tp);
        mpn_mul (result_2, result_1, 2,me, 2);

        mp_limb_t q[4];
        mpn_tdiv_qr (q, 				//quotent - not used
                     (mp_limb_t *)&res, //remainder
                     0, 				//nuat be 0
                     result_2,			//
                     4,
                     d,					//mod divisor (d == p)
                     2);

        return ZpMersenne127Element(res);
    }

    ZpMersenne127Element operator*(const ZpMersenne127Element& f2)
    {
        unsigned long long m64[4];

        //do four mults
        unsigned long long* me = (unsigned long long*)&elem;
        unsigned long long* other = (unsigned long long*)&f2.elem;

        unsigned long long high00;
        unsigned long low00 = _mulx_u64(me[0], other[0], &high00);

        unsigned long long high01;
        unsigned long low01 = _mulx_u64(me[0], other[1], &high01);

        unsigned long long high10;
        unsigned long low10 = _mulx_u64(me[1], other[0], &high10);

        unsigned long long high11;
        unsigned long low11 = _mulx_u64(me[1], other[1], &high11);

        m64[0] = low00;

        unsigned char c1 = 0, c2 = 0;
        c1 = _addcarry_u64(c1, high00, low01, &m64[1]);
        c2 = _addcarry_u64(c2, m64[1], low10, &m64[1]);
        //m64[1] = high00+low01+low10;
        //m64[2] = high01 + high10 + low11 + c1 +c2;
        //c1=c2=0;
        c1 = _addcarry_u64(c1, high01, high10, &m64[2]);
        c2 = _addcarry_u64(c2, m64[2], low11, &m64[2]);

        m64[3] = high11+c1+c2;

        __uint128_t *m128 = (__uint128_t *) &m64;

        // mpn_mul ( (mp_limb_t *)m128, (mp_limb_t *)&elem, 2,	(mp_limb_t *)&(f2.elem), 2);
        __uint128_t res, low, low128bit, highShift1;

        low = (m128[0] & p);
        low128bit = (m128[0]>>127);
        highShift1 = (m128[1]<<1);
        res = low + low128bit + highShift1;

        return ZpMersenne127Element(res);
    }

    ZpMersenne127Element& operator+=(const ZpMersenne127Element& f2)
    {
        elem = (elem + f2.elem);

        if(elem>=p)
            elem-=p;

        return *this;
    }

    ZpMersenne127Element& operator*=(const ZpMersenne127Element& f2)
    {
        return *this = *this * f2;
    }

};

inline ::ostream& operator<<(::ostream& s, const ZpMersenne127Element& a){

    const uint64_t* abytes = (uint64_t *)&a;
    return s<< abytes[1] << " "  << abytes[0] << endl;
    };

#endif
//------------------------------------------



template <class FieldType>
class TemplateField {
private:

    PrgFromOpenSSLAES prg;
    long fieldParam;
    int elementSizeInBytes;
    int elementSizeInBits;
    FieldType* m_ZERO;
    FieldType* m_ONE;
public:


    /**
     * the function create a field by:
     * generate the irreducible polynomial x^8 + x^4 + x^3 + x + 1 to work with
     * init the field with the newly generated polynomial
     */
    TemplateField(long fieldParam);

    /**
     * return the field
     */

    string elementToString(const FieldType &element);
    FieldType stringToElement(const string &str);


    void elementToBytes(unsigned char* output,FieldType &element);

    FieldType bytesToElement(unsigned char* elemenetInBytes);
    void elementVectorToByteVector(vector<FieldType> &elementVector, vector<byte> &byteVector);

    FieldType* GetZero();
    FieldType* GetOne();

    int getElementSizeInBytes(){ return elementSizeInBytes;}
    int getElementSizeInBits(){ return elementSizeInBits;}
    /*
     * The i-th field element. The ordering is arbitrary, *except* that
     * the 0-th field element must be the neutral w.r.t. addition, and the
     * 1-st field element must be the neutral w.r.t. multiplication.
     */
    FieldType GetElement(long b);
    FieldType Random();
    ~TemplateField();

};

template <class FieldType>
string TemplateField<FieldType>::elementToString(const FieldType& element)
{
    ostringstream stream;
    stream << element;
    string str =  stream.str();
    return str;
}


template <class FieldType>
FieldType TemplateField<FieldType>::stringToElement(const string &str) {

    FieldType element;

    istringstream iss(str);
    iss >> element;

    return element;
}



/**
 * A random random field element, uniform distribution
 */
template <class FieldType>
FieldType TemplateField<FieldType>::Random() {
    unsigned long b;
    if(elementSizeInBytes<=4)
        b = prg.getRandom32();
    else
        b = prg.getRandom64()>>(64-elementSizeInBits);

    return GetElement(b);
}

template <class FieldType>
FieldType* TemplateField<FieldType>::GetZero()
{
    return m_ZERO;
}

template <class FieldType>
FieldType* TemplateField<FieldType>::GetOne()
{
    return m_ONE;
}


template <class FieldType>
TemplateField<FieldType>::~TemplateField() {
    delete m_ZERO;
    delete m_ONE;
}



#endif //LIBSCAPI_MERSSENE_H
