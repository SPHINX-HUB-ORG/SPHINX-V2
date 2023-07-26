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


#ifndef TESTS
#define TESTS

#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file

#include "../include/infra/Common.hpp"
#include "../include/infra/ConfigFile.hpp"
#include "catch.hpp"
#include "../include/primitives/Dlog.hpp"
#include "../include/primitives/DlogOpenSSL.hpp"
#include "../include/primitives/HashOpenSSL.hpp"
#include "../include/primitives/PrfOpenSSL.hpp"
#include "../include/primitives/TrapdoorPermutationOpenSSL.hpp"
#include "../include/primitives/Prg.hpp"
#include "../include/primitives/Kdf.hpp"
#include "../include/primitives/RandomOracle.hpp"
#include "../include/comm/Comm.hpp"
#include "../include/circuits/BooleanCircuits.hpp"
#include "../include/interactive_mid_protocols/CommitmentSchemePedersen.hpp"
#include "../include/mid_layer/OpenSSLSymmetricEnc.hpp"
#include "../include/mid_layer/AsymmetricEnc.hpp"
#include "../include/mid_layer/ElGamalEnc.hpp"
#include "../include/mid_layer/CramerShoupEnc.hpp"
#include "../include/mid_layer/DamgardJurikEnc.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocol.hpp"
#include "../include/primitives/Mersenne.hpp"
#include <ctype.h>
#ifdef __x86_64__
#include <smmintrin.h>
#elif __aarch64__
#include "../include/infra/sse2neon.h"
#endif


biginteger endcode_decode(biginteger bi) {
	auto s = bi.str();
	s.c_str();
	return biginteger(s);
}

string rsa100 = "1522605027922533360535618378132637429718068114961380688657908494580122963258952897654000350692006139";
string xx = "12796996813601383763849798056730343283682939747202100943566894545802445831004";

TEST_CASE("Common methods", "[boost, common, math, log, bitLength, helper]") {

	SECTION("find_log2_floor") {
		REQUIRE(find_log2_floor(16) == 4);
		REQUIRE(find_log2_floor(19) == 4);
		REQUIRE(find_log2_floor(31) == 4);
		REQUIRE(find_log2_floor(32) == 5);
		REQUIRE(find_log2_floor(39) == 5);
	}

	SECTION("bitlength and byteLength")
	{
		REQUIRE(NumberOfBits(64) == 7);
		REQUIRE(bytesCount(64) == 1);
		REQUIRE(NumberOfBits(9999) == 14);
		REQUIRE(bytesCount(9999) == 2);
		REQUIRE(NumberOfBits(biginteger(rsa100))== 330);
		REQUIRE(bytesCount(biginteger(rsa100)) == 42);
		REQUIRE(NumberOfBits(-biginteger(rsa100)) == 330);
		REQUIRE(bytesCount(-biginteger(rsa100)) == 42);
	}

	SECTION("gen_random_bytes_vector")
	{
		vector<byte> v, v2;
		auto prg = get_seeded_prg();
		gen_random_bytes_vector(v, 10, prg.get());
		gen_random_bytes_vector(v2, 10, prg.get());
		REQUIRE(v.size() == 10);
		for (byte b : v)
			REQUIRE(isalnum(b));
		string string1(v.begin(), v.end());
		string string2(v2.begin(), v2.end());
		REQUIRE(string1 != string2);
	}

	SECTION("copy byte vector to byte array")
	{
		vector<byte> v;
		auto prg = get_seeded_prg();
		gen_random_bytes_vector(v, 20, prg.get());
		byte * vb = new byte[40];
		int index;
		copy_byte_vector_to_byte_array(v, vb, 0);
		copy_byte_vector_to_byte_array(v, vb, 20);
		for (auto it = v.begin(); it != v.end(); it++)
		{
			index = it - v.begin();
			REQUIRE(*it == vb[index]);
			REQUIRE(*it == vb[index+20]);
		}
		delete vb;
	}


	SECTION("copy byte array to byte vector")
	{
		
		byte src[10] = { 0xb1, 0xb2, 0xb3, 0xb4,  0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xc1 };
		vector<byte> target;
		copy_byte_array_to_byte_vector(src, 10, target, 0);
		int i = 0;
		REQUIRE(target.size() == 10);
		for (byte & b : target) 
			REQUIRE(src[i++] == b);
		target.clear();
		copy_byte_array_to_byte_vector(src + 5, 5, target, 0);
		i = 5;
		REQUIRE(target.size() == 5);
		for (byte & b : target)
			REQUIRE(src[i++] == b);
		target.clear();
		copy_byte_array_to_byte_vector(src, 5, target, 5);
		i = 5;
		REQUIRE(target.size() == 10);
		for (int i = 0; i < 5; i++)
			REQUIRE(target[i] == 0);
		for (int i = 5; i < 5; i++)
			REQUIRE(target[i] == src[5+i]);
		target.clear();
		target.resize(10);
		copy_byte_array_to_byte_vector(src, 10, target, 0);
		REQUIRE(target.size() == 10);
		i = 0;
		for (byte & b : target)
			REQUIRE(src[i++] == b);
	}

	SECTION("encode and decode bigintegers")
	{
		biginteger bi_res = endcode_decode(3322);
		REQUIRE(bi_res == 3322);
		biginteger birsa100 = biginteger(rsa100);
		bi_res = endcode_decode(birsa100);
		REQUIRE(bi_res == birsa100);
		bi_res = endcode_decode(-birsa100);
		REQUIRE(bi_res == -birsa100);
		bi_res = endcode_decode(197);
		REQUIRE(bi_res == 197);
		bi_res = endcode_decode(biginteger(xx));
		REQUIRE(bi_res == biginteger(xx));

	}

	SECTION("convert hex to string") {
		string hex = "64";
		REQUIRE(convert_hex_to_biginteger(hex)==biginteger(100));
	}

	SECTION("Config file") {
		// clean and create the config file
		remove("config_for_test.txt");
		std::ofstream outfile("config_for_test.txt");
		string textforfoo = "text_for_foo";
		string textforwater = "text_for_water";
		string nosecarg = "text_for_no_section_arg";
		outfile << "no_section_arg=" << nosecarg << "\n[section_1]\nfoo=" 
			<< textforfoo << "\n[section_2]\nwater=" << textforwater << std::endl;
		outfile.close();
	
		// read the file as config file
		ConfigFile cf("config_for_test.txt");
		std::string nosec = cf.Value("", "no_section_arg");
		std::string foo = cf.Value("section_1", "foo");
		std::string water = cf.Value("section_2", "water");
		REQUIRE(foo == textforfoo);
		REQUIRE(water == textforwater);
	}
}

//TEST_CASE("perfromance") {
//	int exp;
//	cin >> exp;
//	auto start0 = scapi_now();
//	biginteger bignumber = mp::pow(biginteger(2), exp);
//	print_elapsed_micros(start0, "compute pow");
//	auto start = scapi_now();
//	bool res_80 = isPrime(bignumber);
//	print_elapsed_micros(start, "miller_rabin");
//}

TEST_CASE("boosts multiprecision", "[boost, multiprecision]") {
	auto gen = get_seeded_prg();

	SECTION("testing pow")
	{
		biginteger res = mp::pow(biginteger(2), 10);
		REQUIRE(res == 1024);
	}

	SECTION("miller rabin test for prime numbers")
	{
		bool res_80 = isPrime(80);
		bool res_71 = isPrime(71);
		REQUIRE(!res_80);
		REQUIRE(res_71);
	}

	SECTION("generating random from range")
	{
		for (int i = 0; i < 100; ++i) {
			biginteger randNum = getRandomInRange(0, 100, gen.get());
			REQUIRE((randNum >= 0 && randNum <= 100));
		}
	}

	SECTION("generating random from range")
	{
		biginteger randNum1 = getRandomInRange(0, 1000000, gen.get());
		biginteger randNum2 = getRandomInRange(0, 1000000, gen.get());
		REQUIRE(randNum1 != randNum2);
	}
	
	SECTION("bit test")
	{
		// 16 is 1000 - bit index is starting to count right to left so:
		bool bit_4 = mp::bit_test(biginteger(16), 4);
		bool bit_0 = mp::bit_test(biginteger(16), 0);
		REQUIRE(bit_4);
		REQUIRE(!bit_0);
	}

	SECTION("string conversion for biginteger")
	{
		string s = "12345678910123456789123456789123456789123456789123456789123456789123456789123456789";
		biginteger bi(s);
		REQUIRE(bi.str()  == s);
		biginteger b2 = bi - 3;
		auto st_res = s.substr(0, s.size() - 1)+"6";
		REQUIRE(b2.str() == st_res);
	}

	SECTION("boost powm - pow modolu m")
	{
		REQUIRE(mp::powm(biginteger(2), 3, 3) == 2);
		REQUIRE(mp::powm(biginteger(3), 4, 17) == 13);
	}
}

TEST_CASE("MathAlgorithm", "[crt, sqrt_mod_3_4, math]")
{
	SECTION("conversion between CryptoPP::Integer and boost's biginteger")
	{
		// sqrt(16) mod 7 == (4,-4)
		MathAlgorithms::SquareRootResults roots = MathAlgorithms::sqrtModP_3_4(16, 7);
		REQUIRE((roots.getRoot1() == 4 || roots.getRoot2() == 4));

		// sqrt(25) mod 7 == (5,-5)
		roots = MathAlgorithms::sqrtModP_3_4(25, 7);
		REQUIRE((roots.getRoot1() == 5 || roots.getRoot2() == 5));

		// sqrt(121) mod 7 == (4,-4)
		roots = MathAlgorithms::sqrtModP_3_4(121, 7);
		REQUIRE((roots.getRoot1() == 4 || roots.getRoot2() == 4));

		// sqrt(207936) mod 7 == (1,-1)
		roots = MathAlgorithms::sqrtModP_3_4(207936, 7);
		REQUIRE((roots.getRoot1() == 1 || roots.getRoot2() == 1));

		// 13 is equal to 3 mod 4
		REQUIRE_THROWS_AS(MathAlgorithms::sqrtModP_3_4(625, 13), invalid_argument);
	}
	SECTION("mod inverse")
	{
		biginteger res = MathAlgorithms::modInverse(3, 7);
		REQUIRE(res == 5);
	}
	SECTION("Chineese reminder theorem")
	{
		vector<biginteger> congruences = { 2, 3, 2 };
		vector<biginteger> moduli = { 3, 5, 7 };
		auto bi= MathAlgorithms::chineseRemainderTheorem(congruences, moduli);
		REQUIRE(bi == 23);
	}
	SECTION("factorial")
	{
		REQUIRE(MathAlgorithms::factorial(6)==720);
		string fact35 = "10333147966386144929666651337523200000000";
		REQUIRE(MathAlgorithms::factorialBI(35).str() == fact35);
	}
}

/***************************************************/
/***********TESTING DLOG IMPLEMENTATIONS******************/
/*****************************************************/

void test_multiply_group_elements(shared_ptr<DlogGroup> dg, bool check_membership=false)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	auto ge = dg->createRandomElement();
	auto ige = dg->getInverse(ge.get());
	auto mul = dg->multiplyGroupElements(ge.get(), ige.get());
	auto identity = dg->getIdentity();
#else
    auto ge = dg.get()->createRandomElement();
    auto ige = dg.get()->getInverse(ge.get());
    auto mul = dg.get()->multiplyGroupElements(ge.get(), ige.get());
    auto identity = dg.get()->getIdentity();
#endif

	vector <shared_ptr<GroupElement>> vs{ ge, ige, mul, identity };
	if (check_membership)
		for (auto tge : vs)
#if OPENSSL_VERSION_NUMBER < 0x10100000L
			REQUIRE(dg->isMember(tge.get()));
#else
			REQUIRE(dg.get()->isMember((tge.get())));
#endif

	REQUIRE(mul->isIdentity());
}

void test_exponentiate(shared_ptr<DlogGroup> dg)
{
	auto ge = dg->createRandomElement();
	auto res_exp = dg->exponentiate(ge.get(), 3);
	auto res_mul = dg->multiplyGroupElements(dg->multiplyGroupElements(ge.get(), ge.get()).get(), ge.get());
	REQUIRE(*res_exp == *res_mul); // testing the == operator overloading and override
}

void test_simultaneous_multiple_exponentiations(shared_ptr<DlogGroup> dg)
{
	auto ge1 = dg->createRandomElement();
	auto ge2 = dg->createRandomElement();

	vector<shared_ptr<GroupElement>> baseArray = { ge1, ge2 };
	vector<biginteger> exponentArray = { 3, 4 };

	auto res1 = dg->simultaneousMultipleExponentiations(baseArray, exponentArray);
	auto expected_res = dg->multiplyGroupElements(dg->exponentiate(ge1.get(), 3).get(),
		dg->exponentiate(ge2.get(), 4).get());

	REQUIRE(*res1 == *expected_res);
}

void test_exponentiate_with_pre_computed_values(shared_ptr<DlogGroup> dg)
{
	auto base = dg->createRandomElement();
	auto res = dg->exponentiateWithPreComputedValues(base, 32);
	auto expected_res = dg->exponentiate(base.get(), 32);
	dg->endExponentiateWithPreComputedValues(base);

	REQUIRE(*expected_res == *res);
}

void test_encode_decode(shared_ptr<DlogGroup> dg)
{
	int k = dg->getMaxLengthOfByteArrayForEncoding();
	REQUIRE(k > 0);

	auto prg = get_seeded_prg();
	vector<byte> v;
	v.reserve(k);
	gen_random_bytes_vector(v, k, prg.get());

	auto ge = dg->encodeByteArrayToGroupElement(v);
	vector<byte> res = dg->decodeGroupElementToByteArray(ge.get());
	
	for (int i = 0; i < k; i++) {
		REQUIRE(v[i] == res[i]);
	}
}

void test_all(shared_ptr<DlogGroup> dg)
{
	test_multiply_group_elements(dg);
	test_simultaneous_multiple_exponentiations(dg);
	test_exponentiate(dg);
	test_exponentiate_with_pre_computed_values(dg);
	test_encode_decode(dg);
}

TEST_CASE("DlogGroup", "[Dlog, DlogGroup, CryptoPpDlogZpSafePrime]")
{
	SECTION("test OpenSSLZpSafePrime implementation")
	{
		// testing with the default 1024 take too much time. 64 bit is good enough to test conversion with big numbers
		auto dg = make_shared<OpenSSLDlogZpSafePrime>(64); 
		test_all(dg);
	}

	SECTION("test OpenSSLDlogECFp implementation")
	{
		auto dg = make_shared<OpenSSLDlogECFp>();
		test_all(dg);
	}
	SECTION("test OpenSSLDlogECF2m implementation")
	{
		auto dg = make_shared<OpenSSLDlogECF2m>();
		test_multiply_group_elements(dg);
		test_simultaneous_multiple_exponentiations(dg);
		test_exponentiate(dg);
		test_exponentiate_with_pre_computed_values(dg);
	}

	SECTION("test OpenSSLDlogECF2m implementation")
	{
		auto dg = make_shared<OpenSSLDlogECF2m>("B-233");
		test_multiply_group_elements(dg);
		test_simultaneous_multiple_exponentiations(dg);
		test_exponentiate(dg);
		test_exponentiate_with_pre_computed_values(dg);
	}
}


template <class FieldType>
void  test_field(FieldType elem1){

    //test templateField

    TemplateField<FieldType> field(0);

    //get a random element
    auto random = field.Random();


    //check element to bytes and vice versa
    byte * outBuytes = new byte[field.getElementSizeInBytes()];
    field.elementToBytes(outBuytes, random);
    auto fromBytes = field.bytesToElement(outBuytes);

    REQUIRE(fromBytes==random);


    //check multiplication
    FieldType two(2);
    FieldType one(1);

    FieldType  pminus1(FieldType::p - 1);
    //test mult and add
    FieldType twicePMinus1 = pminus1 * two;

    REQUIRE(!(twicePMinus1!=pminus1 - one ));

    //test division
    elem1 = elem1 - two;

    auto temp = elem1*pminus1;
    temp = temp/elem1;

    REQUIRE(temp==pminus1);






}

TEST_CASE("field operations", "[ZpMersenneIntElement, ZpMersenneLongElement, ZpMersenne127Element]") {

	SECTION("testing ZpMersenneIntElement") {

        ZpMersenneIntElement elem1;
        test_field(elem1);

	}
#ifdef __x86_64__
	SECTION("testing ZpMersenneLongElement") {

        ZpMersenneLongElement elem1;
        test_field(elem1);

	}

	SECTION("testing ZpMersenne127Element") {

        ZpMersenne127Element elem1;
        test_field(elem1);

	}
#endif

}

void test_hash(CryptographicHash * hash, string in, string expect)
{
	const char *cstr = in.c_str();
	int len = in.size();
	vector<byte> vec(cstr, cstr + len);
	hash->update(vec, 0, len);
	vector<byte> out;
	hash->hashFinal(out, 0);
	string actual = hexStr(out);
	CAPTURE(actual);
	CAPTURE(expect);
	CAPTURE(actual.size());
	CAPTURE(expect.size());
	CAPTURE(hash->getHashedMsgSize());
	REQUIRE(actual == expect);
}

TEST_CASE("HashOpenSSL", "[HASH, SHA1]")
{
	SECTION("Testing OpenSSL SHA1") {
		string input_msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
		CryptographicHash * hash = new OpenSSLSHA1();
		test_hash(hash, input_msg, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
		delete hash;
		hash = new OpenSSLSHA224();
		test_hash(hash, input_msg, "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
		delete hash;
		hash = new OpenSSLSHA256();
		test_hash(hash, input_msg, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
		delete hash;
		hash = new OpenSSLSHA384();
		test_hash(hash, input_msg, "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");
		delete hash;
		hash = new OpenSSLSHA512();
		test_hash(hash, input_msg, "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
		delete hash;
	}
}

template<typename T>
void test_prp(string key, string in, string expected_out)
{
	OpenSSLPRP * prp = new T();
	string s = boost::algorithm::unhex(key);
	char const *c = s.c_str();
	SecretKey sk = SecretKey((byte *)c, strlen(c), prp->getAlgorithmName());
	prp->setKey(sk);
	
	string sin = boost::algorithm::unhex(in);
	char const * cin = sin.c_str();
	vector<byte> in_vec, out_vec;
	copy_byte_array_to_byte_vector((byte*)cin, strlen(cin), in_vec, 0);
	prp->computeBlock(in_vec, 0, out_vec, 0);
	
	REQUIRE(hexStr(out_vec) == expected_out);
	delete prp;
}

TEST_CASE("PRF", "[AES, PRF]")
{
	SECTION("OpenSSL PRP")
	{
		test_prp<OpenSSLAES>("2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97");
	}
	SECTION("TRIPLE DES")
	{
		string key = "1234567890123456ABCDEFGH";
		string plain = "The quic";
		test_prp<OpenSSLTripleDES>(boost::algorithm::hex(key), boost::algorithm::hex(plain), "13d4d3549493d287");
	}
	SECTION("HMAC")
	{
		string key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
		char const * plain = "Hi There";
		string expected_out_hex = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

		// create mac and set key
		auto mac = new OpenSSLHMAC();
		string s = boost::algorithm::unhex(key);
		char const *c = s.c_str();
		SecretKey sk = SecretKey((byte *)c, strlen(c), mac->getAlgorithmName());
		mac->setKey(sk);
		
		// compute_block for plain 
		int in_len = strlen(plain);
		vector<byte> in_vec, out_vec;
		copy_byte_array_to_byte_vector((byte*)plain, in_len, in_vec, 0);
		mac->computeBlock(in_vec, 0, in_len, out_vec, 0);

		// clean 
		delete mac;
		
		// verify 
		REQUIRE(hexStr(out_vec) == expected_out_hex);
	}
}

void test_prg(PseudorandomGenerator * prg, string expected_name)
{
	REQUIRE(!prg->isKeySet()); // verify key is not set yet
	auto sk = prg->generateKey(128);
	prg->setKey(sk);
	REQUIRE(prg->isKeySet());

	REQUIRE(prg->getAlgorithmName() == expected_name); // verify alg name is as expected
	vector<byte> out;
	prg->getPRGBytes(out, 0, 16);
	REQUIRE(out.size() == 16);
	vector<byte> out2;
	prg->getPRGBytes(out2, 0, 16);
	string s1(out.begin(), out.end());
	string s2(out2.begin(), out2.end());
	REQUIRE(s1 != s2);
}

TEST_CASE("PRG", "[PRG]")
{

	SECTION("PrgFromOpenSSLAES")
	{
		PrgFromOpenSSLAES * scprg = new PrgFromOpenSSLAES();
		test_prg(scprg, "PrgFromOpenSSLAES");
	}

	SECTION("ScPrgFromPrf")
	{
		auto prf = make_shared<OpenSSLAES>();
		ScPrgFromPrf * scprg = new ScPrgFromPrf(prf);
		test_prg(scprg, "PRG_from_AES");
	}

	SECTION("OpenSSLRC4")
	{
		test_prg(new OpenSSLRC4(), "RC4");
	}
}


TEST_CASE("random", "[PrgFromOpenSSLAES]")
{
	SECTION("test seeded random")
	{

		PrgFromOpenSSLAES random1;
		PrgFromOpenSSLAES random2;

		auto sk = random1.generateKey(128);
		random1.setKey(sk);
		random2.setKey(sk);



		for (int k = 0; k < 10; k++) {
			auto int1 = random1.getRandom32();
			auto int2 = random2.getRandom32();

			bool equal = false;

			if(int1 == int2)
				equal = true;
			REQUIRE(equal == true);
		}

		for (int k = 0; k < 10; k++) {
			auto int1 = random1.getRandom64();
			auto int2 = random2.getRandom64();

			bool equal = false;

			if (int1 == int2)
				equal = true;
			REQUIRE(equal == true);
		}

		for (int k = 0; k < 10; k++) {
			auto int1 = random1.getRandom128();
			auto int2 = random2.getRandom128();

			bool equal = false;


			__m128i neq = _mm_xor_si128(int1, int2);
			if (_mm_test_all_zeros(neq, neq)) {//int1 == int2
				equal = true;
			}
			REQUIRE(equal == true);
		}

		for (int k = 0; k < 10; k++) {

			vector<byte> out;
			random1.getPRGBytes(out, 0, 10);
			REQUIRE(out.size() == 10);
			vector<byte> out2;
			random2.getPRGBytes(out2, 0, 10);
			bool equal = false;


			if (out == out2) {
				equal = true;
			}
			REQUIRE(equal == true);
			REQUIRE(equal == true);
		}

		random1.prepare();
		random2.prepare();

		for (int k = 0; k < 10; k++) {

			vector<byte> out;
			random1.getPRGBytes(out, 0, 10);
			REQUIRE(out.size() == 10);
			vector<byte> out2;
			random2.getPRGBytes(out2, 0, 10);
			bool equal = false;


			if (out == out2) {
				equal = true;
			}
			REQUIRE(equal == true);
		}

		auto random3 = move(random1);

		for (int k = 0; k < 10; k++) {

			vector<byte> out;
			random3.getPRGBytes(out, 0, 10);
			REQUIRE(out.size() == 10);
			vector<byte> out2;
			random2.getPRGBytes(out2, 0, 10);
			bool equal = false;


			if (out == out2) {
				equal = true;
			}
			REQUIRE(equal == true);
		}
	}

	//make sure that 2 prg with different secret key dont give the same randoms
	PrgFromOpenSSLAES random4;
	PrgFromOpenSSLAES random5;

	auto sk1 = random4.generateKey(128);
	auto sk2 = random4.generateKey(128);
	random4.setKey(sk1);
	random5.setKey(sk2);

	auto int1 = random4.getRandom64();
	auto int2 = random5.getRandom64();

	bool equal = false;

	if (int1 == int2)
		equal = true;
	REQUIRE(equal == false);

	//set to the key that random4 holds
	random5.setKey(sk1);
	int2 = random5.getRandom64();

	if (int1 == int2)
		equal = true;
	REQUIRE(equal == true);

}



TEST_CASE("KDF","")
{
	SECTION("HKDF")
	{
		HKDF hkdf(make_shared<OpenSSLHMAC>());
		string s = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
		string source = boost::algorithm::unhex(s);
		vector<byte> v_source(source.begin(), source.end());
		auto sk = hkdf.deriveKey(v_source, 0, v_source.size(), 40);
		auto v = sk.getEncoded();
		string s2(v.begin(), v.end());
	}
}

void random_oracle_test(RandomOracle * ro, string algName)
{
	REQUIRE(ro->getAlgorithmName() == algName);
	string input = "123456";
	vector<byte> in_vec(input.begin(), input.end());
	vector<byte> output;
	ro->compute(in_vec, 0, 6, output, 6);
	//REQUIRE(output.size() == 6);
	string s(output.begin(), output.end());
	delete ro;
}
TEST_CASE("Random Oracle", "")
{
	SECTION("HashBasedRO") {
		random_oracle_test(new HashBasedRO(), "HashBasedRO");
	}
	SECTION("HKDFBasedRO") {
		auto hkdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>());
		random_oracle_test(new HKDFBasedRO(hkdf), "HKDFBasedRO");
	}
}

TEST_CASE("TrapdoorPermutation", "[OpenSSL]")
{
	SECTION("OpenSSL") {
		auto tp = OpenSSLRSAPermutation();
		REQUIRE(tp.getAlgorithmName() == "OpenSSLRSA");
		biginteger public_mod = 55;
		int public_exponent = 3;
		int private_exponent = 7;
		shared_ptr<RSAPublicKey> pubKey = make_shared<RSAPublicKey>(public_mod, public_exponent);
		shared_ptr<RSAPrivateKey> prvKey = make_shared<RSAPrivateKey>(public_mod, private_exponent);
		tp.setKey(pubKey, prvKey);

        auto publicKey = tp.getPubKey().get();
        auto re_src = tp.generateRandomTPElement();
        auto re_enc = tp.compute(re_src.get());
		auto re_inv = tp.invert(re_enc.get());
        CAPTURE(re_enc->getElement());
		REQUIRE(re_inv->getElement() == re_src->getElement());
	}
}

TEST_CASE("Comm basics", "[Communication]") {
	SECTION("Comparing SocketPartyData") {
		auto spd1 = SocketPartyData(IpAddress::from_string("127.0.0.1"), 3000);
		auto spd2 = SocketPartyData(IpAddress::from_string("127.0.0.1"), 3001);
		REQUIRE(spd1 < spd2);
		REQUIRE(spd2 > spd1);
		REQUIRE(spd2 >= spd1);
		REQUIRE(spd1 <= spd2);
		REQUIRE(spd1 != spd2);
		REQUIRE(!(spd1 == spd2));
	}
}

TEST_CASE("Gates and Wires", "") {
	/*
	* Calculating the function f=(~X)vY.
	* 3 wires. 0-X, 1-Y, 2-f(x,y)
	* Calculating once for x=0,y=0 (expecting 1) and for x=0, y=1 (expecting 0)
	*/
	SECTION("Compute Gate") {
		vector<bool> truthT = { 1, 0, 1, 1 }; // Truth table for f=(~X)vY
		vector<int> inputWireIndices = { 0,1 };
		vector<int> outputWireIndices = { 2 };
		Gate g(3, truthT, inputWireIndices, outputWireIndices);
		map<int, Wire> computed_wires_map;
		computed_wires_map[0] = 0; // x=0
		computed_wires_map[1] = 0; // y=0
		g.compute(computed_wires_map);
		REQUIRE(computed_wires_map[0].getValue() == 0); // x still 0
		REQUIRE(computed_wires_map[1].getValue() == 0); // y still 1
		REQUIRE(computed_wires_map[2].getValue() == 1); // res = 1
		computed_wires_map[1] = 1; // y=1 now
		g.compute(computed_wires_map);
		REQUIRE(computed_wires_map[0].getValue() == 0); // x is still 0
		REQUIRE(computed_wires_map[1].getValue() == 1); // y is now 1
		REQUIRE(computed_wires_map[2].getValue() == 0); // res = 0
	}

	SECTION("Boolean Circuit") {
		/*
		* Calculating Circuit composed of 3 gates:
		*  i0 ----\
		*          > f1(X,Y)=(X or Y) -(i5 is x)\
		*  i1 ----/                              \
		*                                         --- > F3(x,y,z)= ((x or y) and z)   ----- i7 --->
		*  i2 ----\                              /   /
		*          > f2(X,Y)=(X and Y)-(i6 is y)/   /
		*  i3 ----/                                /
		*                                         /
		*  i4 --------------------------(is z)---/
		* Testing with i0=1, i1=0, i2=1, i3=0, i4=1.
		* Should get i7=1
		*/
		Gate g1(1, { 0, 1, 1, 1 }, { 0, 1 }, { 5 }); // x || y
		Gate g2(2, { 0, 0, 0, 1 }, { 2, 3 }, { 6 }); // x && y
		Gate g3(3, { 0, 0, 0, 1, 0, 1, 0, 1 }, { 5, 6, 4 }, { 7 }); // (x || y) && z
        vector<int> outputs = { 7 };
		BooleanCircuit bc({ g1, g2, g3 }, outputs, { {1,2,3,4} });
		map<int, Wire> presetInputWires = { { 0, Wire(1) }, { 1, Wire(0) }, { 2, Wire(1) },
											{ 3, Wire(0) }, { 4, Wire(1) } };
		bc.setInputs(presetInputWires, 1);
		auto bc_res_map = bc.compute();
		REQUIRE(bc_res_map[7].getValue() == 1);
	}

	SECTION("Boolean Circuit From file") {
		BooleanCircuit bc(new scannerpp::File("testCircuit.txt"));
		bc.write("testCircuitOutput.txt");
		BooleanCircuit aesbc(new scannerpp::File("NigelAes.txt"));
		aesbc.write("NigelAesOutput.txt");
		REQUIRE(bc.getNumberOfInputs(1) == 4);
		REQUIRE(bc.getNumberOfInputs(2) == 1);
		REQUIRE(bc.getOutputWireIndices().size() == 1);
	}
}

TEST_CASE("serialization", "[SerializedData, CmtCCommitmentMsg]")
{
	SECTION("CmtPedersenCommitmentMessage") {
		biginteger birsa100 = biginteger(rsa100);
		long id = 123123123123123;
		
		// create serialize, and verify original values untouched
		auto es = make_shared<ZpElementSendableData>(birsa100);
		CmtPedersenCommitmentMessage cmtMsg(es, id);
		auto serialized = cmtMsg.toString();
		REQUIRE(cmtMsg.getId() == id);
		REQUIRE(((ZpElementSendableData*)cmtMsg.getCommitment().get())->getX() == birsa100);

		// verify new one is created with empty values
		CmtPedersenCommitmentMessage cmtMsg2(make_shared<ZpElementSendableData>(0));
		REQUIRE(cmtMsg2.getId() == 0);
		REQUIRE(((ZpElementSendableData*)cmtMsg2.getCommitment().get())->getX() == 0);

		// deserialize and verify original values in the new object
		cmtMsg2.initFromString(serialized);
		REQUIRE(cmtMsg2.getId() == id);
		REQUIRE(((ZpElementSendableData*)cmtMsg2.getCommitment().get())->getX() == birsa100);
	}
	SECTION("SigmaBIMsg") {
		biginteger value = 123456789;
		SigmaBIMsg sMsg(value);
		auto serialized = sMsg.toString();
		REQUIRE(sMsg.getMsg() == value);

		// verify new one is created with empty values
		SigmaBIMsg sMsg2;
		REQUIRE(sMsg2.getMsg() == -100);

		// deserialize and verify original values in the new object
		sMsg2.initFromString(serialized);
		REQUIRE(sMsg2.getMsg() == value);
	}
	SECTION("CmtPedersenDecommitmentMessage") {
		biginteger rvalue(rsa100);
		biginteger xvalue(95612134554333);
		auto r = make_shared<BigIntegerRandomValue>(rvalue);
		CmtPedersenDecommitmentMessage cpdm(make_shared<biginteger>(xvalue), r);
		auto serialized = cpdm.toString();
		auto biR = dynamic_pointer_cast<BigIntegerRandomValue>(cpdm.getR());
		REQUIRE(biR->getR() == rvalue);
		REQUIRE(cpdm.getXValue() == xvalue);
		
		// verify new one is created with empty values
		auto r2 = make_shared<BigIntegerRandomValue>(0);
		CmtPedersenDecommitmentMessage cpdm2;
		auto biR2 = dynamic_pointer_cast<BigIntegerRandomValue>(cpdm2.getR());
		REQUIRE(!biR2);
		REQUIRE(cpdm2.getXValue() == 0);
		
		// deserialize and verify original values in the new object
		cpdm2.initFromString(serialized);
		auto biR3 = dynamic_pointer_cast<BigIntegerRandomValue>(cpdm2.getR());
		REQUIRE(biR3->getR() == rvalue);
		REQUIRE(cpdm2.getXValue() == xvalue);
	}
	SECTION("CmtRTrapdoorCommitPhaseOutput") {
		biginteger trap(rsa100);
		long commitmentId = 123456789;
		CmtRTrapdoorCommitPhaseOutput cmtTrapOut(trap, commitmentId);
		auto serialized = cmtTrapOut.toString();
		REQUIRE(cmtTrapOut.getCommitmentId() == commitmentId);
		REQUIRE(cmtTrapOut.getTrap() == trap);

		// verify new one is created with empty values
		CmtRTrapdoorCommitPhaseOutput cmtTrapOut2;
		REQUIRE(cmtTrapOut2.getCommitmentId() == 0);
		REQUIRE(cmtTrapOut2.getTrap() == 0);

		// deserialize and verify original values in the new object
		cmtTrapOut2.initFromString(serialized);
		REQUIRE(cmtTrapOut2.getCommitmentId() == commitmentId);
		REQUIRE(cmtTrapOut2.getTrap() == trap);
	}
	SECTION("ECFp Point sendable data") {
		OpenSSLDlogECFp dlog;
		shared_ptr<GroupElement> point = dlog.createRandomElement();
		
		shared_ptr<ECElementSendableData> data = dynamic_pointer_cast<ECElementSendableData>(point->generateSendableData());
		REQUIRE(dynamic_pointer_cast<ECElement>(point)->getX() == data->getX());
		REQUIRE(dynamic_pointer_cast<ECElement>(point)->getY() == data->getY());
		
		string dataBytes = data->toString();
		ECElementSendableData point2Data(0,0);
		point2Data.initFromString(dataBytes);

		REQUIRE(point2Data.getX() == data->getX());
		REQUIRE(point2Data.getY() == data->getY());
		
		shared_ptr<GroupElement> point2 = dlog.reconstructElement(false, &point2Data);
		REQUIRE(dlog.isMember(point2.get()));
		REQUIRE(*point2.get() == *point.get());
	}

	SECTION("ECF2m Point sendable data") {
		OpenSSLDlogECF2m dlog;
		shared_ptr<GroupElement> point = dlog.createRandomElement();

		shared_ptr<ECElementSendableData> data = dynamic_pointer_cast<ECElementSendableData>(point->generateSendableData());
		REQUIRE(dynamic_pointer_cast<ECElement>(point)->getX() == data->getX());
		REQUIRE(dynamic_pointer_cast<ECElement>(point)->getY() == data->getY());

		string dataBytes = data->toString();
		ECElementSendableData point2Data(0, 0);
		point2Data.initFromString(dataBytes);

		REQUIRE(point2Data.getX() == data->getX());
		REQUIRE(point2Data.getY() == data->getY());

		shared_ptr<GroupElement> point2 = dlog.reconstructElement(false, &point2Data);
		REQUIRE(dlog.isMember(point2.get()));
		REQUIRE(*point2.get() == *point.get());
	}
}


TEST_CASE("symmetric encryption")
{
	SECTION("Openssl CTR encryption")
	{

		OpenSSLCTREncRandomIV enc("AES");
		auto key = enc.generateKey(128);
		REQUIRE(enc.isKeySet() == false);
		enc.setKey(key);
		REQUIRE(enc.isKeySet() == true);
		REQUIRE(enc.getAlgorithmName() == "CTR Encryption with AES"); 
		
		string message = "I want to encrypt this!";
		vector<byte> plainM(message.begin(), message.end());
		ByteArrayPlaintext plaintext(plainM);
		auto cipher = enc.encrypt(&plaintext);
		auto original = enc.decrypt(cipher.get());
		REQUIRE(*original == plaintext);
	}
}



TEST_CASE("asymmetric encryption")
{
	SECTION("El Gamal on group element")
	{
		auto random = get_seeded_prg();
		auto dlog = make_shared<OpenSSLDlogZpSafePrime>(256);
		ElGamalOnGroupElementEnc elgamal(dlog);
		auto keys = elgamal.generateKey();
		elgamal.setKey(keys.first, keys.second);
		string message = "I want to encrypt this!";
		int len = message.size();
		if (elgamal.hasMaxByteArrayLengthForPlaintext()) {
			REQUIRE(len < elgamal.getMaxLengthOfByteArrayForPlaintext());
		}
		vector<byte> plainM(message.begin(), message.end());
		auto plaintext = elgamal.generatePlaintext(plainM);
		biginteger r = getRandomInRange(0, dlog->getOrder() - 1, random.get());
		auto cipher = elgamal.encrypt(plaintext, r);
		auto returnedP = elgamal.decrypt(cipher.get());
		REQUIRE(*returnedP == *plaintext);

		auto returnedV = elgamal.generateBytesFromPlaintext(plaintext.get());
		bool equal = true;
		for (int i = 0; i < plainM.size(); i++)
			if (returnedV.data()[i] != plainM.data()[i])
				equal = false;
		REQUIRE(equal == true);


		auto doubleC = elgamal.multiply(cipher.get(), cipher.get(), r);
		auto p = dynamic_pointer_cast<GroupElementPlaintext>(plaintext);
		auto c = dlog->multiplyGroupElements(p->getElement().get(), p->getElement().get());
		auto multC = elgamal.encrypt(make_shared<GroupElementPlaintext>(c), r*3 % dlog->getOrder());
		REQUIRE(*doubleC == *multC);
	}

	SECTION("El Gamal on byte array")
	{
		auto random = get_seeded_prg();
		auto dlog = make_shared<OpenSSLDlogZpSafePrime>(64);
		auto kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>());
		ElGamalOnByteArrayEnc elgamal(dlog, kdf);
		auto keys = elgamal.generateKey();
		elgamal.setKey(keys.first, keys.second);
		string message = "I want to encrypt this!";
		int len = message.size();
		if (elgamal.hasMaxByteArrayLengthForPlaintext()) {
			REQUIRE(len < elgamal.getMaxLengthOfByteArrayForPlaintext());
		}
		vector<byte> plainM(message.begin(), message.end());
		auto plaintext = elgamal.generatePlaintext(plainM);
		biginteger r = getRandomInRange(0, dlog->getOrder() - 1, random.get());
		auto cipher = elgamal.encrypt(plaintext, r);
		auto returnedP = elgamal.decrypt(cipher.get());
		REQUIRE(*returnedP == *plaintext);

		auto returnedV = elgamal.generateBytesFromPlaintext(plaintext.get());
		bool equal = true;
		for (int i = 0; i < plainM.size(); i++)
			if (returnedV.data()[i] != plainM.data()[i])
				equal = false;
		REQUIRE(equal == true);
	}

	SECTION("CramerShoup")
	{
		auto random = get_seeded_prg();
		auto dlog = make_shared<OpenSSLDlogZpSafePrime>(256);
		CramerShoupOnGroupElementEnc cr(dlog);
		auto keys = cr.generateKey();
		cr.setKey(keys.first, keys.second);
		string message = "I want to encrypt this!";
		int len = message.size();
		if (cr.hasMaxByteArrayLengthForPlaintext()) {
			REQUIRE(len < cr.getMaxLengthOfByteArrayForPlaintext());
		}
		vector<byte> plainM(message.begin(), message.end());
		auto plaintext = cr.generatePlaintext(plainM);
		biginteger r = getRandomInRange(0, dlog->getOrder() - 1, random.get());
		auto cipher = cr.encrypt(plaintext, r);
		auto returnedP = cr.decrypt(cipher.get());
		REQUIRE(*returnedP == *plaintext);

		auto returnedV = cr.generateBytesFromPlaintext(plaintext.get());
		bool equal = true;
		for (int i = 0; i < plainM.size(); i++)
			if (returnedV.data()[i] != plainM.data()[i])
				equal = false;
		REQUIRE(equal == true);
	}
}

#endif
