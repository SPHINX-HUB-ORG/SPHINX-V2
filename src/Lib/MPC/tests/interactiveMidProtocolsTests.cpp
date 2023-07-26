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

#ifndef INTERACTIVE_MID_TEST
#define INTERACTIVE_MID_TEST

#include "catch.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocol.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocolDlog.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocolDH.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocolDHExtended.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocolPedersenCmtKnowledge.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocolPedersenCommittedValue.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocolElGamalCmtKnowledge.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocolElGamalCommittedValue.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocolElGamalPrivateKey.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocolElGamalEncryptedValue.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocolCramerShoupEncryptedValue.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocolDamgardJurikEncryptedZero.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocolDamgardJurikEncryptedValue.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocolDamgardJurikProduct.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocolAnd.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocolOrTwo.hpp"
#include "../include/interactive_mid_protocols/SigmaProtocolOrMultiple.hpp"

void computeSigmaProtocol(SigmaProverComputation* prover, SigmaVerifierComputation* verifier,
	SigmaCommonInput* commonInput, shared_ptr<SigmaProverInput> proverInput) {
	shared_ptr<SigmaProtocolMsg> firstMsg = prover->computeFirstMsg(proverInput);
	verifier->sampleChallenge();
	vector<byte> challenge = verifier->getChallenge();
	shared_ptr<SigmaProtocolMsg> secondMsg = prover->computeSecondMsg(challenge);
	bool verified = verifier->verify(commonInput, firstMsg.get(), secondMsg.get());

	REQUIRE(verified == true);
}

void simulate(SigmaSimulator* simulator, SigmaVerifierComputation* verifier,
	SigmaCommonInput* commonInput) {
	shared_ptr<SigmaSimulatorOutput> output = simulator->simulate(commonInput);
	verifier->setChallenge(output->getE());
	bool verified = verifier->verify(commonInput, output->getA().get(), output->getZ().get());

	REQUIRE(verified == true);
}

TEST_CASE("SigmaProtocols", "[SigmaProtocolDlog, SigmaProtocolDH]")
{
	SECTION("test sigma protocol dlog")
	{
		auto random = get_seeded_prg(); 
		auto dlog = make_shared<OpenSSLDlogECF2m>();
		//auto dlog = make_shared<OpenSSLDlogZpSafePrime>();

		SigmaDlogProverComputation prover(dlog, 80);
		SigmaDlogVerifierComputation verifier(dlog, 80);
		biginteger w = getRandomInRange(0, dlog->getOrder() - 1, random.get());

		auto h = dlog->exponentiate(dlog->getGenerator().get(), w);
		SigmaDlogCommonInput commonInput(h);
		shared_ptr<SigmaDlogProverInput> proverInput = make_shared<SigmaDlogProverInput>(h, w);

		computeSigmaProtocol(&prover, &verifier, &commonInput, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &commonInput);
	}

	SECTION("test sigma protocol DH")
	{
		auto random = get_seeded_prg();
		auto dlog = make_shared<OpenSSLDlogECFp>();
		//auto dlog = make_shared<OpenSSLDlogZpSafePrime>();
		SigmaDHProverComputation prover(dlog, 80);
		SigmaDHVerifierComputation verifier(dlog, 80);
		biginteger w = getRandomInRange(0, dlog->getOrder() - 1, random.get());

		auto u = dlog->exponentiate(dlog->getGenerator().get(), w);
		auto h = dlog->createRandomElement();
		auto v = dlog->exponentiate(h.get(), w);
		SigmaDHCommonInput commonInput(h, u, v);
		shared_ptr<SigmaDHProverInput> proverInput = make_shared<SigmaDHProverInput>(h, u, v, w);

		computeSigmaProtocol(&prover, &verifier, &commonInput, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &commonInput);
	}

	SECTION("test sigma protocol DH Extended")
	{
		auto random = get_seeded_prg();
		auto dlog = make_shared<OpenSSLDlogECFp>();
		//auto dlog = make_shared<OpenSSLDlogZpSafePrime>();
		SigmaDHExtendedProverComputation prover(dlog, 80);
		SigmaDHExtendedVerifierComputation verifier(dlog, 80);
		biginteger w = getRandomInRange(0, dlog->getOrder() - 1, random.get());

		auto g1 = dlog->getGenerator();
		auto h1 = dlog->exponentiate(g1.get(), w);
		auto g2 = dlog->createRandomElement();
		auto h2 = dlog->exponentiate(g2.get(), w);
		vector<shared_ptr<GroupElement>> g;
		g.push_back(g1);
		g.push_back(g2);
		vector<shared_ptr<GroupElement>> h;
		h.push_back(h1);
		h.push_back(h2);
		SigmaDHExtendedCommonInput commonInput(g, h);
		shared_ptr<SigmaDHExtendedProverInput> proverInput = make_shared<SigmaDHExtendedProverInput>(g, h, w);

		computeSigmaProtocol(&prover, &verifier, &commonInput, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &commonInput);
	}

	SECTION("test sigma protocol pedersen cmt knowledge")
	{
		auto random = get_seeded_prg();
		auto dlog = make_shared<OpenSSLDlogECFp>();
		//auto dlog = make_shared<OpenSSLDlogZpSafePrime>();
		SigmaPedersenCmtKnowledgeProverComputation prover(dlog, 80);
		SigmaPedersenCmtKnowledgeVerifierComputation verifier(dlog, 80);
		biginteger x = getRandomInRange(0, dlog->getOrder() - 1, random.get());
		biginteger r = getRandomInRange(0, dlog->getOrder() - 1, random.get());
		auto g = dlog->getGenerator();
		auto h1 = dlog->exponentiate(g.get(), r);
		auto h = dlog->createRandomElement();
		auto h2 = dlog->exponentiate(h.get(), x);
		auto c = dlog->multiplyGroupElements(h1.get(), h2.get());


		SigmaPedersenCmtKnowledgeCommonInput commonInput(h, c);
		shared_ptr<SigmaPedersenCmtKnowledgeProverInput> proverInput = make_shared<SigmaPedersenCmtKnowledgeProverInput>(h, c, x, r);

		computeSigmaProtocol(&prover, &verifier, &commonInput, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &commonInput);
	}

	SECTION("test sigma protocol pedersen cmt value")
	{
		auto random = get_seeded_prg();
		auto dlog = make_shared<OpenSSLDlogECFp>();
		//auto dlog = make_shared<OpenSSLDlogZpSafePrime>();
		SigmaPedersenCommittedValueProverComputation prover(dlog, 80);
		SigmaPedersenCommittedValueVerifierComputation verifier(dlog, 80);
		biginteger x = getRandomInRange(0, dlog->getOrder() - 1, random.get());
		biginteger r = getRandomInRange(0, dlog->getOrder() - 1, random.get());
		auto g = dlog->getGenerator();
		auto h1 = dlog->exponentiate(g.get(), r);
		auto h = dlog->createRandomElement();
		auto h2 = dlog->exponentiate(h.get(), x);
		auto c = dlog->multiplyGroupElements(h1.get(), h2.get());


		SigmaPedersenCommittedValueCommonInput commonInput(h, c, x);
		shared_ptr<SigmaPedersenCommittedValueProverInput> proverInput = make_shared<SigmaPedersenCommittedValueProverInput>(h, c, x, r);

		computeSigmaProtocol(&prover, &verifier, &commonInput, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &commonInput);
	}

	SECTION("test sigma protocol el gamal cmt knowledge")
	{
		auto random = get_seeded_prg();
		auto dlog = make_shared<OpenSSLDlogECFp>();
		//auto dlog = make_shared<OpenSSLDlogZpSafePrime>();
		SigmaElGamalCmtKnowledgeProverComputation prover(dlog, 80);
		SigmaElGamalCmtKnowledgeVerifierComputation verifier(dlog, 80);
		biginteger w = getRandomInRange(0, dlog->getOrder() - 1, random.get());
		auto g = dlog->getGenerator();
		auto h = dlog->exponentiate(g.get(), w);
		ElGamalPublicKey key(h);

		SigmaElGamalCmtKnowledgeCommonInput commonInput(h);
		auto proverInput = make_shared<SigmaElGamalCmtKnowledgeProverInput>(key, w);

		computeSigmaProtocol(&prover, &verifier, &commonInput, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &commonInput);
	}

	SECTION("test sigma protocol el gamal committed value")
	{
		auto random = get_seeded_prg();
		auto dlog = make_shared<OpenSSLDlogECFp>();
		//auto dlog = make_shared<OpenSSLDlogZpSafePrime>();
		SigmaElGamalCommittedValueProverComputation prover(dlog, 80);
		SigmaElGamalCommittedValueVerifierComputation verifier(dlog, 80);
		biginteger w = getRandomInRange(0, dlog->getOrder() - 1, random.get());
		auto x = dlog->createRandomElement();
		ElGamalOnGroupElementEnc elgamal(dlog);
		auto pair = elgamal.generateKey();
		elgamal.setKey(pair.first, pair.second);
		auto cipher = elgamal.encrypt(make_shared<GroupElementPlaintext>(x), w);

		auto key = dynamic_pointer_cast<ElGamalPublicKey>(pair.first);
		auto commitment = dynamic_pointer_cast<ElGamalOnGrElSendableData>(cipher->generateSendableData());
		SigmaElGamalCommittedValueCommonInput commonInput(key, commitment, x);
		auto proverInput = make_shared<SigmaElGamalCommittedValueProverInput>(key, commitment, x, w);

		computeSigmaProtocol(&prover, &verifier, &commonInput, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &commonInput);
	}

	SECTION("test sigma protocol el gamal private key")
	{
		auto dlog = make_shared<OpenSSLDlogECFp>();
		//auto dlog = make_shared<OpenSSLDlogZpSafePrime>();
		SigmaElGamalPrivateKeyProverComputation prover(dlog, 80);
		SigmaElGamalPrivateKeyVerifierComputation verifier(dlog, 80);
		ElGamalOnGroupElementEnc elgamal(dlog);
		auto pair = elgamal.generateKey();

		auto publicKey = *(dynamic_cast<ElGamalPublicKey*>(pair.first.get()));
		auto privateKey = *(dynamic_cast<ElGamalPrivateKey*>(pair.second.get()));
		SigmaElGamalPrivateKeyCommonInput commonInput(publicKey);
		auto proverInput = make_shared<SigmaElGamalPrivateKeyProverInput>(publicKey, privateKey);

		computeSigmaProtocol(&prover, &verifier, &commonInput, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &commonInput);
	}

	SECTION("test sigma protocol el gamal encrypted value")
	{
		auto random = get_seeded_prg();
		auto dlog = make_shared<OpenSSLDlogECFp>();
		//auto dlog = make_shared<OpenSSLDlogZpSafePrime>();
		SigmaElGamalEncryptedValueProverComputation prover(dlog, 80);
		SigmaElGamalEncryptedValueVerifierComputation verifier(dlog, 80);
		biginteger w = getRandomInRange(0, dlog->getOrder() - 1, random.get());
		auto x = dlog->createRandomElement();
		ElGamalOnGroupElementEnc elgamal(dlog);
		auto pair = elgamal.generateKey();
		elgamal.setKey(pair.first, pair.second);
		auto cipher = elgamal.encrypt(make_shared<GroupElementPlaintext>(x), w);

		auto key = *(dynamic_cast<ElGamalPublicKey*>(pair.first.get()));
		auto ciphertext = *(dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get()));
		SigmaElGamalEncryptedValueCommonInput randomInput(true, ciphertext, key, x);
		auto proverRandomInput = make_shared<SigmaElGamalEncryptedValueRandomnessProverInput>(ciphertext, key, x, w);

		computeSigmaProtocol(&prover, &verifier, &randomInput, proverRandomInput);
		simulate(prover.getSimulator().get(), &verifier, &randomInput);

		auto privateKey = *(dynamic_cast<ElGamalPrivateKey*>(pair.second.get()));
		SigmaElGamalEncryptedValueCommonInput keyInput(false, ciphertext, key, x);
		auto proverKeyInput = make_shared<SigmaElGamalEncryptedValuePrivKeyProverInput>(ciphertext, key, x, privateKey);

		computeSigmaProtocol(&prover, &verifier, &keyInput, proverKeyInput);
		simulate(prover.getSimulator().get(), &verifier, &keyInput);
	}

	SECTION("test sigma protocol Cramer Shoup encrypted value")
	{
		auto random = get_seeded_prg();
		auto dlog = make_shared<OpenSSLDlogECFp>();
		auto hash = make_shared<OpenSSLSHA256>();
		//auto dlog = make_shared<OpenSSLDlogZpSafePrime>();
		SigmaCramerShoupEncryptedValueProverComputation prover(dlog, hash, 80);
		SigmaCramerShoupEncryptedValueVerifierComputation verifier(dlog, hash, 80);
		biginteger w = getRandomInRange(0, dlog->getOrder() - 1, random.get());
		auto x = dlog->createRandomElement();
		CramerShoupOnGroupElementEnc cr(dlog, hash);
		auto pair = cr.generateKey();
		cr.setKey(pair.first, pair.second);
		auto cipher = cr.encrypt(make_shared<GroupElementPlaintext>(x), w);

		auto key = *(dynamic_cast<CramerShoupPublicKey*>(pair.first.get()));
		auto ciphertext = *(dynamic_cast<CramerShoupOnGroupElementCiphertext*>(cipher.get()));
		SigmaCramerShoupEncryptedValueCommonInput input(ciphertext, key, x);
		auto proverInput = make_shared<SigmaCramerShoupEncryptedValueProverInput>(ciphertext, key, x, w);

		computeSigmaProtocol(&prover, &verifier, &input, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &input);
	}

	SECTION("test sigma protocol Damgard Jurik encrypted zero")
	{
		auto random = get_seeded_prg();
		SigmaDJEncryptedZeroProverComputation prover;
		SigmaDJEncryptedZeroVerifierComputation verifier;
		DamgardJurikEnc dj;
		DJKeyGenParameterSpec spec;
		auto pair = dj.generateKey(&spec);
		dj.setKey(pair.first, pair.second);
		biginteger r = getRandomInRange(0, dynamic_pointer_cast<DamgardJurikPublicKey>(pair.first)->getModulus(), random.get());
		auto cipher = dj.encrypt(make_shared<BigIntegerPlainText>(0), r);

		auto publicKey = *(dynamic_cast<DamgardJurikPublicKey*>(pair.first.get()));
		auto privateKey = *(dynamic_cast<DamgardJurikPrivateKey*>(pair.second.get()));
		auto ciphertext = *(dynamic_cast<BigIntegerCiphertext*>(cipher.get()));
		SigmaDJEncryptedZeroCommonInput input(publicKey, ciphertext);
		auto proverInput = make_shared<SigmaDJEncryptedZeroProverInput>(publicKey, ciphertext, r);

		computeSigmaProtocol(&prover, &verifier, &input, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &input);

		proverInput = make_shared<SigmaDJEncryptedZeroProverInput>(publicKey, ciphertext, privateKey);
		computeSigmaProtocol(&prover, &verifier, &input, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &input);
	}

	SECTION("test sigma protocol Damgard Jurik encrypted value")
	{
		auto random = get_seeded_prg();
		SigmaDJEncryptedValueProverComputation prover;
		SigmaDJEncryptedValueVerifierComputation verifier;
		DamgardJurikEnc dj;
		DJKeyGenParameterSpec spec;
		auto pair = dj.generateKey(&spec);
		dj.setKey(pair.first, pair.second);
		biginteger r = getRandomInRange(0, dynamic_pointer_cast<DamgardJurikPublicKey>(pair.first)->getModulus(), random.get());
		auto plaintext = make_shared<BigIntegerPlainText>(0);
		auto cipher = dj.encrypt(plaintext, r);

		auto publicKey = *(dynamic_cast<DamgardJurikPublicKey*>(pair.first.get()));
		auto privateKey = *(dynamic_cast<DamgardJurikPrivateKey*>(pair.second.get()));
		auto ciphertext = *(dynamic_cast<BigIntegerCiphertext*>(cipher.get()));

		SigmaDJEncryptedValueCommonInput input(publicKey, ciphertext, *(plaintext.get()));
		auto proverInput = make_shared<SigmaDJEncryptedValueProverInput>(publicKey, ciphertext, *(plaintext.get()), r);

		computeSigmaProtocol(&prover, &verifier, &input, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &input);

		proverInput = make_shared<SigmaDJEncryptedValueProverInput>(publicKey, ciphertext, *(plaintext.get()), privateKey);
		computeSigmaProtocol(&prover, &verifier, &input, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &input);
	}

	SECTION("test sigma protocol Damgard Jurik product")
	{
		auto random = get_seeded_prg();
		SigmaDJProductProverComputation prover;
		SigmaDJProductVerifierComputation verifier;
		DamgardJurikEnc dj;
		DJKeyGenParameterSpec spec;
		auto pair = dj.generateKey(&spec);
		dj.setKey(pair.first, pair.second);
		biginteger r1 = getRandomInRange(0, dynamic_pointer_cast<DamgardJurikPublicKey>(pair.first)->getModulus(), random.get());
		auto p1 = make_shared<BigIntegerPlainText>(2);
		auto p2 = make_shared<BigIntegerPlainText>(3);
		auto p3 = make_shared<BigIntegerPlainText>(6);
		auto c1 = dj.encrypt(p1, r1);
		auto c2 = dj.encrypt(p2, r1);
		auto c3 = dj.encrypt(p3, r1);

		auto publicKey = *(dynamic_cast<DamgardJurikPublicKey*>(pair.first.get()));
		auto privateKey = *(dynamic_cast<DamgardJurikPrivateKey*>(pair.second.get()));
		auto cipher1 = *(dynamic_cast<BigIntegerCiphertext*>(c1.get()));
		auto cipher2 = *(dynamic_cast<BigIntegerCiphertext*>(c2.get()));
		auto cipher3 = *(dynamic_cast<BigIntegerCiphertext*>(c3.get()));

		SigmaDJProductCommonInput input(publicKey, cipher1, cipher2, cipher3);
		auto proverInput = make_shared<SigmaDJProductProverInput>(publicKey, cipher1, cipher2, cipher3, r1, r1, r1, *p1, *p2);

		computeSigmaProtocol(&prover, &verifier, &input, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &input);

		proverInput = make_shared<SigmaDJProductProverInput>(publicKey, cipher1, cipher2, cipher3, privateKey, *p1, *p2);
		computeSigmaProtocol(&prover, &verifier, &input, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &input);
	}

	SECTION("test sigma protocol AND")
	{
		auto random = get_seeded_prg();
		auto dlog = make_shared<OpenSSLDlogECFp>();

		auto dlogProver = make_shared<SigmaDlogProverComputation>(dlog, 80, random);
		auto dlogVerifier = make_shared<SigmaDlogVerifierComputation>(dlog, 80, random);
		biginteger w = getRandomInRange(0, dlog->getOrder() - 1, random.get());

		auto h1 = dlog->exponentiate(dlog->getGenerator().get(), w);
		auto commonDlogInput = make_shared<SigmaDlogCommonInput>(h1);
		auto proverDlogInput = make_shared<SigmaDlogProverInput>(h1, w);

		//auto dlog = make_shared<OpenSSLDlogZpSafePrime>();
		auto dhProver = make_shared<SigmaDHProverComputation>(dlog, 80, random);
		auto dhVerifier = make_shared<SigmaDHVerifierComputation>(dlog, 80, random);

		auto u = dlog->exponentiate(dlog->getGenerator().get(), w);
		auto h = dlog->createRandomElement();
		auto v = dlog->exponentiate(h.get(), w);
		auto commonDHInput = make_shared<SigmaDHCommonInput>(h, u, v);
		auto proverDHInput = make_shared<SigmaDHProverInput>(h, u, v, w);

		vector<shared_ptr<SigmaProverComputation>> provers;
		vector<shared_ptr<SigmaVerifierComputation>> verifiers;
		vector<shared_ptr<SigmaSimulator>> simulators;
		vector<shared_ptr<SigmaCommonInput>> commonInputArr;
		vector<shared_ptr<SigmaProverInput>> proverInputArr;

		provers.push_back(dlogProver);
		provers.push_back(dhProver);
		verifiers.push_back(dlogVerifier);
		verifiers.push_back(dhVerifier);
		simulators.push_back(dlogProver->getSimulator());
		simulators.push_back(dhProver->getSimulator());
		commonInputArr.push_back(commonDlogInput);
		commonInputArr.push_back(commonDHInput);
		proverInputArr.push_back(proverDlogInput);
		proverInputArr.push_back(proverDHInput);

		SigmaANDProverComputation prover(provers, 80);
		SigmaANDVerifierComputation verifier(verifiers, 80);
		SigmaMultipleCommonInput commonInput(commonInputArr);
		auto proverInput = make_shared<SigmaMultipleProverInput>(proverInputArr);

		computeSigmaProtocol(&prover, &verifier, &commonInput, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &commonInput);

	}

	SECTION("test sigma protocol OR")
	{
		auto random = get_seeded_prg();
		auto dlog = make_shared<OpenSSLDlogECFp>();

		auto dlogProver = make_shared<SigmaDlogProverComputation>(dlog, 80, random);
		auto dlogVerifier = make_shared<SigmaDlogVerifierComputation>(dlog, 80, random);
		biginteger w = getRandomInRange(0, dlog->getOrder() - 1, random.get());

		auto h1 = dlog->exponentiate(dlog->getGenerator().get(), w);
		auto commonDlogInput = make_shared<SigmaDlogCommonInput>(h1);
		auto proverDlogInput = make_shared<SigmaDlogProverInput>(h1, w);

		//auto dlog = make_shared<OpenSSLDlogZpSafePrime>();
		auto dhProver = make_shared<SigmaDHProverComputation>(dlog, 80, random);
		auto dhVerifier = make_shared<SigmaDHVerifierComputation>(dlog, 80, random);

		auto u = dlog->exponentiate(dlog->getGenerator().get(), w);
		auto h = dlog->createRandomElement();
		auto v = dlog->exponentiate(h.get(), w);
		auto commonDHInput = make_shared<SigmaDHCommonInput>(h, u, v);

		vector<shared_ptr<SigmaVerifierComputation>> verifiers;
		vector<shared_ptr<SigmaSimulator>> simulators;
		vector<shared_ptr<SigmaCommonInput>> commonInputArr;

		verifiers.push_back(dlogVerifier);
		verifiers.push_back(dhVerifier);
		simulators.push_back(dlogProver->getSimulator());
		simulators.push_back(dhProver->getSimulator());
		commonInputArr.push_back(commonDlogInput);
		commonInputArr.push_back(commonDHInput);

		SigmaOrTwoProverComputation prover(dlogProver, dhProver->getSimulator(), 80);
		SigmaOrTwoVerifierComputation verifier(verifiers, 80);
		SigmaMultipleCommonInput commonInput(commonInputArr);
		auto proverInput = make_shared<SigmaOrTwoProverInput>(proverDlogInput, commonDHInput, 0);

		computeSigmaProtocol(&prover, &verifier, &commonInput, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &commonInput);

	}

	SECTION("test sigma protocol OR Multiple")
	{
		auto random = get_seeded_prg();
		auto dlog = make_shared<OpenSSLDlogECFp>();

		auto dlogProver = make_shared<SigmaDlogProverComputation>(dlog, 80, random);
		auto dlogVerifier = make_shared<SigmaDlogVerifierComputation>(dlog, 80, random);
		biginteger w = getRandomInRange(0, dlog->getOrder() - 1, random.get());

		auto h1 = dlog->exponentiate(dlog->getGenerator().get(), w);
		auto commonDlogInput = make_shared<SigmaDlogCommonInput>(h1);
		auto proverDlogInput = make_shared<SigmaDlogProverInput>(h1, w);

		//auto dlog = make_shared<OpenSSLDlogZpSafePrime>();
		auto dhProver = make_shared<SigmaDHProverComputation>(dlog, 80, random);
		auto dhVerifier = make_shared<SigmaDHVerifierComputation>(dlog, 80, random);

		auto u = dlog->exponentiate(dlog->getGenerator().get(), w);
		auto h = dlog->createRandomElement();
		auto v = dlog->exponentiate(h.get(), w);
		auto commonDHInput = make_shared<SigmaDHCommonInput>(h, u, v);

		auto djProver = make_shared<SigmaDJEncryptedZeroProverComputation>(80);
		auto djVerifier = make_shared<SigmaDJEncryptedZeroVerifierComputation>(80);
		DamgardJurikEnc dj;
		DJKeyGenParameterSpec spec;
		auto pair = dj.generateKey(&spec);
		dj.setKey(pair.first, pair.second);
		biginteger r = getRandomInRange(0, dynamic_pointer_cast<DamgardJurikPublicKey>(pair.first)->getModulus(), random.get());
		auto cipher = dj.encrypt(make_shared<BigIntegerPlainText>(0), r);

		auto publicKey = *(dynamic_cast<DamgardJurikPublicKey*>(pair.first.get()));
		auto privateKey = *(dynamic_cast<DamgardJurikPrivateKey*>(pair.second.get()));
		auto ciphertext = *(dynamic_cast<BigIntegerCiphertext*>(cipher.get()));
		auto commonDjInput = make_shared<SigmaDJEncryptedZeroCommonInput>(publicKey, ciphertext);
		auto djProverInput = make_shared<SigmaDJEncryptedZeroProverInput>(publicKey, ciphertext, r);

		map<int, shared_ptr<SigmaProverComputation>> provers;
		vector<shared_ptr<SigmaVerifierComputation>> verifiers;
		map<int, shared_ptr<SigmaSimulator>> simulators;
		vector<shared_ptr<SigmaCommonInput>> commonInputArr;
		map<int, shared_ptr<SigmaProverInput>> proversInputs;
		map<int, shared_ptr<SigmaCommonInput>> simulatorsInputs;

		provers[0] = dlogProver;
		verifiers.push_back(dlogVerifier);
		verifiers.push_back(dhVerifier);
		verifiers.push_back(djVerifier);
		simulators[1] = dhProver->getSimulator();
		simulators[2] = djProver->getSimulator();
		commonInputArr.push_back(commonDlogInput);
		commonInputArr.push_back(commonDHInput);
		commonInputArr.push_back(commonDjInput);
		proversInputs[0] = proverDlogInput;
		simulatorsInputs[1] = commonDHInput;
		simulatorsInputs[2] = commonDjInput;

		SigmaOrMultipleProverComputation prover(provers, simulators, 80);
		SigmaOrMultipleVerifierComputation verifier(verifiers, 80);
		SigmaOrMultipleCommonInput commonInput(commonInputArr, 1);
		auto proverInput = make_shared<SigmaOrMultipleProverInput>(proversInputs, simulatorsInputs);

		computeSigmaProtocol(&prover, &verifier, &commonInput, proverInput);
		simulate(prover.getSimulator().get(), &verifier, &commonInput);
		
	}
}

#endif