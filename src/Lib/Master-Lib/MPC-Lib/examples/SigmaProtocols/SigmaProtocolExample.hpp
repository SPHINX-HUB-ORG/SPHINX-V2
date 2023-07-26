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


#pragma once

#include <boost/thread/thread.hpp>
#include "../../include/comm/Comm.hpp"
#include "../../include/interactive_mid_protocols/SigmaProtocolDlog.hpp"
#include "../../include/interactive_mid_protocols/ZeroKnowledge.hpp"
#include "../../include/primitives/DlogOpenSSL.hpp"
#include "../../include/infra/Scanner.hpp"
#include "../../include/infra/ConfigFile.hpp"

struct SigmaDlogParams {
	biginteger w;
	biginteger p;
	biginteger q;
	biginteger g;
	int t;
	IpAddress proverIp;
	IpAddress verifierIp;
	int proverPort;
	int verifierPort;
	string protocolName;

	SigmaDlogParams(biginteger w, biginteger p, biginteger q, biginteger g, int t, 
		IpAddress proverIp, IpAddress verifierIp, int proverPort, int verifierPort,
		string protocolName) {
		this->w = w; // witness
		this->p = p; // group order - must be prime
		this->q = q; // sub group order - prime such that p=2q+1
		this->g = g; // generator of Zq
		this->t = t; // soundness param must be: 2^t<q
		this->proverIp = proverIp;
		this->verifierIp = verifierIp;
		this->proverPort = proverPort;
		this->verifierPort = verifierPort;
		this->protocolName = protocolName;
	};
};

SigmaDlogParams readSigmaConfig(string config_file) {
	ConfigFile cf(config_file);
	string input_section = cf.Value("", "input_section");
	biginteger p = biginteger(cf.Value(input_section, "p"));
	biginteger q = biginteger(cf.Value(input_section, "q"));
	biginteger g = biginteger(cf.Value(input_section, "g"));
	biginteger w = biginteger(cf.Value(input_section, "w"));
	int t = stoi(cf.Value(input_section, "t"));
	string proverIpStr = cf.Value("", "proverIp");
	string verifierIpStr = cf.Value("", "verifierIp");
	int proverPort = stoi(cf.Value("", "proverPort"));
	int verifierPort = stoi(cf.Value("", "verifierPort"));
	auto proverIp = IpAddress::from_string(proverIpStr);
	auto verifierIp = IpAddress::from_string(verifierIpStr);
	string protocolName = cf.Value("", "protocolName");
	return SigmaDlogParams(w, p, q, g, t, proverIp, verifierIp, proverPort, verifierPort, protocolName);
};

void SigmaUsage() {
	std::cerr << "Usage: ./libscapi_examples <1(=prover)|2(=verifier)> config_file_path" << std::endl;
}

class ProverVerifierExample {
public:
	virtual void prove(shared_ptr<CommParty> server, 
		shared_ptr<SigmaDlogProverComputation> proverComputation, 
		shared_ptr<DlogGroup> dg,
		shared_ptr<SigmaDlogProverInput> proverinput) = 0;
	virtual bool verify(shared_ptr<CommParty> server,
		shared_ptr<SigmaDlogVerifierComputation> verifierComputation,
		shared_ptr<SigmaGroupElementMsg> msgA,
		shared_ptr<SigmaBIMsg> msgZ,
		shared_ptr<SigmaDlogCommonInput> commonInput,
		shared_ptr<DlogGroup> dg) = 0;
};

class SimpleDlogSigma : public ProverVerifierExample {
public:
	virtual void prove(shared_ptr<CommParty> server,
		shared_ptr<SigmaDlogProverComputation> proverComputation,
		shared_ptr<DlogGroup> dg,
		shared_ptr<SigmaDlogProverInput> proverinput) override {
		auto sp = new SigmaProtocolProver(server, proverComputation);
		cout << "--> running simple sigma dlog prover" << endl;
		sp->prove(proverinput);
	}
	virtual bool verify(shared_ptr<CommParty> server,
		shared_ptr<SigmaDlogVerifierComputation> verifierComputation,
		shared_ptr<SigmaGroupElementMsg> msgA,
		shared_ptr<SigmaBIMsg> msgZ,
		shared_ptr<SigmaDlogCommonInput> commonInput,
		shared_ptr<DlogGroup> dg) override{
		auto v = new SigmaProtocolVerifier(server, verifierComputation, msgA, msgZ);
		cout << "--> running simple sigma dlog verify" << endl;
		bool verificationPassed = v->verify(commonInput.get());
		delete v;
		return verificationPassed;
	}
};

class ZKFromSigma : public ProverVerifierExample {
public:
	virtual void prove(shared_ptr<CommParty> server,
		shared_ptr<SigmaDlogProverComputation> proverComputation,
		shared_ptr<DlogGroup> dg,
		shared_ptr<SigmaDlogProverInput> proverinput) {
		cout << "before creating ZK prover" << endl;
		auto receiver = make_shared<CmtPedersenReceiver>(server, dg);
		auto sp = new ZKFromSigmaProver(server, proverComputation, receiver);
		cout << "--> running ZK prover" << endl;
		sp->prove(proverinput);
	}
	virtual bool verify(shared_ptr<CommParty> server,
		shared_ptr<SigmaDlogVerifierComputation> verifierComputation,
		shared_ptr<SigmaGroupElementMsg> msgA,
		shared_ptr<SigmaBIMsg> msgZ,
		shared_ptr<SigmaDlogCommonInput> commonInput,
		shared_ptr<DlogGroup> dg) override {
		cout << "before creating ZK verifier" << endl;
		auto emptyTrap = make_shared<CmtRTrapdoorCommitPhaseOutput>();
		auto committer = make_shared<CmtPedersenCommitter>(server, dg);
		auto v = new ZKFromSigmaVerifier(server, verifierComputation, committer);
		cout << "--> running ZK verify" << endl;
		bool verificationPassed = v->verify(commonInput.get(), msgA, msgZ);
		delete v;
		return verificationPassed;
	}
};

class PedersenZKSigma : public ProverVerifierExample {
public:
	virtual void prove(shared_ptr<CommParty> server,
		shared_ptr<SigmaDlogProverComputation> proverComputation,
		shared_ptr<DlogGroup> dg,
		shared_ptr<SigmaDlogProverInput> proverinput) {
		auto sp = new ZKPOKFromSigmaCmtPedersenProver(server, proverComputation, dg);
		cout << "--> running pedersen prover" << endl;
		sp->prove(proverinput);
	}
	virtual bool verify(shared_ptr<CommParty> server,
		shared_ptr<SigmaDlogVerifierComputation> verifierComputation,
		shared_ptr<SigmaGroupElementMsg> msgA,
		shared_ptr<SigmaBIMsg> msgZ,
		shared_ptr<SigmaDlogCommonInput> commonInput,
		shared_ptr<DlogGroup> dg) override {
		auto emptyTrap = make_shared<CmtRTrapdoorCommitPhaseOutput>();
		auto v = new ZKPOKFromSigmaCmtPedersenVerifier(server, verifierComputation, emptyTrap, dg);
		cout << "--> running pedersen verify" << endl;
		bool verificationPassed = v->verify(commonInput.get(), msgA, msgZ);
		delete v;
		return verificationPassed;
	}
};

class ZKPOKFiatShamir : public ProverVerifierExample {
public:
	virtual void prove(shared_ptr<CommParty> server,
		shared_ptr<SigmaDlogProverComputation> proverComputation,
		shared_ptr<DlogGroup> dg,
		shared_ptr<SigmaDlogProverInput> proverinput) {
		auto sp = new ZKPOKFiatShamirFromSigmaProver(server, proverComputation);
		cout << "--> running Fiat Shamir prover" << endl;
		vector<byte> cont;
		auto input = make_shared<ZKPOKFiatShamirProverInput>(proverinput, cont);
		sp->prove(input);
	}
	virtual bool verify(shared_ptr<CommParty> server,
		shared_ptr<SigmaDlogVerifierComputation> verifierComputation,
		shared_ptr<SigmaGroupElementMsg> msgA,
		shared_ptr<SigmaBIMsg> msgZ,
		shared_ptr<SigmaDlogCommonInput> commonInput,
		shared_ptr<DlogGroup> dg) override {
		auto emptyTrap = make_shared<CmtRTrapdoorCommitPhaseOutput>();
		auto v = new ZKPOKFiatShamirFromSigmaVerifier(server, verifierComputation);
		cout << "--> running Fiat Shamir verify" << endl;
		vector<byte> cont;
		auto input = make_shared<ZKPOKFiatShamirCommonInput>(commonInput.get(), cont);
		bool verificationPassed = v->verify(input.get(), msgA, msgZ);
		delete v;
		return verificationPassed;
	}
};


shared_ptr<ProverVerifierExample> getProverVerifier(SigmaDlogParams sdp)
{
	shared_ptr<ProverVerifierExample> sds;
	if(sdp.protocolName=="Simple")
		sds = make_shared<SimpleDlogSigma>();
	else if (sdp.protocolName == "SimpleZK")
		sds = make_shared<ZKFromSigma>();
	else if(sdp.protocolName=="ZKPedersen")
		sds = make_shared<PedersenZKSigma>();
	else if (sdp.protocolName == "ZKFiatShamir")
		sds = make_shared<ZKPOKFiatShamir>();
	return sds;
}
