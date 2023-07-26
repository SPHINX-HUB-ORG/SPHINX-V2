#include "OTExample.h"

OTParams readOTConfig(string config_file) {
	ConfigFile cf(config_file);
	string senderIpStr = cf.Value("", "senderIp");
	string receiverIpStr = cf.Value("", "receiverIp");
	int senderPort = stoi(cf.Value("", "senderPort"));
	int receiverPort = stoi(cf.Value("", "receiverPort"));
	auto senderIp = IpAddress::from_string(senderIpStr);
	auto receiverIp = IpAddress::from_string(receiverIpStr);
	string protocolName = cf.Value("", "protocolName");
	OTParams params(senderIp, receiverIp, senderPort, receiverPort, protocolName);

	if (protocolName.find("UC") != string::npos){
        auto dlog = make_shared<OpenSSLDlogECF2m>();
        vector<biginteger> point(2);
        point[0] = biginteger("4373527398576640063579304354969275615843559206632");
        point[1] = biginteger("3705292482178961271312284701371585420180764402649");
        auto g0 = dlog->generateElement(false, point);
        point[0] = biginteger("5358538915372747505940066348728070469076553372492");
        point[1] = biginteger("9028382283996304130045455598981082528772297505697");
        auto g1 = dlog->generateElement(false, point);
        point[0] = biginteger("582941706599807092180704244329891555852679544026");
        point[1] = biginteger("9405288600072608660829837034337429060956333420529");
        auto h0 = dlog->generateElement(false, point);
        point[0] = biginteger("5171406319926278015143700754389901479380894481649");
        point[1] = biginteger("4324109033029607118050375077650365756171591181543");
        auto h1 = dlog->generateElement(false, point);
        params.g0 = g0;
        params.g1 = g1;
        params.h0 = h0;
        params.h1 = h1;
	}

	return params;
}

void OTUsage() {
	std::cerr << "Usage: ./libscapi_examples <1(=sender)|2(=receiver)> config_file_path" << std::endl;
}

shared_ptr<OTSender> getSender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random, OTParams sdp, const shared_ptr<DlogGroup> & dlog) {
	shared_ptr<OTSender> sender;

	if (sdp.protocolName == "SemiHonestOnGroupElement") {
		sender = make_shared<OTSemiHonestDDHOnGroupElementSender>(random, dlog);
	} else if (sdp.protocolName == "SemiHonestOnByteArray") {
		sender = make_shared<OTSemiHonestDDHOnByteArraySender>(random, dlog);
	} else if (sdp.protocolName == "PrivacyOnlyOnGroupElement") {
		sender = make_shared<OTPrivacyOnlyDDHOnGroupElementSender>(random, dlog);
	} else if (sdp.protocolName == "PrivacyOnlyOnByteArray") {
		sender = make_shared<OTPrivacyOnlyDDHOnByteArraySender>(random, dlog);
	} else if (sdp.protocolName == "OneSidedSimulationOnGroupElement") {
		sender = make_shared<OTOneSidedSimDDHOnGroupElementSender>(channel, random, dlog);
	} else if (sdp.protocolName == "OneSidedSimulationOnByteArray") {
		sender = make_shared<OTOneSidedSimDDHOnByteArraySender>(channel, random, dlog);
	} else if (sdp.protocolName == "FullSimulationOnGroupElement") {
		sender = make_shared<OTFullSimDDHOnGroupElementSender>(channel, random, dlog);
	} else if (sdp.protocolName == "FullSimulationOnByteArray") {
		sender = make_shared<OTFullSimDDHOnByteArraySender>(channel, random, dlog);
	} else if (sdp.protocolName == "FullSimulationROMOnGroupElement") {
		sender = make_shared<OTFullSimROMDDHOnGroupElementSender>(channel, random, dlog);
	} else if (sdp.protocolName == "FullSimulationROMOnByteArray") {
		sender = make_shared<OTFullSimROMDDHOnByteArraySender>(channel, random, dlog);
	} else if (sdp.protocolName == "UCOnGroupElement") {
		sender = make_shared<OTUCDDHOnGroupElementSender>(dlog, sdp.g0, sdp.g1, sdp.h0, sdp.h1, random);
	} else if (sdp.protocolName == "UCOnByteArray") {
		sender = make_shared<OTUCDDHOnByteArraySender>(dlog, sdp.g0, sdp.g1, sdp.h0, sdp.h1);
	}

	return sender;
}

shared_ptr<OTReceiver> getReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random, OTParams sdp, const shared_ptr<DlogGroup> & dlog) {
	shared_ptr<OTReceiver> receiver;
	if (sdp.protocolName == "SemiHonestOnGroupElement") {
		receiver = make_shared<OTSemiHonestDDHOnGroupElementReceiver>(random, dlog);
	} else if (sdp.protocolName == "SemiHonestOnByteArray") {
		receiver = make_shared<OTSemiHonestDDHOnByteArrayReceiver>(random, dlog);
	} else if (sdp.protocolName == "PrivacyOnlyOnGroupElement") {
		receiver = make_shared<OTPrivacyOnlyDDHOnGroupElementReceiver>(random, dlog);
	} else if (sdp.protocolName == "PrivacyOnlyOnByteArray") {
		receiver = make_shared<OTPrivacyOnlyDDHOnByteArrayReceiver>(random, dlog);
	} else if (sdp.protocolName == "OneSidedSimulationOnGroupElement") {
		receiver = make_shared<OTOneSidedSimDDHOnGroupElementReceiver>(channel, random, dlog);
	} else if (sdp.protocolName == "OneSidedSimulationOnByteArray") {
		receiver = make_shared<OTOneSidedSimDDHOnByteArrayReceiver>(channel, random, dlog);
	} else if (sdp.protocolName == "FullSimulationOnGroupElement") {
		receiver = make_shared<OTFullSimDDHOnGroupElementReceiver>(channel, random, dlog);
	} else if (sdp.protocolName == "FullSimulationOnByteArray") {
		receiver = make_shared<OTFullSimDDHOnByteArrayReceiver>(channel, random, dlog);
	} else if (sdp.protocolName == "FullSimulationROMOnGroupElement") {
		receiver = make_shared<OTFullSimROMDDHOnGroupElementReceiver>(channel, random, dlog);
	} else if (sdp.protocolName == "FullSimulationROMOnByteArray") {
		receiver = make_shared<OTFullSimROMDDHOnByteArrayReceiver>(channel, random, dlog);
	} else if (sdp.protocolName == "UCOnGroupElement") {
		receiver = make_shared<OTUCDDHOnGroupElementReceiver>(dlog, sdp.g0, sdp.g1, sdp.h0, sdp.h1, random);
	} else if (sdp.protocolName == "UCOnByteArray") {
		receiver = make_shared<OTUCDDHOnByteArrayReceiver>(dlog, sdp.g0, sdp.g1, sdp.h0, sdp.h1);
	}

	return receiver;
}

shared_ptr<OTSInput> getInput(DlogGroup* dlog, OTParams params) {
	
	if (params.protocolName == "SemiHonestOnGroupElement" || params.protocolName == "PrivacyOnlyOnGroupElement" ||
		params.protocolName == "OneSidedSimulationOnGroupElement" || params.protocolName == "FullSimulationOnGroupElement"
		|| params.protocolName == "FullSimulationROMOnGroupElement" || params.protocolName == "UCOnGroupElement") {
		auto x0 = dlog->createRandomElement();
		cout << "X0 = " << x0->generateSendableData()->toString() << endl;
		auto x1 = dlog->createRandomElement();
		cout << "X1 = " << x1->generateSendableData()->toString() << endl;
		return make_shared<OTOnGroupElementSInput>(x0, x1);
	} else if (params.protocolName == "SemiHonestOnByteArray" || params.protocolName == "PrivacyOnlyOnByteArray" ||
			params.protocolName == "OneSidedSimulationOnByteArray" || params.protocolName == "FullSimulationOnByteArray"
			|| params.protocolName == "FullSimulationROMOnByteArray" || params.protocolName == "UCOnByteArray") {
		vector<byte> x0(10, '0'), x1(10, '1');
		cout << "x0 = " << endl;
		for (int i = 0; i < (int) x0.size(); i++)
			cout << x0[i] << " ";
		cout << endl;
		cout << "x1 = " << endl;
		for (int i = 0; i < (int) x1.size(); i++)
			cout << x1[i] << " ";
		cout << endl;
		return make_shared<OTOnByteArraySInput>(x0, x1);
	}
    return nullptr;
}

void printOutput(OTROutput* output, OTParams params) {
	if (params.protocolName == "SemiHonestOnGroupElement" || params.protocolName == "PrivacyOnlyOnGroupElement" ||
			params.protocolName == "OneSidedSimulationOnGroupElement" || params.protocolName == "FullSimulationOnGroupElement"
			|| params.protocolName == "FullSimulationROMOnGroupElement" || params.protocolName == "UCOnGroupElement") {
		auto out = (OTOnGroupElementROutput*)output;
		cout << "output = " << out->getXSigma()->generateSendableData()->toString() << endl;
	} else if (params.protocolName == "SemiHonestOnByteArray" || params.protocolName == "PrivacyOnlyOnByteArray" ||
			params.protocolName == "OneSidedSimulationOnByteArray" || params.protocolName == "FullSimulationOnByteArray"
			|| params.protocolName == "FullSimulationROMOnByteArray" || params.protocolName == "UCOnByteArray") {
		auto out = ((OTOnByteArrayROutput*)output)->getXSigma();
		cout << "output = " << endl;
		for (int i = 0; i < (int) out.size(); i++)
			cout << out[i] << " ";
		cout << endl;
	}
}

int mainOT(string side, string configPath) {
	auto sdp = readOTConfig(configPath);
	boost::asio::io_service io_service;
	SocketPartyData senderParty(sdp.senderIp, sdp.senderPort);
	SocketPartyData receiverParty(sdp.receiverIp, sdp.receiverPort);
	shared_ptr<CommParty> server = (side == "1") ?
		make_shared<CommPartyTCPSynced>(io_service, senderParty, receiverParty) :
		make_shared<CommPartyTCPSynced>(io_service, receiverParty, senderParty);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));

	auto random = make_shared<PrgFromOpenSSLAES>();
	auto key = random->generateKey(128);
	random->setKey(key);
	auto dlog = make_shared<OpenSSLDlogECF2m>();
	try {
		if (side == "1") {
			server->join(500, 5000); // sleep time=500, timeout = 5000 (ms);
			auto sender = getSender(server, random, sdp, dlog);
			auto input = getInput(dlog.get(), sdp);
			sender->transfer(server.get(), input.get());
			
		}
		else if (side == "2") {
			server->join(500, 5000); // sleep time=500, timeout = 5000 (ms);
			auto receiver = getReceiver(server, random, sdp, dlog);
			OTRBasicInput input(0);
			auto output = receiver->transfer(server.get(), &input);
			printOutput(output.get(), sdp);
		}
		else {
			OTUsage();
			return 1;
		}
	}
	catch (const logic_error& e) {
		// Log error message in the exception object
		cerr << e.what();
	}
	io_service.stop();
	t.join();
	return 0;
}

