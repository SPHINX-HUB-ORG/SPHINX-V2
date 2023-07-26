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


#include <boost/thread/thread.hpp>
#include "../../include/infra/Scanner.hpp"
#include "../../include/infra/ConfigFile.hpp"
#include "../../include/comm/Comm.hpp"


struct CommConfig {
	string party_1_ip;
	string party_2_ip;
	int party_1_port;
	int party_2_port;
	string certificateChainFile;
	string password;
	string privateKeyFile;
	string tmpDHFile;
	string clientVerifyFile;
	string classType;
	CommConfig(string party_1_ip, string party_2_ip, int party_1_port, int party_2_port,
		string certificateChainFile, string password, string privateKeyFile, string tmpDHFile, 
		string clientVerifyFile, string classType) {
		this->party_1_ip = party_1_ip;
		this->party_2_ip = party_2_ip;
		this->party_1_port = party_1_port;
		this->party_2_port = party_2_port;
		this->certificateChainFile = certificateChainFile;
		this->password = password;
		this->privateKeyFile = privateKeyFile;
		this->tmpDHFile = tmpDHFile;
		this->clientVerifyFile = clientVerifyFile;
		this->classType = classType;
	}
};

CommConfig readCommConfig(string config_file) {
	ConfigFile cf(config_file);
#ifdef _WIN32
	string os = "Windows";
#else
	string os = "Linux";
#endif
	int party_1_port = stoi(cf.Value("", "party_1_port"));
	int party_2_port = stoi(cf.Value("", "party_2_port"));
	string party_1_ip = cf.Value("", "party_1_ip");
	string party_2_ip = cf.Value("", "party_2_ip");
	string certificateChainFile = cf.Value(os, "certificateChainFile");
	string password = cf.Value(os, "password");
	string privateKeyFile = cf.Value(os, "privateKeyFile");
	string tmpDHFile = cf.Value(os, "tmpDHFile");
	string clientVerifyFile = cf.Value(os, "clientVerifyFile");
	string classType = cf.Value("", "classType");
	return CommConfig(party_1_ip, party_2_ip, party_1_port, party_2_port,
		certificateChainFile, password, privateKeyFile, tmpDHFile, clientVerifyFile, classType);
}

void print_send_message(const string  &s, int i) {
	cout << "sending message number " << i << " message: " << s << endl;
}
void print_recv_message(const string &s, int i) {
	cout << "receievd message number " << i << " message: " << s << endl;
}

void send_messages(CommParty* commParty, string * messages, int start, int end) {
	for (int i = start; i < end; i++) {
		auto s = messages[i];
		print_send_message(s, i);
		commParty->write((const byte *)s.c_str(), s.size());
	}
}

void recv_messages(CommParty* commParty, string * messages, int start, int end, 
	byte * buffer, int expectedSize) {
	commParty->read(buffer, expectedSize);
	// the size of all strings is 2. Parse the message to get the original strings
	int j = 0;
	for (int i = start; i < end; i++, j++) {
		auto s = string(reinterpret_cast<char const*>(buffer+j*2), 2);
		print_recv_message(s, i);
		messages[i] = s;
	}
}

int commUsage() {
	std::cerr << "Usage: ./libscapi_example comm <party_number(1|2)> <config_file_path>";
	return 1;
}

CommParty* getCommParty(CommConfig commConfig, string partyNumber, boost::asio::io_service& io_service) {
	string myIp = (partyNumber == "1") ? commConfig.party_1_ip : commConfig.party_2_ip;
	string otherIp = (partyNumber == "1") ? commConfig.party_2_ip : commConfig.party_1_ip;
	int myPort = (partyNumber == "1") ? commConfig.party_1_port : commConfig.party_2_port;
	int otherPort = (partyNumber == "1") ? commConfig.party_2_port : commConfig.party_1_port;
	SocketPartyData me(IpAddress::from_string(myIp), myPort);
	SocketPartyData other(IpAddress::from_string(otherIp), otherPort);
	cout << "tring to connect to: " << otherIp << " port: " << otherPort << endl;
	if (commConfig.classType == "CommPartyTCPSynced")
	{
		cout << "Running Communication Example With CommPartyTCPSynced Class" << endl;
		return new CommPartyTCPSynced(io_service, me, other);
	}
	throw invalid_argument("Got unsupported class type in config file");
}

/*
* Testing Communication 
*/
int mainComm(string partyNumber, string filePath)
{
	try
	{
		if (partyNumber != "1" && partyNumber != "2")
			return commUsage();

		auto commConfig = readCommConfig(filePath);

		boost::asio::io_service io_service;
		CommParty * commParty = getCommParty(commConfig, partyNumber, io_service);
		boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));
		commParty->join(500, 5000);

		string sendMessages[6] = { "s0", "s1", "s2", "s3", "s4", "s5" };
		string recvMessages[6];
		byte buffer[100];

		// send 3 message. get 3. send additional 2 get 2. send 1 get 1
		send_messages(commParty, sendMessages, 0, 3);
		recv_messages(commParty, recvMessages, 0, 3, buffer, 6);
		send_messages(commParty, sendMessages, 3, 5);
		recv_messages(commParty, recvMessages, 3, 5, buffer, 4);
		send_messages(commParty, sendMessages, 5, 6);
		recv_messages(commParty, recvMessages, 5, 6, buffer, 2);

		string longMessage = "Hi, this is a long message to test the writeWithSize approach";
		commParty->writeWithSize(longMessage);

		vector<byte> resMsg;
		commParty->readWithSizeIntoVector(resMsg);
		const byte * uc = &(resMsg[0]);
		string resMsgStr(reinterpret_cast<char const*>(uc), resMsg.size());
		string eq = (resMsgStr == longMessage)? "yes" : "no";
		cout << "Got long message: " << resMsgStr << ".\nequal? " << eq << "!" << endl;

		io_service.stop();
		t.join();
		delete commParty;
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}
