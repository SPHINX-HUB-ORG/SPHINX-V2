//
// Created by moriya on 04/01/17.
//

#include "../../include/comm/MPCCommunicationBF.hpp"
#include "../../include/infra/ConfigFile.hpp"

#include <iostream>

std::vector< std::shared_ptr<ProtocolPartyDataBF> > MPCCommunicationBF::setCommunication(int id, int numParties, std::string configFile)
{
	std::cout<<"in communication"<<std::endl;

	std::cout<<"num parties = "<<numParties<<std::endl;
	std::cout<<"my id = "<<id<<std::endl;
	std::vector< std::shared_ptr<ProtocolPartyDataBF> > parties(numParties - 1);

    //open file
    ConfigFile cf(configFile);

    std::string portString, ipString;
    std::vector<int> ports(numParties);
    std::vector< std::string > ips(numParties);

    int counter = 0;
    for (int i = 0; i < numParties; i++) {
        portString = "party_" + std::to_string(i) + "_port";
        ipString = "party_" + std::to_string(i) + "_ip";

        //get partys IPs and ports data
        ports[i] = stoi(cf.Value("", portString));
        ips[i] = cf.Value("", ipString);
    }

    for (int i=0; i<numParties; i++)
    {
    	u_int16_t self_port = ports[id]+i, peer_port = ports[i]+id;
    	if(i<id)
    		peer_port -= 1;
    	else if (i>id)
    		self_port -= 1;
    	else
    		continue;

    	std::cout << i << ": self "<< ips[id] << ":" << self_port << " <-> peer " << ips[i] << ":" << peer_port << std::endl;
    	std::shared_ptr<CommPartyBF> channel = std::make_shared<CommPartyTCPSyncedBoostFree>(ips[id].c_str(), self_port, ips[i].c_str(), peer_port);
    	channel->join(500, 5000);
    	std::cout<<"channel established"<<std::endl;
    	parties[counter++] = std::make_shared<ProtocolPartyDataBF>(i, channel);
    }

    return parties;
}
