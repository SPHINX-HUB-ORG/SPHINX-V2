//
// Created by moriya on 04/01/17.
//

#include "../../include/comm/MPCCommunication.hpp"


vector<shared_ptr<ProtocolPartyData>> MPCCommunication::setCommunication(boost::asio::io_service & io_service, int id,
        int numParties, const string & configFile) {
cout<<"in communication"<<endl;

cout<<"num parties = "<<numParties<<endl;
    cout<<"my id = "<<id<<endl;
    vector<shared_ptr<ProtocolPartyData>> parties(numParties - 1);

    //open file
    ConfigFile cf(configFile);

    string portString, ipString;
    vector<int> ports(numParties);
    vector<string> ips(numParties);

    int counter = 0;
    for (int i = 0; i < numParties; i++) {
        portString = "party_" + to_string(i) + "_port";
        ipString = "party_" + to_string(i) + "_ip";

        //get partys IPs and ports data
        ports[i] = stoi(cf.Value("", portString));
        ips[i] = cf.Value("", ipString);
    }

    SocketPartyData me, other;

    for (int i=0; i<numParties; i++){
        if (i < id) {// This party will be the receiver in the protocol

            me = SocketPartyData(boost_ip::address::from_string(ips[id]), ports[id] + i);
            cout<<"my port = "<<ports[id] + i<<endl;
            other = SocketPartyData(boost_ip::address::from_string(ips[i]), ports[i] + id - 1);
            cout<<"other port = "<<ports[i] + id - 1<<endl;

            shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, me, other);
            // connect to party one
            channel->join(500, 5000);
            cout<<"channel established"<<endl;

            parties[counter++] = make_shared<ProtocolPartyData>(i, channel);
        } else if (i>id) {// This party will be the sender in the protocol
            me = SocketPartyData(boost_ip::address::from_string(ips[id]), ports[id] + i - 1);
            cout<<"my port = "<<ports[id] + i - 1<<endl;
            other = SocketPartyData(boost_ip::address::from_string(ips[i]), ports[i] + id);
            cout<<"other port = "<< ports[i] + id<<endl;

            shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, me, other);
            // connect to party one
            channel->join(500, 5000);
            cout<<"channel established"<<endl;

            parties[counter++] = make_shared<ProtocolPartyData>(i, channel);
        }
    }

    return parties;

}

vector<shared_ptr<CommParty>> MPCCommunication::setCommunication(int id, int numParties, string configFile) {
    cout<<"in communication"<<endl;

    cout<<"num parties = "<<numParties<<endl;
    cout<<"my id = "<<id<<endl;
    vector<shared_ptr<CommParty>> parties(numParties);

    //open file
    ConfigFile cf(configFile);

    string portString, ipString;
    vector<int> ports(numParties);
    vector<string> ips(numParties);

    for (int i = 0; i < numParties; i++) {
        portString = "party_" + to_string(i) + "_port";
        ipString = "party_" + to_string(i) + "_ip";

        //get partys IPs and ports data
        ports[i] = stoi(cf.Value("", portString));
        ips[i] = cf.Value("", ipString);
    }

    for (int i=0; i<numParties; i++){

        SocketPartyData me, other;
        if (i < id) {// This party will be the receiver in the protocol

            me = SocketPartyData(boost_ip::address::from_string(ips[id]), ports[id] + i);
            cout<<"my port = "<<ports[id] + i<<endl;
            other = SocketPartyData(boost_ip::address::from_string(ips[i]), ports[i] + id - 1);
            cout<<"other port = "<<ports[i] + id - 1<<endl;

        } else if (i>id) {// This party will be the sender in the protocol
            me = SocketPartyData(boost_ip::address::from_string(ips[id]), ports[id] + i - 1);
            cout<<"my port = "<<ports[id] + i - 1<<endl;
            other = SocketPartyData(boost_ip::address::from_string(ips[i]), ports[i] + id);
            cout<<"other port = "<< ports[i] + id<<endl;
        }

        if (i!= id) {
            shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, me, other);

            // connect to party one
            channel->join(500, 5000);
            cout << "channel established" << endl;

            parties[i] = channel;
        }
    }

    return parties;
}

void MPCCommunication::printNetworkStats(vector<shared_ptr<ProtocolPartyData>> &parties, int partyID,
                                         vector<pair<string, string>> &arguments) {
    map<string, string> metaData = { {"partyId", to_string(partyID)},
                                     {"numberOfParties", to_string(parties.size() + 1)} } ;

    json partyData = json::array();
    for (int idx = 0; idx < parties.size(); idx++) {
        if(partyID == idx) continue;

        json commData = json::object();
        commData["partyId"] = idx;
        commData["bytesSent"] = parties[idx].get()->getChannel().get()->bytesOut;
        commData["bytesReceived"] = parties[idx].get()->getChannel().get()->bytesIn;
        partyData.insert(partyData.begin(), commData);
    }

    json party;
    party["data"] = partyData;
    party["metaData"] = metaData;

    string fileName;
    for (size_t idx = 0; idx< arguments.size(); idx++)
        fileName += arguments[idx].second + "*";
    fileName += "*partyCommData.json";

    try {
        ofstream myfile (fileName, ostream::out);
        myfile << party;
    }

    catch (exception& e) {
        cout << "Exception thrown : " << e.what() << endl;
    }
}
