=======================
The Communication Layer
=======================

.. contents::

----------------------
Communication Design
----------------------

The communication layer provides communication services for any interactive cryptographic protocol. We have two types of communication, plain (unauthenticated and unencrypted) communication and secure channels using ssl. This layer is heavily used by the interactive protocols in libscapi' third layer and by MPC protocols. It can also be used by any other cryptographic protocol that requires communication. Currently the communication layer is a two-party communication channel. MultiParty communication can be achieved by setting a communication between each pair of parties.

Class hierarchy
---------------

The main communication clas is ``CommParty``. This is an abstract class that declares all communication functionalities.
There are two concrete classes that derive the ``CommParty`` class:

* ``CommPartyTCPSynced`` - establish a plain channel between the parties.
* ``CommPartyTcpSslSynced`` - establish an ssl channel between the parties.


------------------------
Setting up communication
------------------------

There are several steps involved in setting up a communication channel between parties. Each one of them will be explained below:
First, let's take a look of an example for setting a cummunication between 3 parties:

.. code-block:: cpp

    #include <libscapi/include/comm/Comm.hpp>

    int main(int argc, char* argv[]) {


	int numParties = 3;
	    
	//open file
	ConfigFile cf("/home/moriya/libscapi/protocols/GMW/Parties");

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
	boost::asio::io_service io_service;

	int id = atoi(argv[1]);
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

	    } else if (i>id) {// This party will be the sender in the protocol
		me = SocketPartyData(boost_ip::address::from_string(ips[id]), ports[id] + i - 1);
		cout<<"my port = "<<ports[id] + i - 1<<endl;
		other = SocketPartyData(boost_ip::address::from_string(ips[i]), ports[i] + id);
		cout<<"other port = "<< ports[i] + id<<endl;

		shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, me, other);
		// connect to party one
		channel->join(500, 5000);
		cout<<"channel established"<<endl;
	    }
	}
    }


Fetch the list of ips and ports
-------------------------------

The first step towards obtaining communication services is to setup the connections between the different parties. In order start obtaining the communication, party should first get a list of the parties' ips and ports. Each pair of ip and port represents a party in the protocol.
The ips and ports can be obtaind from a file or any other way. In the example above the reading from the file is done via ConfigFile wich is a libscapi's class that reads from a given file :   

.. code-block:: cpp

    //open file
    ConfigFile cf("/home/moriya/libscapi/protocols/GMW/Parties");

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

In the example, the parties file contains for each party in the protocol the ip and starting port number. The other port numbers are the next indices. ::

	party_0_ip = 127.0.0.1
	party_1_ip = 127.0.0.1
	party_2_ip = 127.0.0.1
	party_0_port = 8000
	party_1_port = 8020
	party_2_port = 8040


Setting up the actual communication
-----------------------------------

The actual communication is done by creating the channels and activate them. Once a channel has been activated, it can be used to write and read messages. 
Each channel communicates between two parties and uses a **single port** for each one of them. In order to create the channel, one should give the ips and ports of the parties on both channel's sides.

As we said before, the abstract communication class is ``CommParty`` and there are two concrete classes ``CommPartyTCPSynced`` and ``CommPartyTcpSslSynced``. The constructors of the concrete classes are follow: 

.. cpp:function:: CommPartyTCPSynced(boost::asio::io_service& ioService, SocketPartyData me, SocketPartyData other)

.. cpp:function:: CommPartyTcpSslSynced(boost::asio::io_service& ioService, SocketPartyData me, SocketPartyData other, string certificateChainFile, string password, string privateKeyFile, string  						tmpDHFile, string clientVerifyFile)

    :param out: ``boost::asio::io_service io_service`` - Boost's object that used in the communication.
    :param out: ``SocketPartyData me`` - An object that contains the ip and the port of this party.
    :param out: ``SocketPartyData other`` - An object that contains the ip and the port of the party that we want to communicate with.

     ``CommPartyTcpSslSynced`` also accepts the parameters for the ssl protocol:

    :param out: string certificateChainFile
    :param out: string password
    :param out: string privateKeyFile
    :param out: string tmpDHFile
    :param out: string clientVerifyFile

After the channel has been creates, it needs to get activated. This is done by the ``join`` function of the channel: 

.. cpp:function:: void join(int sleep_between_attempts, int timeout)

    This function setups a double edge connection with the the current party and the other party. The method blocks until both sides are connected to each other. In case of timeout, the communication fails and an error is thrown. 

After the join function is complete, the channel is ready to send and receive messages.

In the example above the code that creates a channel and activate it is: ::

    me = SocketPartyData(boost_ip::address::from_string(ips[id]), ports[id] + i);
    cout<<"my port = "<<ports[id] + i<<endl;
    other = SocketPartyData(boost_ip::address::from_string(ips[i]), ports[i] + id - 1);
    cout<<"other port = "<<ports[i] + id - 1<<endl;

    shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, me, other);
    // connect to party one
    channel->join(500, 5000);

First, we create a SocketPartyData for the current application with the ip and port. Second, we create a SocketPartyData for the other application and then we create the channel and activate it.


----------------------------------
Using an established connection
----------------------------------

A connection is represented by the ``CommParty`` interface. Once a channel is established, we can ``write()`` and ``read()`` data between parties.  
There are multiple write and read functions: 

.. cpp:function:: void write(const byte* data, int size)

    Writes bytes from data to the other party. This function Will write exactly size bytes. 

.. cpp:function:: void writeWithSize(const byte* data, int size)

    Writes the size of the data parameter, then writes the data itself.

.. cpp:function:: size_t read(byte* buffer, int sizeToRead)

    Reads exactly sizeToRead bytes and put them in buffer. This function Will block until all bytes are read.    

There are also functions that working on strings and vectors:
 
.. cpp:function:: void write(string s)
.. cpp:function:: void writeWithSize(string s)
.. cpp:function:: int readSize()
.. cpp:function:: size_t readWithSizeIntoVector(vector<byte> & targetVector)

