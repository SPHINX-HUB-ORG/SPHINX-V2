Quickstart
==========

Eager to get started? This page gives a good introduction to Libscapi. It assumes you already have libscapi installed. If you do not, head over to the :ref:`Installation <install>` section.


Your First libscapi Application
-------------------------------

We begin with a minimal application and go through some basic examples.

.. sourcecode:: cpp
    :emphasize-lines: 22
    
    #include "../../include/primitives/DlogOpenSSL.hpp"

    int main(int argc, char* argv[]){
	// initiate a discrete log group
	// (in this case the OpenSSL implementation of the elliptic curve group K-233)
	DlogGroup* dlog = new OpenSSLDlogECF2m("include/configFiles/NISTEC.txt", "K-233");

	// get the group generator and order
	auto g = dlog->getGenerator();
	biginteger q = dlog->getOrder();

	// create a random exponent r
	shared_ptr<PrgFromOpenSSLAES> gen = get_seeded_prg();
	biginteger r = getRandomInRange(0, q - 1, gen.get());

	// exponentiate g in r to receive a new group element
	auto g1 = dlog->exponentiate(g.get(), r);
	// create a random group element
	auto h = dlog->createRandomElement();
	// multiply elements
	auto gMult = dlog->multiplyGroupElements(g1.get(), h.get());
    }


Pay attention to the definition of the discrete log group. In libscapi we will always use a generic data type
such as ``DlogGroup`` instead of a more specified data type. This allows us to replace the group to a
different implementation or a different group entirely, without changing our code.

Let's break it down:
~~~~~~~~~~~~~~~~~~~~

We include the libscapi primitive ``OpenSSLDlogECF2m`` class that extends the ``DlogGroup`` abstract class (implements a discrete log group). This is a wrapper class to an implementation of an elliptic curve group in the OpenSSL library. Since ``DlogGroup`` is abstract class, we can easily choose a different group without changing a single line of code except the one in emphasis.

We also use the get_seeded_prg() function implemented by libscapi, that returns an object of type PrgFromOpenSSlAES. This is a libscapi's class that provides a cryptographically pseudo random generator. 

In order to handle big numbers we use the ``biginteger`` define that represents boost::multiprecision::mpz_int in linux systems and boost::multiprecision::cpp_int in windows.

.. sourcecode:: cpp

     #include "../../include/primitives/DlogOpenSSL.hpp"

Our main class defines a discrete log group, and then extract the group properties (generator and order).

.. sourcecode:: cpp

    // initiate a discrete log group
    // (in this case the OpenSSL implementation of the elliptic curve group K-233 
    // using the NISTEC.txt file that provided by libscapi that is a at libscapi/include/configFiles)
    DlogGroup* dlog = new OpenSSLDlogECF2m("include/configFiles/NISTEC.txt", "K-233");

    // get the group generator and order
    auto g = dlog->getGenerator();
    biginteger q = dlog->getOrder();

We then choose a random exponent, and exponentiate the generator in this exponent.

.. sourcecode:: cpp

    // create a random exponent r
    shared_ptr<PrgFromOpenSSLAES> gen = get_seeded_prg();
    biginteger r = getRandomInRange(0, q - 1, gen.get());

    // exponentiate g in r to receive a new group element
    auto g1 = dlog->exponentiate(g.get(), r);

We then select another group element randomly.

.. sourcecode:: cpp

    // create a random group element
    auto h = dlog->createRandomElement();

Finally, we demonstrate how to multiply group elements.

.. sourcecode:: cpp

    // multiply elements
    auto gMult = dlog->multiplyGroupElements(g1.get(), h.get());

Compiling and Running the libscapi Code
---------------------------------------

Save this example to a file called *DlogExample.cpp*. In order to compile this file, type in the terminal: ::

    $ g++ example.cpp -I/home/moriya -I/home/moriya/boost_1_60_0 -std=c++11 scapi.a -lboost_system -L/home/moriya/boost_1_60_0/stage/lib -lssl -lcrypto -lgmp

Note that we use the scapi.a which is the libscapi lirary. The -I command sets the include files to use in the program and the -l command sets the libraries to link to the program. 

A file called *a.out* should be created as a result. In order to run this file, type in the terminal: ::

    $ ./a.out


Establishing Secure Communication
---------------------------------

The first thing that needs to be done to obtain communication services is to setup the connections between the different parties. Libscapi provides two communication types - tcp communication and ssl tcp communication. The abstract communication class called ``commParty`` and the concrete classes are ``CommPartyTCPSynced`` and ``CommPartyTcpSslSynced``. Both communication types use ``boost::asio::io_service`` in order to set communication between the parties.

Let's get a look at the following code:

.. code-block:: cpp
    :emphasize-lines: 19

    #include <libscapi/include/comm/Comm.hpp>

    int main(int argc, char* argv[]) {

	boost::asio::io_service io_service;
	SocketPartyData me, other;
	if (atoi(argv[1]) == 0){
		me = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);
		other = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);
	} else {
		me = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);
		other = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);
	}
        
        shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, me, other);
        // connect to party one
        channel->join(500, 5000);
        cout<<"channel established"<<endl;
    }

In this example, we establish a communication between two parties in the same machine, using ports 8000 and 8001. 

A ``CommParty`` represents an established connection between two parties. It has two main functions: ::

    void write(const byte* data, int size)

Sends a message *data* to the other party, the number of bytes in *data* should be equal to *size*. ::

    size_t read(byte* buffer, int sizeToRead)

Receives a message with *sizeToRead* bytes from the channel. The buffer should have at least sizeToRead bytes.

This means that from the applications point of view, once it obtains the channels it can completely forget about it and just send and receive messages.

..
   How to set an Encrypted Channel manually
   ----------------------------------------

   Some text.

   Using Public Key Encryption
   ---------------------------

   Some text.

   Using 1-out-of-2 Oblivious Trasfer
   ----------------------------------

   Some text.

   Using Commitment Schemes
   ------------------------

   Some text.

   Using Sigma Protocols
   ---------------------

   Some text.

   Using Zero Knowledge Proofs
   ---------------------------

   Some text.

