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

#include <string>
#include <vector>

/**
* A simple interface that encapsulate all network operations of one peer in a two peers (or more)
* setup.
*/
class CommPartyBF {
public:
	/**
	* This method setups a double edge connection with another party.
	* It connects to the other party, and also accepts connections from it.
	* The method blocks until boths side are connected to each other.
	*/
	virtual void join(int sleep_between_attempts, int timeout) = 0;
	/**
	* Write data from @param data to the other party.
	* Will write exactly @param size bytes
	*/
	virtual void write(const unsigned char * data, int size) = 0;
	/**
	* Read exactly @param sizeToRead bytes int @param buffer
	* Will block until all bytes are read.
	*/
	virtual size_t read(unsigned char* buffer, int sizeToRead) = 0;
	virtual void write(std::string s) { write((const unsigned char *)s.c_str(), s.size()); };
	virtual void writeWithSize(const unsigned char* data, int size);
	virtual int readSize();
	virtual size_t readWithSizeIntoVector(std::vector<unsigned char> & targetVector);
	virtual void writeWithSize(std::string s) { writeWithSize((const unsigned char*)s.c_str(), s.size()); };
	virtual ~CommPartyBF() {};
};

class CommPartyTCPSyncedBoostFree : public CommPartyBF {
public:
	CommPartyTCPSyncedBoostFree(const char * self_addr, const u_int16_t self_port,
								const char * peer_addr, const u_int16_t peer_port);
	virtual ~CommPartyTCPSyncedBoostFree();

	void join(int sleepBetweenAttempts = 500, int timeout = 5000);

	void write(const unsigned char* data, int size);
	size_t read(unsigned char* data, int sizeToRead);

private:
	std::string m_self_addr, m_peer_addr;
	u_int16_t m_self_port, m_peer_port;
	int lstn_fd, srvc_fd, clnt_fd;

	static int prep_addr(const char * addr, const u_int16_t port, struct sockaddr_in * sockaddr);
};
