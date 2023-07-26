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

#include "../../include/comm/CommBF.hpp"

#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <string.h>
#include <errno.h>

/*****************************************/
/* CommPartyBF			                */
/*****************************************/

void CommPartyBF::writeWithSize(const unsigned char* data, int size) {
	write((const unsigned char *)&size, sizeof(int));
	write(data, size);
}

int CommPartyBF::readSize() {
	unsigned char buf[sizeof(int)];
	read(buf, sizeof(int));
	int * res = (int *)buf;
	return *res;
}

size_t CommPartyBF::readWithSizeIntoVector(std::vector<unsigned char> & targetVector) {
	int msgSize = readSize();
	targetVector.resize(msgSize);
	return read((unsigned char*)&targetVector[0], msgSize);
}

/*****************************************/
/* CommPartyTCPSyncedBoostFree           */
/*****************************************/
CommPartyTCPSyncedBoostFree::CommPartyTCPSyncedBoostFree(const char * self_addr, const u_int16_t self_port,
														 const char * peer_addr, const u_int16_t peer_port)
 : m_self_addr(self_addr), m_peer_addr(peer_addr), m_self_port(self_port), m_peer_port(peer_port)
 , lstn_fd(-1), srvc_fd(-1), clnt_fd(-1)
{
}

CommPartyTCPSyncedBoostFree::~CommPartyTCPSyncedBoostFree()
{
	if(-1 != lstn_fd) { close(lstn_fd); lstn_fd = -1; }
	if(-1 != srvc_fd) { close(srvc_fd); srvc_fd = -1; }
	if(-1 != clnt_fd) { close(clnt_fd); clnt_fd = -1; }
}

int CommPartyTCPSyncedBoostFree::prep_addr(const char * addr, const u_int16_t port, struct sockaddr_in * sockaddr)
{
	if(inet_aton(addr, &sockaddr->sin_addr) == 0)
		return -1;
	sockaddr->sin_port = htons(port);
	sockaddr->sin_family = AF_INET;
    return 0;
}

void CommPartyTCPSyncedBoostFree::join(int sleepBetweenAttempts, int timeout)
{
	//prep address structure
	struct sockaddr_in self, peer;
	if(0 != prep_addr(m_self_addr.c_str(), m_self_port, &self))
	{
		std::cerr << "join: prep_addr() failed converting self address [" << m_self_addr << "]" << std::endl;
		throw -1;
	}
	if(0 != prep_addr(m_peer_addr.c_str(), m_peer_port, &peer))
	{
		std::cerr << "join: prep_addr() failed converting peer address [" << m_self_addr << "]" << std::endl;
		throw -1;
	}

	//socket
	lstn_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(lstn_fd < 0)
	{
		int errcode = errno;
		char errmsg[256];
		std::cerr << "join: listener socket() failed with error [" << errcode << " : " << strerror_r(errcode, errmsg, 256) << "]" <<std::endl;
		throw errcode;
	}

	clnt_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(clnt_fd < 0)
	{
		int errcode = errno;
		char errmsg[256];
		std::cerr << "join: client socket() failed with error [" << errcode << " : " << strerror_r(errcode, errmsg, 256) << "]" <<std::endl;
		throw errcode;
	}

	//bind
	if(0 != bind(lstn_fd, (const struct sockaddr *)&self, (socklen_t)sizeof(struct sockaddr_in)))
	{
		int errcode = errno;
		char errmsg[256];
		std::cerr << "join: listener bind() failed with error [" << errcode << " : " << strerror_r(errcode, errmsg, 256) << "]" <<std::endl;
		throw errcode;
	}

	//listen
	if(0 != listen(lstn_fd, 1))
	{
		int errcode = errno;
		char errmsg[256];
		std::cerr << "join: listener listen() failed with error [" << errcode << " : " << strerror_r(errcode, errmsg, 256) << "]" <<std::endl;
		throw errcode;
	}

	struct timeval master_timeout;
	master_timeout.tv_usec = 1000 * (u_int32_t)sleepBetweenAttempts;
	master_timeout.tv_sec = master_timeout.tv_usec / 1000000;
	master_timeout.tv_usec = master_timeout.tv_usec % 1000000;

	//accept/connect
	bool clnt_conn = false, srvc_conn = false;
	int time_consumption = 0;
	while(!clnt_conn || !srvc_conn)
	{
		if(time_consumption > timeout)
			throw EAGAIN;

		if(!clnt_conn)
		{
			clnt_conn = (0 == connect(clnt_fd, (const struct sockaddr *)&peer, (socklen_t)sizeof(struct sockaddr_in)))? true: false;
		}

		if(!srvc_conn)
		{
			fd_set rfds;
			FD_ZERO(&rfds);
			FD_SET(lstn_fd, &rfds);

			struct timeval accept_timeout = master_timeout;
			if(0 < select(lstn_fd+1, &rfds, NULL, NULL, &accept_timeout) && FD_ISSET(lstn_fd, &rfds))
			{
				struct sockaddr addr;
				socklen_t addrlen;
				if(0 <= (srvc_fd = accept(lstn_fd, &addr, &addrlen)))
				{
					srvc_conn = true;
				}
			}
			else
			{
				time_consumption += sleepBetweenAttempts;
			}
		}
		else if(!clnt_conn)
		{
			struct timeval justa_timeout = master_timeout;
			select(0, NULL, NULL, NULL, &justa_timeout);
			time_consumption += sleepBetweenAttempts;
		}
	}
}

void CommPartyTCPSyncedBoostFree::write(const unsigned char* data, int size)
{
	struct timeval write_timeout;
	int written_size = 0, written_now;
	while(size > written_size)
	{
		write_timeout.tv_sec = 1;
		write_timeout.tv_usec = 0;

		fd_set wfds;
		FD_ZERO(&wfds);
		FD_SET(clnt_fd, &wfds);

		if(0 < select(clnt_fd+1, NULL, &wfds, NULL, &write_timeout) && FD_ISSET(clnt_fd, &wfds))
		{
			if(0 < (written_now = ::write(clnt_fd, data + written_size, size - written_size)))
			{
				written_size += written_now;
			}
		}
	}
}

size_t CommPartyTCPSyncedBoostFree::read(unsigned char* data, int sizeToRead)
{
	struct timeval read_timeout;
	int read_size = 0, read_now;
	while(sizeToRead > read_size)
	{
		read_timeout.tv_sec = 1;
		read_timeout.tv_usec = 0;

		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(srvc_fd, &rfds);

		if(0 < select(srvc_fd+1, &rfds, NULL, NULL, &read_timeout) && FD_ISSET(srvc_fd, &rfds))
		{
			if(0 < (read_now = ::read(srvc_fd, data + read_size, sizeToRead - read_size)))
			{
				read_size += read_now;
			}
		}
	}
	return (size_t)read_size;
}

