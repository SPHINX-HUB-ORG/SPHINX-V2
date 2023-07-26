//
// Created by roee on 1/16/19.
//

#include "../../include/comm/PeerInfo.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <cstring>
#include <iostream>

//PeerInfo::PeerInfo() : mId(-1), mIp(), mPort(-1)  {
//  std::cout << "peer default ctor" << std::endl;
//}

PeerInfo::PeerInfo(int id, const std::string &ip, int port, const std::string &cat, int fd)
: mId(id), mIp(ip), mPort(port), mFd(fd), mCat(cat) {
  // Initialize sockaddr_in structure
  memset((char*)&mPeerAddr, 0, sizeof(mPeerAddr));
  mPeerAddr.sin_family = AF_INET;
  mPeerAddr.sin_port = htons(mPort);
  inet_aton(ip.c_str(), &mPeerAddr.sin_addr);
}

PeerInfo::~PeerInfo() {

}

PeerInfo::operator std::string() const {
  return (this->mIp) + std::string(":") +
         std::to_string(this->mPort);
}

std::string PeerInfo::ip() const {
  return this->mIp;
}

int PeerInfo::port() const {
  return this->mPort;
}

const struct sockaddr_in* PeerInfo::addr() const {
  return &this->mPeerAddr;
}

int &PeerInfo::fd() {
  return this->mFd;
}

const int &PeerInfo::fd() const {
  return this->mFd;
}

std::string PeerInfo::cat() const {
	return mCat;
}
