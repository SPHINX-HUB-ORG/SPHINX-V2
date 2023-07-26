//
// Created by roee on 1/16/19.
//

#ifndef CONNECTIONLESS_PROTOCOL_PEERINFO_H
#define CONNECTIONLESS_PROTOCOL_PEERINFO_H

#include <netinet/in.h>

#include <string>

class PeerInfo {
public:
//  PeerInfo();
  PeerInfo(int id, const std::string &ip, int port, const std::string &cat, int fd = -1);
  ~PeerInfo();

  PeerInfo & operator=(const PeerInfo&) = delete;
//  PeerInfo(const PeerInfo&) = delete;
  PeerInfo() = delete;

  explicit operator std::string() const;

  std::string ip() const;
  int port() const;
  const struct sockaddr_in* addr() const;
  int &fd();
  const int &fd() const;
  std::string cat() const;

private:
  int mId;
  std::string mIp;
  int mPort;
  int mFd;
  std::string mCat;

  struct sockaddr_in mPeerAddr; // Peer address
};


#endif //CONNECTIONLESS_PROTOCOL_PEERINFO_H
