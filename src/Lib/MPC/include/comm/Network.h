//
// Created by roee on 1/16/19.
//

#ifndef CONNECTIONLESS_PROTOCOL_NETWORK_H
#define CONNECTIONLESS_PROTOCOL_NETWORK_H

#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <KCP/ikcp.h>
#include "PeerInfo.h"

class Network {
public:
  Network(int pid, int numPeers, const std::string &config_file, int numProtocols, std::string cat);
  ~Network();

  int send(int peer, int protocol, const char *buffer, int len);
  int recv(int peer, int protocol, char *buffer, int len);
  void update(int peer, int protocol);
  void flush(int peer, int protocol);

  bool sync(bool first = false);
  bool round(int rid, int data_size);

protected:
  bool initNetwork();
  void cleanUp();
  void readSocket();
  void updateConnections();

  const PeerInfo& getPeer(int id);

  int mPid;
  int mNumPeers;      ///< Total number of peers
  int mNumProtocols;  ///< Number of parallel protocols
  int mFd;            ///< UDP socket file descriptor
  std::string mCat;   ///< Logging category

  std::vector<PeerInfo> mPeers;
  std::vector<ikcpcb *> mConnections;
  std::vector<IUINT32> mUpdateTimes;
  std::vector<bool> mConnDirty;
  std::vector<std::mutex *> mMutex;

  std::map<std::pair<in_addr_t, in_port_t>, int> mConnMap;

  bool mDone, mKill; ///< Flags for termination

  std::thread *mThreadUpdateConnections, *mThreadReadSocket;
};


#endif //CONNECTIONLESS_PROTOCOL_NETWORK_H
