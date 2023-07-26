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


#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "Comm.hpp"
#include "../../lib/KCP/ikcp.h"
#include "PeerInfo.h"

class CommUDP: public CommParty {
public:

    CommUDP(int pid, int numPeers, const string & configFile, int numProtocols, string cat);
    ~CommUDP(){};
    int join(int sleepBetweenAttempts = 500, int timeout = 5000, bool first = true) override;

    size_t write(const byte* data, int size, int peer=-1, int protocol=-1) override;
    size_t read(byte* buffer, int sizeToRead, int peer=-1, int protocol=-1) override;

private:

    bool initNetwork();
    void cleanUp();
    void readSocket();
    void updateConnections();

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