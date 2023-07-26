//
// Created by liork on 3/18/19.
//

#ifdef __x86_64__
#ifndef __APPLE__
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>

#include "../../include/comm/CommUDP.hpp"
#include "../../include/comm/utils.h"


#define NUM_MESSAGES 100


/*
 * Callback for UDP messages
 * */
int udp_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
    const PeerInfo *peer = static_cast<const PeerInfo *>(user);
    const struct sockaddr *addr = reinterpret_cast<const struct sockaddr *>(peer->addr());
    const int &fd = peer->fd();

    int ret;

    if ((ret = sendto(fd, buf, len, 0, addr, sizeof(*addr))) < 0)
    { // TODO: use return value, mb a loop is needed
        log4cpp::Category::getInstance(((const PeerInfo *)user)->cat()).errorStream()
                << "sendto failed, errno: " << errno << "[" << strerror(errno)
                << "] (file: " << __FILE__ << ", line: " << __LINE__ << ")";
        std::cerr
                << "sendto failed, errno: " << errno << "[" << strerror(errno)
                << "] (file: " << __FILE__ << ", line: " << __LINE__ << ")";

        return -1;
    }

    return 0;
}


void writelog(const char *log, struct IKCPCB *kcp, void *user)
        {log4cpp::Category::getInstance((((const PeerInfo *)user)->cat())).debug(log);}


CommUDP::CommUDP(int pid, int numPeers, const string &configFile, int numProtocols, string cat):
        mPid(pid), mNumPeers(numPeers), mNumProtocols(numProtocols), mFd(-1), mCat(cat),
        mDone(false), mKill(false), mThreadUpdateConnections(nullptr), mThreadReadSocket(nullptr)
{
    assert(0 < mNumProtocols && mNumProtocols <= (1 <<4));
    log4cpp::Category::getInstance(mCat + ".ctor").info("network started");

    mPeers.reserve(mNumPeers);
    mConnections.resize(mNumPeers * mNumProtocols);
    mUpdateTimes.resize(mNumPeers * mNumProtocols);
    mConnDirty.resize(mNumPeers * mNumProtocols);
    mMutex.resize(mNumPeers * mNumProtocols);

    for(int i = 0; i < mNumPeers; i++)
        mMutex[i * mNumProtocols] = new mutex;

    log4cpp::Category::getInstance(mCat + ".ctor").info("parsing peers information");

    std::ifstream config(configFile);

    // assign each address port to party id
    for (int i = 0; i < mNumPeers; ++i)
    {
        string ip, port;
        config >> ip >> port;

        mPeers.emplace_back(PeerInfo{i, ip, stoi(port), mCat});

        const struct sockaddr_in *addr = mPeers.back().addr();

        mConnMap.insert(make_pair(make_pair(addr->sin_addr.s_addr, addr->sin_port), i));
    }

    initNetwork();  // Bind UDP port, assign mFd

    for (int i = 0; i < mNumPeers; ++i)
        mPeers[i].fd() = mFd;

    log4cpp::Category::getInstance(mCat + ".ctor").info("creating ikcp objects");

    for (int i = 0; i < mNumPeers; ++i)
    {
        if (mPid == i)
            continue;

        for (int j = 0; j < mNumProtocols; ++j)
        {
            //TODO Ask roee what he wants here

            // Calculate "conv" number (14 bits - smaller pid, 14 bits - bigger pid, 2 bits - protocol number)
            IUINT32  conv = 0;

            conv |= min(mPid, i);
            conv <<= 14;
            conv |= max(mPid, i);
            conv <<= 14;
            conv |= j;

            mConnections[i * mNumProtocols + j] = ikcp_create(conv, (void*) &mPeers[i]);
            ikcp_setoutput(mConnections[i * mNumProtocols + j], udp_output);

            if (log4cpp::Category::getInstance(mCat).isDebugEnabled())
            {
                mConnections[i * numProtocols + j]->writelog = writelog;
                mConnections[i * numProtocols + j]->logmask = 4096 - 1 - 1 - 2;
            }
        }
    }
}

int CommUDP::join(int sleepBetweenAttempts, int timeout, bool first)
{
    int ret;

    if (first)
    {
        timeval read_timeout;
        read_timeout.tv_sec = 0;
        read_timeout.tv_usec = 500000;

        if (setsockopt(mFd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout)) < 0)
        {
            log4cpp::Category::getInstance(mCat + ".dtor").warnStream()
                    << "setsockopt failed, errno: " << errno << "[" << strerror(errno)
                    << "] (file: " << __FILE__ << ", line: " << __LINE__ << ")";
        }

        mThreadReadSocket = new std::thread(&CommUDP::readSocket, this);
        mThreadUpdateConnections = new std::thread(&CommUDP::updateConnections, this);
    }

    for (int i = 0; i < mNumPeers; i++)
    {
        if (mPid == i)
            continue;

        ret = write((const byte*)"0", 1, i, 0); // Send byte for sync
        KCP_CHECK(ret, mCat + ".sync")
    }

    std::atomic<int> cnt; // For future multi-threading
    std::vector<bool> syncs(mNumPeers);

    cnt = 0;
    while (cnt < mNumPeers - 1)
    {
        byte b;

        for (int i = 0; i < mNumPeers; i++)
        {
            if (mPid == i)
                continue;

            if (syncs[i])
                continue;

            ret = read(&b, 1, i, 0);
            if (ret < 0) {
                continue;
            }
            else if (ret == 1)
            {
                if (b == '0')
                {
                    log4cpp::Category::getInstance(mCat + ".sync").infoStream() << "got sync from " << i;
                    syncs[i] = true;
                    ++cnt;
                }
                else
                    log4cpp::Category::getInstance(mCat + ".sync").warnStream()
                            << "and un recoginzed message (" << b << ") was received from " << i;
            }
            else  // Should never happen
                log4cpp::Category::getInstance(mCat + ".sync").warnStream()
                        << "got from " << i << " " << ret  << " bytes (expected: " << (ssize_t)(1) << ")";
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    return ret;
}


size_t CommUDP::write(const byte *data, int size, int peer, int protocol)
{
    assert(0 <= peer  && peer < mNumPeers && peer != mPid);
    assert(0 <= protocol && protocol < mNumProtocols);

    mMutex[peer * mNumProtocols + protocol]->lock();
    size_t ret = ikcp_send(mConnections[peer * mNumProtocols + protocol], (const char *)data, size);
    mConnDirty[peer * mNumProtocols + protocol] = true;
    mMutex[peer * mNumProtocols + protocol]->unlock();

    return ret;
}

size_t CommUDP::read(byte *buffer, int sizeToRead, int peer, int protocol)
{
    assert(0 <= peer && peer < mNumPeers && peer!= mPid);
    assert(0 <= protocol && protocol < mNumProtocols);

    return ikcp_recv(mConnections[peer * mNumProtocols + protocol], (char*)buffer, sizeToRead);
}

bool CommUDP::initNetwork()
{
    struct sockaddr_in myaddr;      /* our address */

    /* create a UDP socket */
    if ((mFd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        log4cpp::Category::getInstance(mCat + ".initNetwork").errorStream()
                << "cannot create socket (file: " << __FILE__ << ", line: " << __LINE__ << ")";

        return false;
    }

    /* bind the socket to any valid IP address and a specific port */
    memset((char *)&myaddr, 0, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    myaddr.sin_port = htons(mPeers[mPid].port());

    if (bind(mFd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0)
    {
        log4cpp::Category::getInstance(mCat + ".initNetwork").errorStream()
                << "bind failed (file: " << __FILE__ << ", line: " << __LINE__ << ")";

        return false;
    }

    log4cpp::Category::getInstance(mCat + ".initNetwork").debugStream()
            << "listening on port " << mPeers[mPid].port() << " UDP (fd: " << mFd << ")";

    return true;
}


void CommUDP::cleanUp()
{
    mDone = true;

    mThreadReadSocket->join();
    mThreadUpdateConnections->join();
}

void CommUDP::readSocket()
{
    int counter = 0;
    mmsghdr msgvec[NUM_MESSAGES];
    iovec iovec[NUM_MESSAGES];
    char bufs[NUM_MESSAGES][4096];

    for (int i = 0; i < NUM_MESSAGES; i++)
    {
        msgvec[i].msg_hdr.msg_name = new sockaddr_in;
        msgvec[i].msg_hdr.msg_namelen = sizeof(sockaddr_in);

        iovec[i].iov_base = bufs[i];
        iovec[i].iov_len = 4095;

        msgvec[i].msg_hdr.msg_iov = iovec + i;
        msgvec[i].msg_hdr.msg_iovlen = 1;
        msgvec[i].msg_hdr.msg_flags = 0;
    }

    while (!mKill)
    {
        int recvlen;
        recvlen = recvmmsg(mFd, msgvec, NUM_MESSAGES, 0, NULL);

        if (recvlen == -1)
        {
            if (mDone)
                log4cpp::Category::getInstance(mCat + ".initNetwork").debugStream() << "update counter " << counter;
            if (mDone && (++counter >= 15))
            {
                mKill = true;
                break;
            }

            continue;
        }

        counter = 0;

        for (int i = 0; i < recvlen; i++)
        {
            std::map<std::pair<in_addr_t, in_port_t>, int>::iterator conn =
                    mConnMap.find( { static_cast<sockaddr_in *>(msgvec[i].msg_hdr.msg_name)->sin_addr.s_addr,
                                     static_cast<sockaddr_in *>(msgvec[i].msg_hdr.msg_name)->sin_port });
            if (mConnMap.end() != conn)
            {
                mMutex[conn->second]->lock();
                int ret = ikcp_input(mConnections[conn->second], reinterpret_cast<char *>(iovec[i].iov_base), msgvec[i].msg_len);
                IUINT32 current = iclock();
                ikcp_update(mConnections[conn->second], current);
                mUpdateTimes[conn->second] = ikcp_check(mConnections[conn->second], current);
                mMutex[conn->second]->unlock();
                KCP_CHECK(ret, mCat + ".readSocket");
            }
        }

        if (recvlen != NUM_MESSAGES)
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    for (int i = 0; i < NUM_MESSAGES; i++)
        delete reinterpret_cast<sockaddr_in *>(msgvec[i].msg_hdr.msg_name);
}

void CommUDP::updateConnections()
{
    while (!mKill)
    {
        IUINT32 current = iclock(), min_check = 10000 + current; // 10 miliseconds

        for (int i = 0; i < mNumPeers; i++)
        {
            if (mPid == i)
                continue;

            if (mConnDirty[i * mNumProtocols] ||  mUpdateTimes[i * mNumProtocols] < current)
            {
                mMutex[i * mNumProtocols]->lock();
                current = iclock();
                ikcp_update(mConnections[i * mNumProtocols], current);
                mUpdateTimes[i * mNumProtocols] = ikcp_check(mConnections[i * mNumProtocols], current);
                mConnDirty[i * mNumProtocols] = false;
                mMutex[i * mNumProtocols]->unlock();
            }

            if(mUpdateTimes[i * mNumProtocols] < min_check)
                min_check = mUpdateTimes[i * mNumProtocols];
        }

        if(min_check > current)
            std::this_thread::sleep_for(std::chrono::milliseconds(min_check - current));
    }
}

#endif
#endif
