//
// Created by liork on 04/11/2019.
//

#ifdef __aarch64__
#include "../../include/interactive_mid_protocols/OTExtensionEncrypto.hpp"

OTExtensionEncryptoSender::OTExtensionEncryptoSender(string ipAddress, int port)
{
    m_socket = Listen(ipAddress, port);
    m_clock = new CLock();
    m_senderThread = new SndThread(m_socket.get(), m_clock);
    m_receiverThread = new RcvThread(m_socket.get(), m_clock);

    m_receiverThread->Start();
    m_senderThread->Start();

    m_cConstSeed = rand();

    m_crypt = new crypto(m_nSecParam, &m_cConstSeed);
    m_sender = new IKNPOTExtSnd(m_crypt, m_receiverThread, m_senderThread);

    m_sender->ComputeBaseOTs(P_FIELD);
}

shared_ptr<OTBatchSOutput> OTExtensionEncryptoSender::transfer(OTBatchSInput *input)
{
    CBitVector** X = (CBitVector**) malloc(sizeof(CBitVector*) * m_nsndvals);
    OTExtensionGeneralSInput* localInput = (OTExtensionGeneralSInput*)input;
    //copy the x0Arr and x1Arr from input to CBitVector
    X[0] = new CBitVector();
    X[0]->Copy(localInput->getX0Arr().data(), 0, localInput->getX0ArrSize());
    X[1] = new CBitVector();
    X[1]->Copy(localInput->getX1Arr().data(), 0, localInput->getX1ArrSize());

    MaskingFunction* m_fMaskFct = new XORMasking(m_bitlength);

    m_socket->ResetSndCnt();
    m_socket->ResetRcvCnt();
    // Execute OT sender routine
    int m_nNumOTThreads = 1;
    bool success;
    success = m_sender->send(m_numOTs, m_bitlength, m_nsndvals, X,
            Snd_OT, Rec_OT, m_nNumOTThreads, m_fMaskFct);

}

OTExtensionEncryptoReceiver::OTExtensionEncryptoReceiver(string ipAddress, int port)
{
    m_socket = Connect(ipAddress, port);
    m_clock = new CLock();
    m_senderThread = new SndThread(m_socket.get(), m_clock);
    m_receiverThread = new RcvThread(m_socket.get(), m_clock);

    m_receiverThread->Start();
    m_senderThread->Start();

    m_cConstSeed = rand();

    m_crypt = new crypto(m_nSecParam, &this->m_cConstSeed);
    m_receiver = new IKNPOTExtRec(m_crypt, m_receiverThread, m_senderThread);

    m_receiver->ComputeBaseOTs(P_FIELD);
}

shared_ptr<OTBatchROutput> OTExtensionEncryptoReceiver::transfer(OTBatchRInput *input)
{
    MaskingFunction* m_fMaskFct = new XORMasking(m_bitlength);
    CBitVector choices, response;
    m_numOTs = m_numOTs * ceil_log2(m_nsndvals);
    choices.Create(m_numOTs, m_crypt);
    response.Create(m_numOTs, m_bitlength);
    response.Reset();

    m_socket->ResetSndCnt();
    m_socket->ResetRcvCnt();

    bool success;
    int m_nNumOTThreads = 1;
    // Execute OT receiver routine
    success = m_receiver->receive(m_numOTs, m_bitlength, m_nsndvals, &choices, &response,
            Snd_OT, Rec_OT, m_nNumOTThreads, m_fMaskFct);
    CBitVector * data(&response);
}

#endif
