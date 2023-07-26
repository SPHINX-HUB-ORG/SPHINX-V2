//
// Created by liork on 03/11/2019.
//

#ifndef SCAPI_OTEXTENSIONENCRYPTO_HPP
#define SCAPI_OTEXTENSIONENCRYPTO_HPP

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

#include <openssl/evp.h>

#include <ENCRYPTO_utils/timer.h>
#include <ENCRYPTO_utils/socket.h>
#include <ENCRYPTO_utils/channel.h>
#include <ENCRYPTO_utils/typedefs.h>
#include <ENCRYPTO_utils/sndthread.h>
#include <ENCRYPTO_utils/rcvthread.h>
#include <ENCRYPTO_utils/cbitvector.h>
#include <ENCRYPTO_utils/connection.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include <ENCRYPTO_utils/crypto/ecc-pk-crypto.h>

#include <ot/xormasking.h>
#include <ot/iknp-ot-ext-snd.h>
#include <ot/iknp-ot-ext-rec.h>

#include "OTBatch.hpp"
#include "../comm/Comm.hpp"
#include "../cryptoInfra/SecurityLevel.hpp"

using namespace std;

/**
 * A sender side of the Encrypto ot extension
 * The sender does not need to provide an IP, since is listens on local host, It only needs to provide the
 * port on which it listens to.
 *
 */
class OTExtensionEncryptoSender: public OTBatchSender{

public:
    OTExtensionEncryptoSender(const string ipAddress="127.0.0.1", int port=7766);
    virtual shared_ptr<OTBatchSOutput> transfer(OTBatchSInput * input) override;

private:
    OTExtSnd *m_sender;			//The OT object that used in the protocol.
    shared_ptr<CSocket> m_socket;
    SndThread* m_senderThread;
    RcvThread* m_receiverThread;
    uint32_t m_nSecParam = 128;
    uint32_t m_bitlength = 8;
    uint64_t m_numOTs = 1;
    uint32_t m_nsndvals = 2;
    uint8_t m_cConstSeed = 68; // DEBUG ONLY
    const int m_nBaseOTs = 190;
    const int m_nChecks = 380;
    CLock *m_clock;
    crypto *m_crypt;

};


/**
 * A receiver side of the Encrypto ot extension for both the semi honest and malicious adversaries.
 * The receiver should provide the sender's address since that is the hostname it should connect to.
 *
 */
class OTExtensionEncryptoReceiver: public OTBatchReceiver{

public:
    OTExtensionEncryptoReceiver(string ipAddress="127.0.0.1", int port=7766);
    virtual shared_ptr<OTBatchROutput> transfer(OTBatchRInput * input) override;

private:
    OTExtRec * m_receiver;  //The OT object that used in the protocol.
    shared_ptr<CSocket> m_socket;
    SndThread* m_senderThread;
    RcvThread* m_receiverThread;
    uint32_t m_nSecParam = 128;
    uint32_t m_bitlength = 8;
    uint64_t m_numOTs = 1;
    uint32_t m_nsndvals = 2;
    uint8_t m_cConstSeed = 156; // DEBUG ONLY
    const int m_nBaseOTs = 190;
    const int m_nChecks = 380;
    CLock *m_clock;
    crypto *m_crypt;
};



#endif //SCAPI_OTEXTENSIONENCRYPTO_HPP
