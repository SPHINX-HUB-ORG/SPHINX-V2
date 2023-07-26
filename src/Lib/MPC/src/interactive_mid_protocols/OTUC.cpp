//
// Created by moriya on 06/03/17.
//
#include "../../include/interactive_mid_protocols/OTUC.hpp"

OTUCDDHOnGroupElementSender::OTUCDDHOnGroupElementSender(const shared_ptr<DlogGroup> & dlog, const shared_ptr<GroupElement> &  g0,
                            const shared_ptr<GroupElement> &  g1, const shared_ptr<GroupElement> &  h0,
                            const shared_ptr<GroupElement> &  h1, const shared_ptr<PrgFromOpenSSLAES> & random){
    //The underlying dlog group must be DDH secure.
    auto ddh = dynamic_pointer_cast<DDH>(dlog);
    if (ddh == NULL) {
        throw SecurityLevelException("DlogGroup should have DDH security level");
    }

    this->dlog = dlog;
    this->random = random;
    this->g0 = g0;
    this->g1 = g1;
    this->h0 = h0;
    this->h1 = h1;
    cout<<"g0 = "<<g0->generateSendableData()->toString()<<endl;
    cout<<"g1 = "<<g1->generateSendableData()->toString()<<endl;
    cout<<"h0 = "<<h0->generateSendableData()->toString()<<endl;
    cout<<"h1 = "<<h1->generateSendableData()->toString()<<endl;
    // This protocol has no pre process stage.
}

void OTUCDDHOnGroupElementSender::transfer(CommParty* channel, OTSInput* input) {
    //Creates the utility class that executes the transfer phase.
    OTFullSimOnGroupElementSenderTransferUtil transferUtil(dlog, random);
    OTFullSimPreprocessPhaseValues values(g0, g1, h0, h1);
    transferUtil.transfer(channel, input, &values);
}

OTUCDDHOnGroupElementReceiver::OTUCDDHOnGroupElementReceiver(const shared_ptr<DlogGroup> & dlog,
                              const shared_ptr<GroupElement> & g0, const shared_ptr<GroupElement> & g1,
                              const shared_ptr<GroupElement> & h0, const shared_ptr<GroupElement> & h1,
                              const shared_ptr<PrgFromOpenSSLAES> & random) {
    //The underlying dlog group must be DDH secure.
    auto ddh = dynamic_pointer_cast<DDH>(dlog);
    if (ddh == NULL) {
        throw SecurityLevelException("DlogGroup should have DDH security level");
    }

    this->dlog = dlog;
    this->random = random;
    this->g0 = g0;
    this->g1 = g1;
    this->h0 = h0;
    this->h1 = h1;
cout<<"g0 = "<<g0->generateSendableData()->toString()<<endl;
    cout<<"g1 = "<<g1->generateSendableData()->toString()<<endl;
    cout<<"h0 = "<<h0->generateSendableData()->toString()<<endl;
    cout<<"h1 = "<<h1->generateSendableData()->toString()<<endl;
    // This protocol has no pre process stage.
}

/**
 *
 * Run the transfer phase of the OT protocol.
 * Transfer Phase (with input sigma)
 *		SAMPLE a random value r <- {0, . . . , q-1}
 *		COMPUTE
 *		4.	g = (gSigma)^r
 *		5.	h = (hSigma)^r
 *		SEND (g,h) to S
 *		WAIT for messages (u0,c0) and (u1,c1) from S
 *		IF  NOT
 *			u0, u1, c0, c1 in G
 *		      REPORT ERROR
 *		OUTPUT  xSigma = cSigma * (uSigma)^(-r)
 */
shared_ptr<OTROutput> OTUCDDHOnGroupElementReceiver::transfer(CommParty* channel, OTRInput* input){
    //Creates the utility class that executes the transfer phase.
    OTFullSimOnGroupElementReceiverTransferUtil transferUtil(dlog, random);
    OTFullSimPreprocessPhaseValues values(g0, g1, h0, h1);
    return transferUtil.transfer(channel, input, &values);
}

OTUCDDHOnByteArraySender::OTUCDDHOnByteArraySender(const shared_ptr<DlogGroup> & dlog, const shared_ptr<GroupElement> & g0,
    const shared_ptr<GroupElement> & g1, const shared_ptr<GroupElement> & h0, const shared_ptr<GroupElement> & h1,
    const shared_ptr<KeyDerivationFunction> & kdf, const shared_ptr<PrgFromOpenSSLAES> & random){

    //The underlying dlog group must be DDH secure.
    auto ddh = dynamic_pointer_cast<DDH>(dlog);
    if (ddh == NULL) {
        throw SecurityLevelException("DlogGroup should have DDH security level");
    }

    this->dlog = dlog;
    this->random = random;
    this->kdf = kdf;
    this->g0 = g0;
    this->g1 = g1;
    this->h0 = h0;
    this->h1 = h1;

    // This protocol has no pre process stage.
}

void OTUCDDHOnByteArraySender::transfer(CommParty* channel, OTSInput* input) {

    //Creates the utility class that executes the transfer phase.
    OTFullSimOnByteArraySenderTransferUtil transferUtil(dlog, kdf ,random);
    OTFullSimPreprocessPhaseValues values(g0, g1, h0, h1);
    transferUtil.transfer(channel, input, &values);
}

OTUCDDHOnByteArrayReceiver::OTUCDDHOnByteArrayReceiver(const shared_ptr<DlogGroup> & dlog, const shared_ptr<GroupElement> & g0,
                           const shared_ptr<GroupElement> & g1, const shared_ptr<GroupElement> & h0,
                           const shared_ptr<GroupElement> & h1, const shared_ptr<KeyDerivationFunction> & kdf,
                           const shared_ptr<PrgFromOpenSSLAES> & random) {
    //The underlying dlog group must be DDH secure.
    auto ddh = dynamic_pointer_cast<DDH>(dlog);
    if (ddh == NULL) {
        throw SecurityLevelException("DlogGroup should have DDH security level");
    }

    this->dlog = dlog;
    this->kdf = kdf;
    this->random = random;
    this->g0 = g0;
    this->g1 = g1;
    this->h0 = h0;
    this->h1 = h1;

    // This protocol has no pre process stage.
}

shared_ptr<OTROutput> OTUCDDHOnByteArrayReceiver::transfer(CommParty* channel, OTRInput* input) {
    //Creates the utility class that executes the transfer phase.
    OTFullSimOnByteArrayReceiverTransferUtil transferUtil(dlog, kdf, random);

    OTFullSimPreprocessPhaseValues values(g0, g1, h0, h1);
    return transferUtil.transfer(channel, input, &values);
}