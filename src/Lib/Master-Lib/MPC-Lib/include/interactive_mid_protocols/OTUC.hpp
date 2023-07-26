//
// Created by moriya on 06/03/17.
//

#pragma once

#include "OT.hpp"
#include "../cryptoInfra/SecurityLevel.hpp"
#include "../primitives/Kdf.hpp"
#include "OTFullSimulation.hpp"

/**
 * Concrete class for OT sender based on the DDH assumption that achieves UC security in
 * the common reference string model.
 * This implementation is based on the protocol of Peikert, Vaikuntanathan and Waters (CRYPTO 2008) for achieving UC-secure OT.
 *
 * This is implementation in GroupElement mode, derived from OTUCDDHSenderAbs and implements the functionality
 * related to the byte array inputs.
 *
 * The pseudo code of this protocol can be found in Protocol 4.6 of pseudo codes document at <a href="http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf">http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf</a>.<p>
 *
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
class OTUCDDHOnGroupElementSender : public OTSender, Malicious, UC {

private:
    shared_ptr<PrgFromOpenSSLAES> random;
    shared_ptr<GroupElement> g0, g1, h0, h1; //Common reference string
    shared_ptr<DlogGroup> dlog;

public:
    /**
     * Constructor that sets the given common reference string composed of a DLOG
     * description (G,q,g0) and (g0,g1,h0,h1) which is a randomly chosen non-DDH tuple,
     * kdf and random.
     */
    OTUCDDHOnGroupElementSender(const shared_ptr<DlogGroup> & dlog, const shared_ptr<GroupElement> &  g0,
                                const shared_ptr<GroupElement> &  g1, const shared_ptr<GroupElement> &  h0,
                                const shared_ptr<GroupElement> &  h1, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

    /**
     * Runs the transfer phase of the OT protocol.
     *	Transfer Phase (with inputs x0,x1)
     *	WAIT for message from R
     *	DENOTE the values received by (g,h)
     *	COMPUTE (u0,v0) = RAND(g0,g,h0,h)
     *	COMPUTE (u1,v1) = RAND(g1,g,h1,h)
     *	COMPUTE c0 = x0 * v0
     *	COMPUTE c1 = x1 * v1
     *	SEND (u0,c0) and (u1,c1) to R
     *	OUTPUT nothing
     */
    void transfer(CommParty* channel, OTSInput* input) override;

};

/**
 * Concrete class for OT receiver based on the DDH assumption that achieves UC security in
 * the common reference string model.
 * This implementation is based on the protocol of Peikert, Vaikuntanathan and Waters (CRYPTO 2008) for achieving UC-secure OT.
 *
 * This is implementation in GroupElement mode, derived from OTUCDDHReceiverAbs and implements the functionality
 * related to the byte array inputs.
 *
 * The pseudo code of this protocol can be found in Protocol 4.6 of pseudo codes document at <a href="http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf">http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf</a>.<p>
 *
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
class OTUCDDHOnGroupElementReceiver : public OTReceiver, Malicious, UC{

private:
    shared_ptr<DlogGroup> dlog;
    shared_ptr<PrgFromOpenSSLAES> random;
    shared_ptr<GroupElement> g0, g1, h0, h1; //Common reference string

public:
    /**
     * Constructor that sets the given common reference string composed of a DLOG
     * description (G,q,g0) and (g0,g1,h0,h1) which is a randomly chosen non-DDH tuple,
     * kdf and random.
     */
    OTUCDDHOnGroupElementReceiver(const shared_ptr<DlogGroup> & dlog, const shared_ptr<GroupElement> & g0,
                                  const shared_ptr<GroupElement> & g1, const shared_ptr<GroupElement> & h0,
                                  const shared_ptr<GroupElement> & h1, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

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
    shared_ptr<OTROutput> transfer(CommParty* channel, OTRInput* input) override;
};

/**
 * Concrete class for OT sender based on the DDH assumption that achieves UC security in
 * the common reference string model.
 * This implementation is based on the protocol of Peikert, Vaikuntanathan and Waters (CRYPTO 2008) for achieving UC-secure OT.
 *
 * This is implementation in BYTE ARRAY mode, derived from OTUCDDHSenderAbs and implements the functionality
 * related to the byte array inputs.
 *
 * The pseudo code of this protocol can be found in Protocol 4.6 of pseudo codes document at <a href="http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf">http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf</a>.<p>
 *
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
class OTUCDDHOnByteArraySender : public OTSender, Malicious, UC{
private:

    shared_ptr<KeyDerivationFunction> kdf; //Used in the calculation.
    shared_ptr<PrgFromOpenSSLAES> random;
    shared_ptr<GroupElement> g0, g1, h0, h1; //Common reference string
    shared_ptr<DlogGroup> dlog;

public:
    /**
     * Constructor that sets the given common reference string composed of a DLOG
     * description (G,q,g0) and (g0,g1,h0,h1) which is a randomly chosen non-DDH tuple,
     * kdf and random.
     * @param dlog must be DDH secure.
     */
    OTUCDDHOnByteArraySender(const shared_ptr<DlogGroup> & dlog, const shared_ptr<GroupElement> & g0,
         const shared_ptr<GroupElement> & g1, const shared_ptr<GroupElement> & h0, const shared_ptr<GroupElement> & h1,
         const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>("SHA-256")),
         const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

    /**
     * Runs the transfer phase of the OT protocol.
     * This is the part of the protocol where the sender's input is necessary as follows:
     *	Transfer Phase (with inputs x0,x1)
     *	WAIT for message from R
     *	DENOTE the values received by (g,h)
     *	COMPUTE (u0,v0) = RAND(g0,g,h0,h)
     *	COMPUTE (u1,v1) = RAND(g1,g,h1,h)
     *	COMPUTE c0 = x0 XOR KDF(|x0|,v0)
     *	COMPUTE c1 = x1 XOR KDF(|x1|,v1)
     *	SEND (u0,c0) and (u1,c1) to R
     *	OUTPUT nothing
     */
    void transfer(CommParty* channel, OTSInput* input) override;
};

/**
 * Concrete class for OT receiver based on the DDH assumption that achieves UC security in
 * the common reference string model.
 * This implementation is based on the protocol of Peikert, Vaikuntanathan and Waters (CRYPTO 2008) for achieving UC-secure OT.
 *
 * This is implementation in BYTE ARRAY mode, derived from OTUCDDHReceiverAbs and implements the functionality
 * related to the byte array inputs.
 *
 * The pseudo code of this protocol can be found in Protocol 4.6 of pseudo codes document at <a href="http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf">http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf</a>.<p>
 *
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
class OTUCDDHOnByteArrayReceiver : public  OTReceiver, Malicious, UC{

private:
    shared_ptr<DlogGroup> dlog;
    shared_ptr<KeyDerivationFunction> kdf; //Used in the calculation.
    shared_ptr<PrgFromOpenSSLAES> random;
    shared_ptr<GroupElement> g0, g1, h0, h1; //Common reference string

public:
    /**
     * Constructor that sets the given common reference string composed of a DLOG
     * description (G,q,g0) and (g0,g1,h0,h1) which is a randomly chosen non-DDH tuple,
     * kdf and random.
     * @param dlog must be DDH secure.
     * @param g0
     * @param g1
     * @param h0
     * @param h1
     * @param kdf
     * @param random
     * @throws SecurityLevelException if the given DlogGroup is not DDH secure.
     */
    OTUCDDHOnByteArrayReceiver(const shared_ptr<DlogGroup> & dlog, const shared_ptr<GroupElement> & g0,
         const shared_ptr<GroupElement> & g1, const shared_ptr<GroupElement> & h0, const shared_ptr<GroupElement> & h1,
         const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>("SHA-256")),
         const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());

    /**
     * Run the transfer phase of the protocol.
     * Transfer Phase (with input sigma)
     *	SAMPLE a random value r <- {0, . . . , q-1}
     *	COMPUTE
     *	4.	g = (gSigma)^r
     *	5.	h = (hSigma)^r
     *	SEND (g,h) to S
     *	WAIT for messages (u0,c0) and (u1,c1) from S
     *	IF  NOT
     *		u0, u1 in G, AND
     *		c0, c1 are binary strings of the same length
     *		   REPORT ERROR
     *	OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)
     */
    shared_ptr<OTROutput> transfer(CommParty* channel, OTRInput* input) override;
};

