#pragma once
#include "../primitives/Dlog.hpp"
#include "../primitives/DlogOpenSSL.hpp"
#include "../primitives/Prg.hpp"
#include "../primitives/Kdf.hpp"
#include "../primitives/PrfOpenSSL.hpp"
#include "OT.hpp"

/**
* Abstract class for OT Privacy assuming DDH sender.
* Privacy OT have two modes: one is on ByteArray and the second is on GroupElement.
* The different is in the input and output types and the way to process them.
* In spite that, there is a common behavior for both modes which this class is implementing.
*
* For more information see Protocol 7.2.1 page 179 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.
* The pseudo code of this protocol can be found in Protocol 4.2 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTPrivacyOnlyDDHSenderAbs : public OTSender {

	/*
		This class runs the following protocol:
		IF NOT VALID_PARAMS(G,q,g)
		REPORT ERROR and HALT
		WAIT for message a from R
		DENOTE the tuple a received by S by (x, y, z0, z1)
		IF NOT
		*	z0 != z1
		*	x, y, z0, z1 in the DlogGroup
		REPORT ERROR (cheat attempt)
		SAMPLE random values u0,u1,v0,v1 in  {0, . . . , q-1}
		COMPUTE:
		*	w0 = x^u0 � g^v0
		*	k0 = (z0)^u0 � y^v0
		*	w1 = x^u1 � g^v1
		*	k1 = (z1)^u1 � y^v1
		in byteArray scenario:
		*	c0 = x0 XOR KDF(|x0|,k0)
		*	c1 = x1 XOR KDF(|x1|,k1)
		OR in GroupElement scenario:
		*	c0 = x0 * k0
		*	c1 = x1 * k1
		SEND (w0, c0) and (w1, c1) to R
		OUTPUT nothing
	*/

public:
	/**
	* Runs the transfer phase of the protocol.
	* This is the part of the protocol where the sender input is necessary.
	* "WAIT for message a from R
	*		DENOTE the tuple a received by S by (x, y, z0, z1)
	*		IF NOT
	*		*	z0 != z1
	*		*	x, y, z0, z1 in the DlogGroup
	*		REPORT ERROR (cheat attempt)
	*		SAMPLE random values u0,u1,v0,v1 in  {0, . . . , q-1}
	*		COMPUTE:
	*		*	w0 = x^u0 � g^v0
	*		*	k0 = (z0)^u0 � y^v0
	*		*	w1 = x^u1 � g^v1
	*		*	k1 = (z1)^u1 � y^v1 
	*		in byteArray scenario:
	*			*	c0 = x0 XOR KDF(|x0|,k0)
	*			*	c1 = x1 XOR KDF(|x1|,k1)
	*		OR in GroupElement scenario:
	*			*	c0 = x0 * k0
	*			*	c1 = x1 * k1
	*		SEND (w0, c0) and (w1, c1) to R
	*		OUTPUT nothing"
	*/
	void transfer(CommParty* channel, OTSInput* input) override;

protected:
	shared_ptr<DlogGroup> dlog;

	/**
	* Constructor that sets the given dlogGroup and random.
	* @param dlog must be DDH secure.
	* @param random
	* @throws SecurityLevelException if the given dlog is not DDH secure
	* @throws InvalidDlogGroupException if the given DlogGroup is not valid.
	*/
	OTPrivacyOnlyDDHSenderAbs(const shared_ptr<PrgFromOpenSSLAES> & random, const shared_ptr<DlogGroup> & dlog);

	/**
	* Runs the following lines from the protocol:
	* "COMPUTE: in byteArray scenario:
	*	*	c0 = x0 XOR KDF(|x0|,k0)
	*	*	c1 = x1 XOR KDF(|x1|,k1)
	*	OR in GroupElement scenario:
	*	*	c0 = x0 * k0
	*	*	c1 = x1 * k1"
	* @return tuple contains (w0, c0, w1, c1) to send to the receiver.
	*/
	virtual shared_ptr<OTSMsg> computeTuple(OTSInput* input, GroupElement* w0, GroupElement* w1, GroupElement* k0, GroupElement* k1) = 0;

private:
	shared_ptr<PrgFromOpenSSLAES> random;
	biginteger qMinusOne;

	/**
	* Runs the following line from the protocol:
	* "WAIT for message (h0,h1) from R"
	* @param channel
	* @return the received message.
	*/
	OTRGroupElementQuadMsg waitForMessageFromReceiver(CommParty* channel);

	/**
	* Runs the following lines from the protocol:
	* "IF NOT
	*	*	z0 != z1
	*	*	x, y, z0, z1 in the DlogGroup
	*	REPORT ERROR (cheat attempt)"
	* @throws CheatAttemptException
	*/
	void checkReceivedTuple(GroupElement* x, GroupElement* y, GroupElement* z0, GroupElement* z1);

	/**
	* Runs the following lines from the protocol:
	* "SEND (w0, c0) and (w1, c1) to R"
	* @param channel
	* @param message to send to the receiver
	*/
	void sendTupleToReceiver(CommParty* channel, OTSMsg* message);
};

/**
* Concrete class for OT Privacy assuming DDH sender ON GroupElement.
* This class derived from OTPrivacyOnlyDDHSenderAbs and implements the functionality related to the GroupElement inputs. 
*
* For more information see Protocol 7.2.1 page 179 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.
* The pseudo code of this protocol can be found in Protocol 4.2 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
*/
class OTPrivacyOnlyDDHOnGroupElementSender : public OTPrivacyOnlyDDHSenderAbs, PrivacyOnly {

public:

	/**
	* Constructor that sets the given dlogGroup and random.
	* @param dlog must be DDH secure.
	* @param random
	* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	*/
	OTPrivacyOnlyDDHOnGroupElementSender(const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(), const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"))
		: OTPrivacyOnlyDDHSenderAbs(random, dlog) {}

protected:
	/**
	* Runs the following lines from the protocol:
	* "COMPUTE:
	*			c0 = x0 * k0
	*			c1 = x1 * k1"
	* @param input MUST be OTSOnGroupElementInput.
	* @return tuple contains (u, v0, v1) to send to the receiver.
	*/
	shared_ptr<OTSMsg> computeTuple(OTSInput* input, GroupElement* w0, GroupElement* w1, GroupElement* k0, GroupElement* k1) override;
};

/**
* Concrete class for OT Privacy assuming DDH sender ON BYTE ARRAY.
* This class derived from OTPrivacyOnlyDDHSenderAbs and implements the functionality related to the byte array inputs. 
*
* For more information see Protocol 7.2.1 page 179 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.
* The pseudo code of this protocol can be found in Protocol 4.2 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
*/
class OTPrivacyOnlyDDHOnByteArraySender : public OTPrivacyOnlyDDHSenderAbs, PrivacyOnly {
public:
	/**
	* Constructor that sets the given dlogGroup, kdf and random.
	* @param dlog must be DDH secure.
	* @param kdf
	* @param random
	* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	*/
	OTPrivacyOnlyDDHOnByteArraySender(const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"),
		const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>("SHA-256"))) : OTPrivacyOnlyDDHSenderAbs(random, dlog), kdf(kdf){}

protected:
	/**
	* Runs the following lines from the protocol:
	* "COMPUTE:
	*			c0 = x0 XOR KDF(|x0|,k0)
	*			c1 = x1 XOR KDF(|x1|,k1)"
	* @param input MUST be OTSOnByteArrayInput with x0, x1 of the same arbitrary length.
	* @return tuple contains (u, v0, v1) to send to the receiver.
	*/
	shared_ptr<OTSMsg> computeTuple(OTSInput* input, GroupElement* w0, GroupElement* w1, GroupElement* k0, GroupElement* k1) override; 

private:
	shared_ptr<KeyDerivationFunction> kdf; //Used in the calculation.
};

/**
* Abstract class for OT Privacy assuming DDH receiver.
* Privacy OT have two modes: one is on ByteArray and the second is on GroupElement.
* The different is in the input and output types and the way to process them.
* In spite that, there is a common behavior for both modes which this class is implementing. 
*
* For more information see Protocol 7.2.1 page 179 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.
* The pseudo code of this protocol can be found in Protocol 4.2 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
*/
class OTPrivacyOnlyDDHReceiverAbs : public OTReceiver {

	/*
		This class runs the following protocol:
		IF NOT VALID_PARAMS(G,q,g)
		REPORT ERROR and HALT
		SAMPLE random values alpha, beta, gamma in {0, . . . , q-1}
		COMPUTE a as follows:
		1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)
		2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))
		SEND a to S
		WAIT for message pairs (w0, c0) and (w1, c1)  from S
		In ByteArray scenario:
		IF  NOT
		1. w0, w1 in the DlogGroup, AND
		2. c0, c1 are binary strings of the same length
		REPORT ERROR
		COMPUTE kSigma = (wSigma)^beta
		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,kSigma)
		In GroupElement scenario:
		IF  NOT
		1. w0, w1, c0, c1 in the DlogGroup
		REPORT ERROR
		COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)
		OUTPUT  xSigma = cSigma * (kSigma)^(-1)

	*/

protected:

	shared_ptr<DlogGroup> dlog;

	/**
	* Constructor that sets the given dlogGroup and random.
	* @param dlog must be DDH secure.
	* @param random
	* @throws SecurityLevelException if the given dlog is not DDH secure
	* @throws InvalidDlogGroupException if the given DlogGroup is not valid.
	*/
	OTPrivacyOnlyDDHReceiverAbs(const shared_ptr<PrgFromOpenSSLAES> & random, const shared_ptr<DlogGroup> & dlog);

	/**
	* Runs the following lines from the protocol:
	* "In ByteArray scenario:
	*		IF  NOT
	*			1. w0, w1 in the DlogGroup, AND
	*			2. c0, c1 are binary strings of the same length
	*		   REPORT ERROR
	*	In GroupElement scenario:
	*		IF  NOT
	*			1. w0, w1, c0, c1 in the DlogGroup
	*		   REPORT ERROR
	* In ByteArray scenario:
	*		COMPUTE kSigma = (wSigma)^beta
	*		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,kSigma)
	*	In GroupElement scenario:
	*		COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)
	*		OUTPUT  xSigma = cSigma * (kSigma)^(-1)"
	* @param sigma input of the protocol
	* @param beta random value sampled in the protocol
	* @param message received from the sender
	* @return OTROutput contains xSigma
	*/
	virtual shared_ptr<OTROutput> getMsgAndComputeXSigma(CommParty* channel, byte sigma, biginteger & beta) = 0;

private:

	shared_ptr<PrgFromOpenSSLAES> random;
	biginteger qMinusOne;

	/**
	* Runs the following lines from the protocol:
	* "SAMPLE random values alpha, gamma in [0, . . . , q-1]
	* COMPUTE a as follows:
	*		1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)
	*		2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))"
	* @param sigma input of the protocol
	* @param beta random value sampled by the protocol
	* @return OTRSemiHonestMessage contains the tuple (h0, h1).
	*/
	OTRGroupElementQuadMsg computeTuple(byte sigma, biginteger & beta);

	/**
	* Runs the following line from the protocol:
	* "SEND a to S"
	* @param channel
	* @param a the tuple to send to the sender.
	* @throws IOException
	*/
	void sendTupleToSender(CommParty* channel, OTRGroupElementQuadMsg & a);

public:

	/**
	* Runs the transfer phase of the OT protocol. 
	* This is the part of the protocol where the receiver input is necessary.
	* "SAMPLE random values alpha, beta, gamma in {0, . . . , q-1} 
	*	COMPUTE a as follows:
	*	1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)
	*	2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))
	*	SEND a to S
	*	WAIT for message pairs (w0, c0) and (w1, c1)  from S
	*	In ByteArray scenario:
	*		IF  NOT 
	*			1. w0, w1 in the DlogGroup, AND
	*			2. c0, c1 are binary strings of the same length
	*			REPORT ERROR
	*		COMPUTE kSigma = (wSigma)^beta
	*		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,kSigma)
	*	In GroupElement scenario:
	*		IF  NOT 
	*			1. w0, w1, c0, c1 in the DlogGroup
	*			REPORT ERROR
	*		COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)
	*		OUTPUT  xSigma = cSigma * (kSigma)^(-1)"
	*
	* @return OTROutput, the output of the protocol.
	*/
	shared_ptr<OTROutput> transfer(CommParty* channel, OTRInput* input) override;
};

/**
* Concrete class for OT Privacy assuming DDH receiver ON GROUP ELEMENT.
* This class derived from OTPrivacyOnlyDDHReceiverAbs and implements the functionality related to the group element inputs.
*
* For more information see Protocol 7.2.1 page 179 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.
* The pseudo code of this protocol can be found in Protocol 4.2 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
*/
class OTPrivacyOnlyDDHOnGroupElementReceiver : public OTPrivacyOnlyDDHReceiverAbs, PrivacyOnly {

private:
	 
	/**
	* Run the following line from the protocol:
	* "IF  NOT w0, w1, c0, c1 in the DlogGroup
	*     REPORT ERROR
	*  COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)
	*	OUTPUT  xSigma = cSigma * (kSigma)^(-1)"
	* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	*/
	void checkReceivedTuple(GroupElement* w0, GroupElement* w1, GroupElement* c0, GroupElement* c1);

protected: 

	/**
	* Run the following lines from the protocol:
	* "COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)
	*	OUTPUT  xSigma = cSigma * (kSigma)^(-1)"
	* @param sigma input of the protocol
	* @param beta random value sampled in the protocol
	* @param message received from the sender
	* @return OTROutput contains xSigma
	* @throws CheatAttemptException
	*/
	shared_ptr<OTROutput> getMsgAndComputeXSigma(CommParty* channel, byte sigma, biginteger & beta) override;

public:

	/**
	* Constructor that sets the given dlogGroup and random.
	* @param dlog must be DDH secure.
	* @param random
	* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	*/
	OTPrivacyOnlyDDHOnGroupElementReceiver(const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(), const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233")) 
		: OTPrivacyOnlyDDHReceiverAbs(random, dlog) {}
};

/**
* Concrete class for OT Privacy assuming DDH receiver ON BYTE ARRAY.
* This class derived from OTPrivacyOnlyDDHReceiverAbs and implements the functionality related to the byte array inputs. 
*
* For more information see Protocol 7.2.1 page 179 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.
* The pseudo code of this protocol can be found in Protocol 4.2 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
*/
class OTPrivacyOnlyDDHOnByteArrayReceiver : public OTPrivacyOnlyDDHReceiverAbs, PrivacyOnly {
private:
	shared_ptr<KeyDerivationFunction> kdf; //Used in the calculation.

	/**
	* Run the following line from the protocol:
	* "IF NOT
	*		1. w0, w1 in the DlogGroup, AND
	*		2. c0, c1 are binary strings of the same length
	*	   REPORT ERROR"
	* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	*/
	void checkReceivedTuple(GroupElement* w0, GroupElement* w1, vector<byte>& c0, vector<byte>& c1);

protected:

	/**
	* Run the following lines from the protocol:
	* "IF  NOT
	*			1. w0, w1 in the DlogGroup, AND
	*			2. c0, c1 are binary strings of the same length
	*		   REPORT ERROR
	*  COMPUTE kSigma = (wSigma)^beta
	*  OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,kSigma)"
	* @param sigma input of the protocol
	* @param beta random value sampled in the protocol
	* @param message received from the sender
	* @return OTROutput contains xSigma
	* @throws CheatAttemptException
	*/
	shared_ptr<OTROutput> getMsgAndComputeXSigma(CommParty* channel, byte sigma, biginteger & beta) override;

public:
	/**
	* Constructor that sets the given dlogGroup, kdf and random.
	* @param dlog must be DDH secure.
	* @param kdf
	* @param random
	* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	*/
	OTPrivacyOnlyDDHOnByteArrayReceiver(const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"),
		const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>("SHA-256")))
		: OTPrivacyOnlyDDHReceiverAbs(random, dlog), kdf(kdf) {}

};



