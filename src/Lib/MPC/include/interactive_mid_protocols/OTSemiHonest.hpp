#pragma once

#include "OT.hpp"
#include "../primitives/Prg.hpp"
#include "../primitives/Dlog.hpp"
#include "../primitives/DlogOpenSSL.hpp"
#include "../primitives/Kdf.hpp"
#include "../primitives/PrfOpenSSL.hpp"

/**
* Abstract class for Semi-Honest OT assuming DDH sender. 
* Semi-Honest OT has two modes: one is on ByteArray and the second is on GroupElement.
* The difference is in the input and output types and the way to process them.
* In spite that, there is a common behavior for both modes which this class implements.
*
* The pseudo code of this protocol can be found in Protocol 4.1 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTSemiHonestDDHSenderAbs : public OTSender {
	/*
		This class runs the following protocol:
		WAIT for message (h0,h1) from R
		SAMPLE a random value r in  [0, . . . , q-1]
		COMPUTE:
		*	u = g^r
		*	k0 = h0^r
		*	v0 = x0 XOR KDF(|x0|,k0) - in byteArray scenario.
		OR x0*k0			 - in GroupElement scenario.
		*	k1 = h1^r
		*	v1 = x1 XOR KDF(|x1|,k1) - in byteArray scenario.
		OR x1*k1 			 - in GroupElement scenario.
		SEND (u,v0,v1) to R
		OUTPUT nothing
	*/

public:

	/**
	* Runs the transfer phase of the OT protocol.
	* This is the phase where the input is necessary as follows:
	*	"WAIT for message (h0,h1) from R
	*	SAMPLE a random value r in  [0, . . . , q-1] 
	*	COMPUTE:
	*		*	u = g^r
	*		*	k0 = h0^r
	*		*	k1 = h1^r
	*	COMPUTE:
	*			in the byte array scenario
	*				*	v0 = x0 XOR KDF(|x0|,k0)
	*				*	v1 = x1 XOR KDF(|x1|,k1)
	*			OR in the GroupElement scenario:
	*				*	v0 = x0 * k0
	*				*	v1 = x1 * k1"
	*		SEND (u,v0,v1) to R
	*		OUTPUT nothing"
	*/
	virtual void transfer(CommParty* channel, OTSInput* input) override;

protected:
	shared_ptr<DlogGroup> dlog;

	/**
	* Constructor that sets the given dlogGroup and random.
	* @param dlog must be DDH secure.
	* @param random
	* @throws SecurityLevelException if the given dlog is not DDH secure
	*/
	OTSemiHonestDDHSenderAbs(const shared_ptr<PrgFromOpenSSLAES> & random, const shared_ptr<DlogGroup> & dlog);

	/**
	* Runs the following lines from the protocol:
	* "COMPUTE: in the byte array scenario:
	*		*	v0 = x0 XOR KDF(|x0|,k0)
	*		*	v1 = x1 XOR KDF(|x1|,k1)
	* OR in the GroupElement scenario:
	* 		*	v0 = x0 * k0
	*		*	v1 = x1 * k1"
	* @return tuple contains (u, v0, v1) to send to the receiver.
	*/
	virtual shared_ptr<OTSMsg> computeTuple(OTSInput* input, GroupElement* u, GroupElement* k0, GroupElement* k1) = 0;


private:
	shared_ptr<PrgFromOpenSSLAES> random;
	biginteger qMinusOne;

	/**
	* Runs the following line from the protocol:
	* "WAIT for message (h0,h1) from R"
	* @param channel
	* @return the received message.
	*/
	shared_ptr<OTRGroupElementPairMsg> waitForMessageFromReceiver(CommParty* channel);

	/**
	* Runs the following line from the protocol:
	* "COMPUTE u = g^r"
	* @param r the exponent
	* @return the computed u.
	*/
	shared_ptr<GroupElement> computeU(biginteger & r);

	/**
	* Runs the following line from the protocol:
	* "COMPUTE k0 = h0^r"
	* @param r the exponent
	* @param message contains h0
	* @return the computed k0
	*/
	shared_ptr<GroupElement> computeK0(biginteger & r, OTRGroupElementPairMsg* message);

	/**
	* Runs the following line from the protocol:
	* "COMPUTE k1 = h1^r"
	* @param r the exponent
	* @param message contains h1
	* @return the computed k1
	*/
	shared_ptr<GroupElement> computeK1(biginteger & r, OTRGroupElementPairMsg* message);

	/**
	* Runs the following lines from the protocol:
	* "SEND (u,v0,v1) to R"
	* @param channel
	* @param message to send to the receiver
	* @throws IOException if failed to send the message.
	*/
	void sendTupleToReceiver(CommParty* channel, OTSMsg* message);
	
};

/**
* Concrete implementation of OT sender (on GroupElement) message.
* In the byteArray scenario, the sender sends three GroupElement - u, v0, v1.)
*
*/
class OTSemiHonestDDHOnGroupElementSenderMsg : public OTSMsg {

private:
	shared_ptr<GroupElementSendableData> u;
	shared_ptr<GroupElementSendableData> v0;
	shared_ptr<GroupElementSendableData> v1;

public:
	OTSemiHonestDDHOnGroupElementSenderMsg() {}
	/**
	* Sets the given values calculated by the protocol.
	*/
	 OTSemiHonestDDHOnGroupElementSenderMsg(const shared_ptr<GroupElementSendableData> & u, const shared_ptr<GroupElementSendableData> & v0, const shared_ptr<GroupElementSendableData> & v1) 
		 : u(u), v0(v0), v1(v1)	{}

	shared_ptr<GroupElementSendableData> getU() { return u;	}

	shared_ptr<GroupElementSendableData> getV0() { return v0; }

	shared_ptr<GroupElementSendableData> getV1() { return v1; }

	string toString();
	void initFromString(const string & row);
};

/**
* Concrete implementation of OT sender (on byte vector) message.
* In the byteArray scenario, the sender sends GroupElement u and two binary strings v0, v1.
*
*/
class OTSemiHonestDDHOnByteArraySenderMsg : public OTSMsg {

private:
	shared_ptr<GroupElementSendableData> u;
	vector<byte> v0;
	vector<byte> v1;

public:
	OTSemiHonestDDHOnByteArraySenderMsg() {}
	/**
	* Constructor that sets the given values calculated by the protocol.
	*/
	OTSemiHonestDDHOnByteArraySenderMsg(const shared_ptr<GroupElementSendableData> & u, vector<byte> & v0, vector<byte> & v1) 
		: u(u), v0(v0), v1(v1)	{}

	shared_ptr<GroupElementSendableData> getU() { return u;	}

	vector<byte> getV0() {	return v0;	}

	vector<byte> getV1() {	return v1; }

	string toString();
	void initFromString(const string & row);
};

/**
* Concrete class for Semi-Honest OT assuming DDH sender ON GROUP ELEMENT.
* This class derived from OTSemiHonestDDHSenderAbs and implements the functionality related to the GroupElement inputs.
*
* The pseudo code of this protocol can be found in Protocol 4.1 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
*/
class OTSemiHonestDDHOnGroupElementSender : public OTSemiHonestDDHSenderAbs, SemiHonest {

public:
	
	/**
	* Constructor that sets the given dlogGroup and random.
	* @param dlog must be DDH secure.
	* @param random
	* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	*/
	OTSemiHonestDDHOnGroupElementSender(const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(), const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233")) : OTSemiHonestDDHSenderAbs(random, dlog) {}

protected:
	/**
	* Runs the following lines from the protocol:
	* "COMPUTE:
	*			v0 = x0 * k0
	*			v1 = x1 * k1"
	* @param input MUST be an instance of OTSOnGroupElementInput
	* @return tuple contains (u, v0, v1) to send to the receiver.
	*/
	shared_ptr<OTSMsg> computeTuple(OTSInput* input, GroupElement* u, GroupElement* k0, GroupElement* k1) override;
};

/**
* Concrete class for Semi-Honest OT assuming DDH sender ON BYTE ARRAY.
* This class derived from OTSemiHonestDDHSenderAbs and implements the functionality related to the byte array inputs.
*
* The pseudo code of this protocol can be found in Protocol 4.1 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
*/
class OTSemiHonestDDHOnByteArraySender : public OTSemiHonestDDHSenderAbs, SemiHonest {
public:
	/**
	* Constructor that sets the given dlogGroup, kdf and random.
	* @param dlog must be DDH secure.
	* @param kdf
	* @param random
	* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	*/
	OTSemiHonestDDHOnByteArraySender(const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"),
		const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>("SHA-256"))) : OTSemiHonestDDHSenderAbs(random, dlog), kdf(kdf) {}

protected:
	/**
	* Runs the following lines from the protocol:
	* "COMPUTE:
	*			v0 = x0 XOR KDF(|x0|,k0)
	*			v1 = x1 XOR KDF(|x1|,k1)"
	* @param input MUST be an instance of OTSOnByteArrayInput
	* @return tuple contains (u, v0, v1) to send to the receiver.
	*/
	shared_ptr<OTSMsg> computeTuple(OTSInput* input, GroupElement* u, GroupElement* k0, GroupElement* k1) override;

private:
	shared_ptr<KeyDerivationFunction> kdf; //Used in the calculation.

};

/**
* Abstract class for Semi-Honest OT assuming DDH receiver. 
* Semi-Honest OT have two modes: one is on ByteArray and the second is on GroupElement.
* The different is in the input and output types and the way to process them.  
* In spite that, there is a common behavior for both modes which this class is implementing.
*
* The pseudo code of this protocol can be found in Protocol 4.1 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
*/
class OTSemiHonestDDHReceiverAbs : public OTReceiver {

	/*
		This class runs the following protocol:
		SAMPLE random values alpha in Zq and h in the DlogGroup
		COMPUTE h0,h1 as follows:
		1.	If sigma = 0 then h0 = g^alpha  and h1 = h
		2.	If sigma = 1 then h0 = h and h1 = g^alpha
		SEND (h0,h1) to S
		WAIT for the message (u, v0,v1) from S
		COMPUTE kSigma = (u)^alpha							- in byte array scenario
		OR (kSigma)^(-1) = u^(-alpha)					- in GroupElement scenario
		OUTPUT  xSigma = vSigma XOR KDF(|cSigma|,kSigma)	- in byte array scenario
		OR xSigma = vSigma * (kSigma)^(-1) 			- in GroupElement scenario
	*/

public:

	/**
	* Run the transfer phase of the protocol.
	* "SAMPLE random values alpha in Zq and h in the DlogGroup 
	*		COMPUTE h0,h1 as follows:
	*			1.	If sigma = 0 then h0 = g^alpha  and h1 = h
	*			2.	If sigma = 1 then h0 = h and h1 = g^alpha
	*		SEND (h0,h1) to S
	*		WAIT for the message (u, v0,v1) from S
	*		COMPUTE kSigma = (u)^alpha							- in byte array scenario
	*			 OR (kSigma)^(-1) = u^(-alpha)					- in GroupElement scenario
	*		OUTPUT  xSigma = vSigma XOR KDF(|cSigma|,kSigma)	- in byte array scenario
	*			 OR xSigma = vSigma * (kSigma)^(-1)" 			- in GroupElement scenario
	*/
	shared_ptr<OTROutput> transfer(CommParty* channel, OTRInput* input) override;

protected:
	shared_ptr<DlogGroup> dlog;

	/**
	* Constructor that sets the given dlogGroup and random.
	* @param dlog must be DDH secure.
	* @param random
	* @throws SecurityLevelException if the given dlog is not DDH secure.
	*/
	OTSemiHonestDDHReceiverAbs(const shared_ptr<PrgFromOpenSSLAES> & random, const shared_ptr<DlogGroup> & dlog);

	/**
	* Runs the following lines from the protocol:
	* "COMPUTE kSigma = (u)^alpha							- in byte array scenario
	OR (kSigma)^(-1) = u^(-alpha)							- in GroupElement scenario
	OUTPUT  xSigma = vSigma XOR KDF(|cSigma|,kSigma)		- in byte array scenario
	OR xSigma = vSigma * (kSigma)^(-1) 						- in GroupElement scenario
	* @param sigma input for the protocol
	* @param alpha random value sampled by the protocol
	* @param message received from the sender
	* @return OTROutput contains XSigma
	*/
	virtual shared_ptr<OTROutput> getMsgAndComputeXSigma(CommParty* channel, bool sigma, biginteger & alpha) = 0;

private:
	shared_ptr<PrgFromOpenSSLAES> random;
	biginteger qMinusOne;

	/**
	* Runs the following lines from the protocol:
	*  COMPUTE h0,h1 as follows:
	*		1.	If sigma = 0 then h0 = g^alpha  and h1 = h
	*		2.	If sigma = 1 then h0 = h and h1 = g^alpha"
	* @param alpha random value sampled by the protocol
	* @param sigma input for the protocol
	* @return OTRSemiHonestMessage contains the tuple (h0, h1).
	*/
	shared_ptr<OTRGroupElementPairMsg> computeTuple(biginteger & alpha, bool sigma);

	/**
	* Runs the following line from the protocol:
	* "SEND (h0,h1) to S"
	* @param channel
	* @param tuple contains (h0,h1)
	* @throws IOException if failed to send the message.
	*/
	void sendTupleToSender(CommParty* channel, OTRGroupElementPairMsg* tuple);
};


/**
* Concrete class for Semi-Honest OT assuming DDH receiver ON GROUP ELEMENT.
* This class derived from OTSemiHonestDDHReceiverAbs and implements the functionality related to the GroupElement inputs.
*
* The pseudo code of this protocol can be found in Protocol 4.1 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
*/
class OTSemiHonestDDHOnGroupElementReceiver : public OTSemiHonestDDHReceiverAbs, SemiHonest {

public:
	
	/**
	* Constructor that sets the given dlogGroup and random.
	* @param dlog must be DDH secure.
	* @param random
	* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	*/
	OTSemiHonestDDHOnGroupElementReceiver(const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(), 
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233")) : OTSemiHonestDDHReceiverAbs(random, dlog) {}

protected:
	/**
	* Runs the following lines from the protocol:
	* "WAIT for the message (u, v0,v1) from S
	*   COMPUTE (kSigma)^(-1) = u^(-alpha)
	*	OUTPUT  xSigma = vSigma * (kSigma)^(-1)"
	* @param sigma input for the protocol
	* @param alpha random value sampled by the protocol
	* @param message received from the sender. must be OTSOnGroupElementSemiHonestMessage
	* @return OTROutput contains xSigma
	*/
	shared_ptr<OTROutput> getMsgAndComputeXSigma(CommParty* channel, bool sigma, biginteger & alpha) override;
};

/**
* Concrete class for Semi-Honest OT assuming DDH receiver ON BYTE ARRAY.
* This class derived from OTSemiHonestDDHReceiverAbs and implements the functionality related to the byte vector inputs.
*
* The pseudo code of this protocol can be found in Protocol 4.1 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
*/
class OTSemiHonestDDHOnByteArrayReceiver : public OTSemiHonestDDHReceiverAbs, SemiHonest {
public:

	/**
	* Constructor that sets the given dlogGroup, kdf and random.
	* @param dlog must be DDH secure.
	* @param kdf
	* @param random
	* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	*/
	OTSemiHonestDDHOnByteArrayReceiver(const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"),
		const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>("SHA-256"))) : OTSemiHonestDDHReceiverAbs(random, dlog), kdf(kdf) {}

protected:

	/**
	* Runs the following lines from the protocol:
	* "COMPUTE kSigma = (u)^alpha
	*	OUTPUT  xSigma = vSigma XOR KDF(|cSigma|,kSigma)"
	* @param sigma input for the protocol
	* @param alpha random value sampled by the protocol
	* @param message received from the sender. must be OTSOnByteArraySemiHonestMessage.
	* @return OTROutput contains xSigma
	*/
	shared_ptr<OTROutput> getMsgAndComputeXSigma(CommParty* channel, bool sigma, biginteger & alpha) override; 

private:
	shared_ptr<KeyDerivationFunction> kdf; //Used in the calculation.
};


