#pragma once
#include "OT.hpp"
#include "../primitives/DlogOpenSSL.hpp"
#include "../primitives/Kdf.hpp"
#include "../primitives/PrfOpenSSL.hpp"
#include "ZeroKnowledge.hpp"
#include "SigmaProtocolDH.hpp"

/**
* Concrete implementation of OT with full simulation receiver message. This implementation is common for OT on byteArray and on GroupElement.
* The message contains tuple of three GroupElements - (h0, h1, g1).
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimDDHReceiverMsg : public NetworkSerialized {

private:
	shared_ptr<GroupElementSendableData> h0;
	shared_ptr<GroupElementSendableData> h1;
	shared_ptr<GroupElementSendableData> g1;

public:
	OTFullSimDDHReceiverMsg() {}

	OTFullSimDDHReceiverMsg(const shared_ptr<GroupElementSendableData> & g1, const shared_ptr<GroupElementSendableData> & h0,
		const shared_ptr<GroupElementSendableData> & h1) : h0(h0), h1(h1), g1(g1) {}

	shared_ptr<GroupElementSendableData> getH0() { return h0; }

	shared_ptr<GroupElementSendableData> getH1() { return h1; }

	shared_ptr<GroupElementSendableData> getG1() { return g1; }

	string toString();
	void initFromString(const string & row);

};

/**
* This class holds the Group Elements calculated in the preprocess phase.
*
*/
class OTFullSimPreprocessPhaseValues {

private:
	shared_ptr<GroupElement> g0, g1, h0, h1; //Values calculated by the preprocess phase.

public:

	OTFullSimPreprocessPhaseValues(const shared_ptr<GroupElement> & g0, const shared_ptr<GroupElement> & g1, const shared_ptr<GroupElement> & h0, 
		const shared_ptr<GroupElement> & h1) : g0(g0), g1(g1), h0(h0), h1(h1){}

	shared_ptr<GroupElement> getG0() {	return g0;	}

	shared_ptr<GroupElement> getG1() {	return g1;	}

	shared_ptr<GroupElement> getH0() {	return h0;	}

	shared_ptr<GroupElement> getH1() {	return h1;	}
};

/**
* This class executes the preprocess phase of OT's that achieve full simulation.
*
*/
class OTFullSimSenderPreprocessUtil {
private:
	/**
	* Runs the following line from the protocol:
	* "WAIT for message (h0,h1) from R"
	* @return the received message
	*/
	static OTFullSimDDHReceiverMsg waitForFullSimMessageFromReceiver(CommParty* channel);

public:

	/**
	* Runs the preprocess phase of the OT protocol, where the sender input is not yet necessary.
	* "WAIT for message from R
	* DENOTE the values received by (g1,h0,h1) 
	* Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH. Use common input (g0,g1,h0,h1/g1).
	* If output is REJ, REPORT ERROR (cheat attempt) and HALT."
	* @param channel used to communicate between the parties.
	* @param dlog
	* @param zkVerifier used to verify the ZKPOK_FROM_SIGMA
	* @return the values calculated in the preprocess
	* @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*/
	static shared_ptr<OTFullSimPreprocessPhaseValues> preProcess(CommParty* channel, DlogGroup* dlog, ZKPOKVerifier* zkVerifier);
};

/**
* This class execute  the preprocess phase of OT's that achieve full simulation.
*
*/
class OTFullSimReceiverPreprocessUtil {
public:

	/**
	* Runs the preprocess phase of the protocol, where the receiver input is not yet necessary.
	* 	"SAMPLE random values y, alpha0 <- {0, . . . , q-1} 
	*	SET alpha1 = alpha0 + 1 
	*	COMPUTE
	*    1. g1 = (g0)^y
	*	  2. h0 = (g0)^(alpha0)
	*	  3. h1 = (g1)^(alpha1)
	*	SEND (g1,h0,h1) to S
	*  Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH. Use common input (g0,g1,h0,h1/g1) and private input alpha0."
	* @param channel
	* @param dlog
	* @param zkProver used to prove the ZKPOK_FROM_SIGMA
	* @param random
	* @return the values calculated in the preprocess
	* @throws CheatAttemptException if the receiver suspects that the sender is trying to cheat in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*/
	static shared_ptr<OTFullSimPreprocessPhaseValues> preProcess(DlogGroup* dlog, ZKPOKProver* zkProver, CommParty* channel, PrgFromOpenSSLAES* random);

};

/**
* This class execute the common functionality of the transfer function of all OT's that achieve full simulation.
*
*/
class OTFullSimSenderTransferUtilAbs {

private:
	shared_ptr<PrgFromOpenSSLAES> random;

	/**
	* Runs the following line from the protocol:
	* "WAIT for message (h0,h1) from R"
	* @return the received message.
	*/
	OTRGroupElementPairMsg waitForMessageFromReceiver(CommParty* channel);

protected:
	shared_ptr<DlogGroup> dlog;

	/**
	* Runs the following lines from the protocol:
	* "COMPUTE:
	* 		in the byte array scenario:
	*			COMPUTE c0 = x0 XOR KDF(|x0|,v0)
	*			COMPUTE c1 = x1 XOR KDF(|x1|,v1)
	*		in the GroupElement scenario:
	*			COMPUTE c0 = x0 * v0
	*			COMPUTE c1 = x1 * v1
	*		SEND (u0,c0) and (u1,c1) to R
	*		OUTPUT nothing
	* @return tuple contains (u, v0, v1) to send to the receiver.
	*/
	virtual shared_ptr<OTSMsg> computeTuple(OTSInput* input, GroupElement* u0, GroupElement* u1, GroupElement* v0, GroupElement* v1) = 0;
	
public:
	/**
	* Sets the given dlog and random.
	*/
	OTFullSimSenderTransferUtilAbs(const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & random): random(random), dlog(dlog) {}

	/**
	* Runs the transfer phase of the OT protocol.
	* Transfer Phase (with inputs x0,x1)
	*	WAIT for message from R
	*	DENOTE the values received by (g,h) 
	*	COMPUTE (u0,v0) = RAND(g0,g,h0,h)
	*	COMPUTE (u1,v1) = RAND(g1,g,h1,h)
	*	in the byte array scenario:
	*		COMPUTE c0 = x0 XOR KDF(|x0|,v0)
	*		COMPUTE c1 = x1 XOR KDF(|x1|,v1)
	*	in the GroupElement scenario:
	*		COMPUTE c0 = x0 * v0
	*		COMPUTE c1 = x1 * v1
	*	SEND (u0,c0) and (u1,c1) to R
	*	OUTPUT nothing<p>
	* This is the transfer stage of OT protocol which can be called several times in parallel.
	* The OT implementation support usage of many calls to transfer, with single preprocess execution. 
	* This way, one can execute batch OT by creating the OT receiver once and call the transfer function for each input couple.
	* In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages.
	* This way the parallel executions of the function will not block each other.
	* @param channel each call should get a different one.
	* @param input the parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
	* @param preprocessValues hold the values calculated in the preprocess phase.
	* @return OTROutput, the output of the protocol.
	* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	*/
	void transfer(CommParty* channel, OTSInput* input, OTFullSimPreprocessPhaseValues* preprocessValues);
};

/**
* This class executes the computations in the transfer function that related to the GroupElement inputs.
*
*/
class OTFullSimOnGroupElementSenderTransferUtil : public OTFullSimSenderTransferUtilAbs {

protected: 
	/**
	* Runs the following lines from the protocol:
	* "COMPUTE:
	*		c0 = x0 * v0
	*		c1 = x1 * v1"
	* @param input MUST be OTSOnGroupElementInput.
	* @return tuple contains (u0, c0, u1, c1) to send to the receiver.
	*/
	shared_ptr<OTSMsg> computeTuple(OTSInput* input, GroupElement* u0, GroupElement* u1, GroupElement* v0, GroupElement* v1) override; 

public:

	/**
	* Sets the given dlog and random.
	*/
	OTFullSimOnGroupElementSenderTransferUtil(const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & random)
	: OTFullSimSenderTransferUtilAbs(dlog, random) {}
};

/**
* This class executes the computations in the transfer function that related to the byte vector inputs.
*
*/
class OTFullSimOnByteArraySenderTransferUtil : public OTFullSimSenderTransferUtilAbs {

private:
	shared_ptr<KeyDerivationFunction> kdf;

protected:
	/**
	* Runs the following lines from the protocol:
	* "COMPUTE:
	*		COMPUTE c0 = x0 XOR KDF(|x0|,v0)
	*		COMPUTE c1 = x1 XOR KDF(|x1|,v1)"
	* @param input must be a OTSOnByteArrayInput.
	* @return tuple contains (u0, c0, u1, c1) to send to the receiver.
	*/
	shared_ptr<OTSMsg> computeTuple(OTSInput* input, GroupElement* u0, GroupElement* u1, GroupElement* v0, GroupElement* v1) override;

public:
	/**
	* Sets the given dlog, kdf and random.
	*/
	OTFullSimOnByteArraySenderTransferUtil(const shared_ptr<DlogGroup> & dlog, const shared_ptr<KeyDerivationFunction> & kdf, const shared_ptr<PrgFromOpenSSLAES> & random);

};

/**
* This class execute the common functionality of the transfer function of all OT's that achieve full simulation.
*
*/
class OTFullSimReceiverTransferUtilAbs {

private:
	shared_ptr<PrgFromOpenSSLAES> random;
	biginteger qMinusOne;

	/**
	* Runs the following lines from the protocol:
	* "COMPUTE
	* 4.	g = (gSigma)^r
	* 5.	h = (hSigma)^r"
	* @param sigma input of the protocol
	* @param r random value sampled in the protocol
	* @return OTRFullSimMessage contains the tuple (g,h).
	*/
	OTRGroupElementPairMsg computeSecondTuple(byte sigma, biginteger & r, OTFullSimPreprocessPhaseValues* preprocessValues);

protected:
	shared_ptr<DlogGroup> dlog;

	/**
	* Runs the following lines from the protocol:
	* "In ByteArray scenario:
	*		IF  NOT
	*			1. w0, w1 in the DlogGroup, AND
	*			2. c0, c1 are binary strings of the same length
	*		   REPORT ERROR
	*		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)
	*	In GroupElement scenario:
	*		IF  NOT
	*			1. w0, w1, c0, c1 in the DlogGroup
	*		   REPORT ERROR
	*	OUTPUT  xSigma = cSigma * (uSigma)^(-r)"
	* @param sigma input of the protocol
	* @param r random value sampled in the protocol
	* @param message received from the sender
	* @return OTROutput contains xSigma
	* @throws CheatAttemptException
	*/
	virtual shared_ptr<OTROutput> getMsgAndComputeXSigma(CommParty* channel, byte sigma, biginteger & r) = 0;

public:
	/**
	* Sets the given dlog and random.
	*/
	OTFullSimReceiverTransferUtilAbs(const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & random);

	/**
	*
	* Run the transfer phase of the OT protocol.
	* Transfer Phase (with inputs sigma)
	*		SAMPLE a random value r <- {0, . . . , q-1} 
	*		COMPUTE<p>
	*		4.	g = (gSigma)^r
	*		5.	h = (hSigma)^r
	*		SEND (g,h) to S
	*		WAIT for messages (u0,c0) and (u1,c1) from S
	*		In ByteArray scenario:
	*		IF  NOT
	*			u0, u1 in G, AND
	*			c0, c1 are binary strings of the same length
	*		      REPORT ERROR
	*		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)
	*		In GroupElement scenario:
	*		IF  NOT
	*			u0, u1, c0, c1 in G
	*		      REPORT ERROR
	*		OUTPUT  xSigma = cSigma * (uSigma)^(-r)
	* This is the transfer stage of OT protocol which can be called several times in parallel.
	* The OT implementation support usage of many calls to transfer, with single preprocess execution. 
	* This way, one can execute batch OT by creating the OT receiver once and call the transfer function for each input couple.
	* In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages.
	* This way the parallel executions of the function will not block each other.
	* @param channel each call should get a different one.
	* @param input MUST be OTRBasicInput. The parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
	* @param preprocessValues hold the values calculated in the preprocess phase.
	* @return OTROutput, the output of the protocol.
	* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	*/
	shared_ptr<OTROutput> transfer(CommParty* channel, OTRInput* input, OTFullSimPreprocessPhaseValues* preprocessValues);
};

/**
* This class executes the computations in the transfer function that related to the GroupElement inputs.
*
*/
class OTFullSimOnGroupElementReceiverTransferUtil : public OTFullSimReceiverTransferUtilAbs {
private:
	
	/**
	* Run the following line from the protocol:
	* "IF  NOT
	*		1. u0, u1, c0, c1 in the DlogGroup
	*	REPORT ERROR"
	* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	*/
	void checkReceivedTuple(GroupElement* u0, GroupElement* u1, GroupElement* c0, GroupElement* c1);

protected:
	/**
	* Run the following lines from the protocol:
	* "COMPUTE xSigma = cSigma * (uSigma)^(-r)"
	* @param sigma input of the protocol
	* @param r random value sampled in the protocol
	* @param message received from the sender
	* @return OTROutput contains xSigma
	* @throws CheatAttemptException
	*/
	shared_ptr<OTROutput> getMsgAndComputeXSigma(CommParty* channel, byte sigma, biginteger & r) override;

public:
	/**
	* Sets the given dlog and random.
	*/
	OTFullSimOnGroupElementReceiverTransferUtil(const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & random) 
	: OTFullSimReceiverTransferUtilAbs(dlog, random) {}

};

/**
* This class executes the computations in the transfer function that related to the byte vector inputs.
*
*/
class OTFullSimOnByteArrayReceiverTransferUtil : public OTFullSimReceiverTransferUtilAbs {

private:
	shared_ptr<KeyDerivationFunction> kdf;

	/**
	* Run the following line from the protocol:
	* "IF NOT
	*		1. u0, u1 in the DlogGroup, AND
	*		2. c0, c1 are binary strings of the same length
	*	   REPORT ERROR"
	* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	*/
	void checkReceivedTuple(GroupElement* u0, GroupElement* u1, vector<byte> & c0, vector<byte> & c1);

public:
	/**
	* Sets the given dlog, kdf and random.
	*/
	OTFullSimOnByteArrayReceiverTransferUtil(const shared_ptr<DlogGroup> & dlog, const shared_ptr<KeyDerivationFunction> & kdf, const shared_ptr<PrgFromOpenSSLAES> & random)
		:OTFullSimReceiverTransferUtilAbs(dlog, random), kdf(kdf) {}

	/**
	* Run the following lines from the protocol:
	* "IF  NOT
	*		1. w0, w1 in the DlogGroup, AND
	*		2. c0, c1 are binary strings of the same length
	*		REPORT ERROR
	*	OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)"
	* @param sigma input of the protocol
	* @param r random value sampled in the protocol
	* @param message received from the sender
	* @return OTROutput contains xSigma
	* @throws CheatAttemptException
	*/
	shared_ptr<OTROutput> getMsgAndComputeXSigma(CommParty* channel, byte sigma, biginteger & r) override;

};

/**
* Concrete implementation of the sender side in oblivious transfer based on the DDH assumption that achieves full simulation.
* This implementation can also be used as batch OT that achieves full simulation. 
* In batch oblivious transfer, the parties run an initialization phase and then can carry out concrete OTs later
* whenever they have new inputs and wish to carry out an OT. 
*
* This class derived from OTFullSimDDHSenderAbs and implements the functionality related to the GroupElement inputs.
*
* For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell;
* this is the protocol of [PVW] adapted to the stand-alone setting 
* The pseudo code of this protocol can be found in Protocol 4.4 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
*/
class OTFullSimDDHOnGroupElementSender : public OTSender, Malicious, StandAlone {

private:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<PrgFromOpenSSLAES> random;

	shared_ptr<OTFullSimPreprocessPhaseValues> preprocessOutput; //Values calculated by the preprocess phase.

public:

	/**
	* Constructor that sets the given channel, dlogGroup and random.
	* @param channel
	* @param dlog must be DDH secure.
	* @param random
	*/
	OTFullSimDDHOnGroupElementSender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"));

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
* Concrete implementation of the sender side in oblivious transfer based on the DDH assumption that achieves full simulation.
* This implementation can also be used as batch OT that achieves full simulation.
* In batch oblivious transfer, the parties run an initialization phase and then can carry out concrete OTs later
* whenever they have new inputs and wish to carry out an OT. 
*
* This class derived from OTFullSimDDHSenderAbs and implements the functionality related to the byte vector inputs.
*
* For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell;
* this is the protocol of [PVW] adapted to the stand-alone setting .
* The pseudo code of this protocol can be found in Protocol 4.4 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
*/
class OTFullSimDDHOnByteArraySender : public OTSender, Malicious, StandAlone {

private:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<KeyDerivationFunction> kdf; //Used in the calculation.
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<OTFullSimPreprocessPhaseValues> preprocessOutput; //Values calculated by the preprocess phase.
													
public:

	/**
	* Constructor that sets the given channel, dlogGroup and random.
	* @param channel
	* @param dlog must be DDH secure.
	* @param kdf
	* @param random
	* @throws SecurityLevelException if the given dlog is not DDH secure
	* @throws InvalidDlogGroupException
	* @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*/
	OTFullSimDDHOnByteArraySender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"), const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>("SHA-256")));

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
* Concrete implementation of the receiver side in oblivious transfer based on the DDH assumption that achieves full simulation.
* This implementation can also be used as batch OT that achieves full simulation. 
* In batch oblivious transfer, the parties run an initialization phase and then can carry out concrete OTs later
* whenever they have new inputs and wish to carry out an OT. 
*
* This class derived from OTFullSimDDHReceiverAbs and implements the functionality related to the GroupElement inputs.
*
* For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell;
* this is the protocol of [PVW] adapted to the stand-alone setting <P>
* The pseudo code of this protocol can be found in Protocol 4.4 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimDDHOnGroupElementReceiver : public OTReceiver, Malicious, StandAlone {

private:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<OTFullSimPreprocessPhaseValues> preprocessOutput; //Values calculated by the preprocess phase.

public:
	
	/**
	* Constructor that sets the given channel, dlogGroup and random.
	* @param channel
	* @param dlog must be DDH secure.
	* @param random
	* @throws SecurityLevelException if the given dlog is not DDH secure
	* @throws InvalidDlogGroupException if the given DlogGroup is not valid.
	* @throws CheatAttemptException if the receiver suspects that the sender is trying to cheat in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*/
	OTFullSimDDHOnGroupElementReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"));

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
	*		IF  NOT<p>
	*			u0, u1, c0, c1 in G
	*		      REPORT ERROR
	*		OUTPUT  xSigma = cSigma * (uSigma)^(-r)
	*/
	shared_ptr<OTROutput> transfer(CommParty* channel, OTRInput* input) override;
};

/**
* Concrete implementation of the receiver side in oblivious transfer based on the DDH assumption that achieves full simulation.
* This implementation can also be used as batch OT that achieves full simulation. 
* In batch oblivious transfer, the parties run an initialization phase and then can carry out concrete
* OTs later whenever they have new inputs and wish to carry out an OT. 
*
* This class derived from OTFullSimDDHReceiverAbs and implements the functionality related to the byte vector inputs.
*
* For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell;
* this is the protocol of [PVW] adapted to the stand-alone setting <P>
* The pseudo code of this protocol can be found in Protocol 4.4 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
*/
class OTFullSimDDHOnByteArrayReceiver : public OTReceiver, Malicious, StandAlone {

private:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<KeyDerivationFunction> kdf; //Used in the calculation.
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<OTFullSimPreprocessPhaseValues> preprocessOutput; //Values calculated by the preprocess phase.

public:

	/**
	* Constructor that sets the given channel, dlogGroup and random.
	* @param channel
	* @param dlog must be DDH secure.
	* @param random
	* @throws SecurityLevelException if the given dlog is not DDH secure
	* @throws InvalidDlogGroupException if the given DlogGroup is not valid.
	* @throws CheatAttemptException if the receiver suspects that the sender is trying to cheat in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*/
	OTFullSimDDHOnByteArrayReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"), const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>("SHA-256")));

	/**
	*
	* Run the transfer phase of the protocol.
	* Transfer Phase (with input sigma) 
	*	SAMPLE a random value r <- {0, . . . , q-1}
	*	COMPUTE<p>
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

