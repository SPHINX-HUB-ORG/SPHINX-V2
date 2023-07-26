#pragma once
#include "OTFullSimulation.hpp"
#include "../primitives/RandomOracle.hpp"

/**
* Concrete implementation of the sender side in oblivious transfer based on the DDH assumption
* that achieves full simulation in the random oracle model.
*
* This class derived from OTFullSimROMDDHSenderAbs and implements the functionality related to the group elements inputs.
*
* For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell;
* this is the protocol of [PVW] adapted to the stand-alone setting and using a Fiat-Shamir proof instead of interactive zero-knowledge.
*
* The pseudo code of this protocol can be found in Protocol 4.5 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimROMDDHOnGroupElementSender : public OTSender, Malicious, StandAlone {

private:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<RandomOracle> ro;
	shared_ptr<OTFullSimPreprocessPhaseValues> preprocessOutput; //Values calculated by the preprocess phase.

public:
	
	/**
	* Constructor that sets the given , dlogGroup, kdf and random.
	* @param dlog must be DDH secure.
	* @param ro random oracle
	* @param random
	* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	* @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*/
	OTFullSimROMDDHOnGroupElementSender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"), const shared_ptr<RandomOracle> & oracle = make_shared<HKDFBasedRO>());


	/**
	* Runs the transfer phase of the protocol.
	*	Transfer Phase (with inputs x0,x1)
	*		WAIT for message from R
	*		DENOTE the values received by (g,h) 
	*		COMPUTE (u0,v0) = RAND(g0,g,h0,h)
	*		COMPUTE (u1,v1) = RAND(g1,g,h1,h)
	*		COMPUTE c0 = x0 * v0
	*		COMPUTE c1 = x1 * v1
	*		SEND (u0,c0) and (u1,c1) to R
	*		OUTPUT nothing
	*/
	void transfer(CommParty* channel, OTSInput* input) override;
};

/**
* Concrete implementation of the sender side in oblivious transfer based on the DDH assumption that achieves
* full simulation in the random oracle model.
*
* This class derived from OTFullSimROMDDHSenderAbs and implements the functionality related to the byte vector inputs.
*
* For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell;
* this is the protocol of [PVW] adapted to the stand-alone setting and using a Fiat-Shamir proof instead of interactive zero-knowledge. 
*
* The pseudo code of this protocol can be found in Protocol 4.5 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
*
*/
class OTFullSimROMDDHOnByteArraySender : public OTSender, Malicious, StandAlone {

private:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<RandomOracle> ro;
	shared_ptr<KeyDerivationFunction> kdf; //Used in the calculation.
	shared_ptr<OTFullSimPreprocessPhaseValues> preprocessOutput; //Values calculated by the preprocess phase.
	
public:
	

	/**
	* Constructor that sets the given , dlogGroup, kdf and random.
	* @param dlog must be DDH secure.
	* @param kdf
	* @param ro random oracle
	* @param random
	* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	* @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*/
	OTFullSimROMDDHOnByteArraySender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"), const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>("SHA-256")),
		const shared_ptr<RandomOracle> & oracle = make_shared<HKDFBasedRO>());

	/**
	* Runs the transfer phase of the protocol.
	*	Transfer Phase (with inputs x0,x1)
	*		WAIT for message from R
	*		DENOTE the values received by (g,h)
	*		COMPUTE (u0,v0) = RAND(g0,g,h0,h)
	*		COMPUTE (u1,v1) = RAND(g1,g,h1,h)
	*		COMPUTE c0 = x0 XOR KDF(|x0|,v0)
	*		COMPUTE c1 = x1 XOR KDF(|x1|,v1)
	*		SEND (u0,c0) and (u1,c1) to R
	*		OUTPUT nothing
	*/
	void transfer(CommParty* channel, OTSInput* input) override;
};

/**
* Concrete implementation of the receiver side in oblivious transfer based on the DDH assumption
* that achieves full simulation in the random oracle model.
*
* This class derived from OTFullSimROMDDHReceiverAbs and implements the functionality related to the GroupElement inputs.
*
* For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell;
* this is the protocol of [PVW] adapted to the stand-alone setting and using a Fiat-Shamir proof instead of interactive zero-knowledge. 
*
* The pseudo code of this protocol can be found in Protocol 4.5 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
*/
class OTFullSimROMDDHOnGroupElementReceiver : public OTReceiver, Malicious, StandAlone {

private:
private:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<RandomOracle> ro;
	shared_ptr<OTFullSimPreprocessPhaseValues> preprocessOutput; //Values calculated by the preprocess phase.

public:
	
	/**
	* Constructor that sets the given dlogGroup, random oracle and random.
	* @param dlog must be DDH secure.
	* @param ro random oracle
	* @param random
	* @throws CheatAttemptException if the receiver suspects that the sender is trying to cheat in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*
	*/
	OTFullSimROMDDHOnGroupElementReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"), const shared_ptr<RandomOracle> & oracle = make_shared<HKDFBasedRO>());

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
* Concrete implementation of the receiver side in oblivious transfer based on the DDH assumption
*  that achieves full simulation in the random oracle model.
*
* This class derived from OTFullSimROMDDHReceiverAbs and implements the functionality related to the byte vector inputs.
*
* For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell;
* this is the protocol of [PVW] adapted to the stand-alone setting and using a Fiat-Shamir proof instead of interactive zero-knowledge. 
*
* The pseudo code of this protocol can be found in Protocol 4.5 of pseudo codes document at https://github.com/cryptobiu/scapi/blob/master/doc/old/SDD_docs/SDK_Pseudocode.docx
*
*/
class OTFullSimROMDDHOnByteArrayReceiver : public OTReceiver, Malicious, StandAlone {

private:

	shared_ptr<DlogGroup> dlog;
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<RandomOracle> ro;
	shared_ptr<KeyDerivationFunction> kdf; //Used in the calculation.
	shared_ptr<OTFullSimPreprocessPhaseValues> preprocessOutput; //Values calculated by the preprocess phase.

public:
	/**
	* Constructor that sets the given dlogGroup, kdf, random oracle and random.
	* @param dlog must be DDH secure.
	* @param kdf
	* @param ro random oracle
	* @param random
	* @throws CheatAttemptException if the receiver suspects that the sender is trying to cheat in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*
	*/
	OTFullSimROMDDHOnByteArrayReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"), const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>("SHA-256")),
		const shared_ptr<RandomOracle> & oracle = make_shared<HKDFBasedRO>());

	/**
	*
	* Run the following part of the protocol:
	* Transfer Phase (with input sigma) 
	*		SAMPLE a random value r <- {0, . . . , q-1} 
	*		COMPUTE
	*		4.	g = (gSigma)^r
	*		5.	h = (hSigma)^r
	*		SEND (g,h) to S
	*		WAIT for messages (u0,c0) and (u1,c1) from S
	*		IF  NOT
	*			u0, u1 in G, AND
	*			c0, c1 are binary strings of the same length
	*		      REPORT ERROR
	*		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)
	*/
	shared_ptr<OTROutput> transfer(CommParty* channel, OTRInput* input) override;
};
