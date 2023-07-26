#include "../../include/interactive_mid_protocols/OTFullSimulationROM.hpp"

/**
* Constructor that sets the given , dlogGroup, kdf and random.
* @param dlog must be DDH secure.
* @param ro random oracle
* @param random
* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
* @throws InvalidDlogGroupException if the given dlog is invalid.
* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
* @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat in the preprocess phase.
* @throws IOException if there was a problem during the communication in the preprocess phase.
* @throws CommitValueException can occur in case of ElGamal commitment scheme.
*/
OTFullSimROMDDHOnGroupElementSender::OTFullSimROMDDHOnGroupElementSender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random,
	const shared_ptr<DlogGroup> & dlog, const shared_ptr<RandomOracle> & oracle) {
	//The underlying dlog group must be DDH secure.
	auto ddh = dynamic_pointer_cast<DDH>(dlog);
	if (ddh == nullptr) {
		throw SecurityLevelException("DlogGroup should have DDH security level");
	}

	// Runs the following part of the protocol:
	//	IF NOT VALID_PARAMS(G,q,g0)
	//    REPORT ERROR and HALT.

	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("The given Dlog Group is not valid");

	this->dlog = dlog;
	this->random = random;
	this->ro = oracle;
	
	//Create the underlying ZKPOK
	ZKPOKFiatShamirFromSigmaVerifier zkVerifier(channel, make_shared<SigmaDHVerifierComputation>(dlog, 80, random), ro);
	
	// Some OT protocols have a pre-process stage before the transfer. 
	// Usually, pre process is done once at the beginning of the protocol and will not be executed later, 
	// and then the transfer function could be called multiple times.
	// We implement the preprocess stage at construction time. 
	// A protocol that needs to call preprocess after the construction time, should create a new instance.
	//Call the utility function that executes the preprocess phase.
	preprocessOutput = OTFullSimSenderPreprocessUtil::preProcess(channel.get(), dlog.get(), &zkVerifier);
}

/**
* Runs the transfer phase of the protocol.<p>
*	Transfer Phase (with inputs x0,x1)<p>
*		WAIT for message from R<p>
*		DENOTE the values received by (g,h) <p>
*		COMPUTE (u0,v0) = RAND(g0,g,h0,h)<p>
*		COMPUTE (u1,v1) = RAND(g1,g,h1,h)<p>
*		COMPUTE c0 = x0 * v0<p>
*		COMPUTE c1 = x1 * v1<p>
*		SEND (u0,c0) and (u1,c1) to R<p>
*		OUTPUT nothing<p>
*/
void OTFullSimROMDDHOnGroupElementSender::transfer(CommParty* channel, OTSInput* input) {
	//Creates the utility class that executes the transfer phase.
	OTFullSimOnGroupElementSenderTransferUtil transferUtil(dlog, random);
	transferUtil.transfer(channel, input, preprocessOutput.get());

}

/**
* Constructor that sets the given , dlogGroup, kdf and random.
* @param dlog must be DDH secure.
* @param kdf
* @param ro random oracle
* @param random
* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
* @throws InvalidDlogGroupException if the given dlog is invalid.
* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
* @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat in the preprocess phase.
* @throws IOException if there was a problem during the communication in the preprocess phase.
* @throws CommitValueException can occur in case of ElGamal commitment scheme.
*/
OTFullSimROMDDHOnByteArraySender::OTFullSimROMDDHOnByteArraySender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random,
	const shared_ptr<DlogGroup> & dlog, const shared_ptr<KeyDerivationFunction> & kdf, const shared_ptr<RandomOracle> & oracle) {
	//The underlying dlog group must be DDH secure.
	auto ddh = dynamic_pointer_cast<DDH>(dlog);
	if (ddh == NULL) {
		throw SecurityLevelException("DlogGroup should have DDH security level");
	}

	// Runs the following part of the protocol:
	//	IF NOT VALID_PARAMS(G,q,g0)
	//    REPORT ERROR and HALT.

	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("The given Dlog Group is not valid");

	this->dlog = dlog;
	this->random = random;
	this->kdf = kdf;
	this->ro = oracle;

	//Create the underlying ZKPOK
	ZKPOKFiatShamirFromSigmaVerifier zkVerifier(channel, make_shared<SigmaDHVerifierComputation>(dlog, 80, random), ro);

	// Some OT protocols have a pre-process stage before the transfer. 
	// Usually, pre process is done once at the beginning of the protocol and will not be executed later, 
	// and then the transfer function could be called multiple times.
	// We implement the preprocess stage at construction time. 
	// A protocol that needs to call preprocess after the construction time, should create a new instance.
	//Call the utility function that executes the preprocess phase.
	preprocessOutput = OTFullSimSenderPreprocessUtil::preProcess(channel.get(), dlog.get(), &zkVerifier);
}

/**
* Runs the transfer phase of the protocol.<p>
*	Transfer Phase (with inputs x0,x1)<p>
*		WAIT for message from R<p>
*		DENOTE the values received by (g,h) <p>
*		COMPUTE (u0,v0) = RAND(g0,g,h0,h)<p>
*		COMPUTE (u1,v1) = RAND(g1,g,h1,h)<p>
*		COMPUTE c0 = x0 XOR KDF(|x0|,v0)<p>
*		COMPUTE c1 = x1 XOR KDF(|x1|,v1)<p>
*		SEND (u0,c0) and (u1,c1) to R<p>
*		OUTPUT nothing<p>
*/
void OTFullSimROMDDHOnByteArraySender::transfer(CommParty* channel, OTSInput* input) {
	//Creates the utility class that executes the transfer phase.
	OTFullSimOnByteArraySenderTransferUtil transferUtil(dlog, kdf, random);
	transferUtil.transfer(channel, input, preprocessOutput.get());
}

/**
* Constructor that sets the given dlogGroup, random oracle and random.
* @param dlog must be DDH secure.
* @param ro random oracle
* @param random
* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
* @throws CheatAttemptException if the receiver suspects that the sender is trying to cheat in the preprocess phase.
* @throws IOException if there was a problem during the communication in the preprocess phase.
* @throws CommitValueException can occur in case of ElGamal commitment scheme.
*
*/
OTFullSimROMDDHOnGroupElementReceiver::OTFullSimROMDDHOnGroupElementReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random,
	const shared_ptr<DlogGroup> & dlog, const shared_ptr<RandomOracle> & oracle) {

	//The underlying dlog group must be DDH secure.
	auto ddh = dynamic_pointer_cast<DDH>(dlog);
	if (ddh == nullptr) {
		throw SecurityLevelException("DlogGroup should have DDH security level");
	}
	//Check that the given dlog is valid.
	// In Zp case, the check is done by Crypto++ library.
	//In elliptic curves case, by default SCAPI uploads a file with NIST recommended curves, 
	//and in this case we assume the parameters are always correct and the validateGroup function always return true.
	//It is also possible to upload a user-defined configuration file. In this case,
	//it is the user's responsibility to check the validity of the parameters by override the implementation of this function.
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("The given Dlog Group is not valid");

	this->dlog = dlog;
	this->random = random;
	this->ro = oracle;
	
	ZKPOKFiatShamirFromSigmaProver zkProver(channel, make_shared<SigmaDHProverComputation>(dlog, 80, random), ro);
	
	// Some OT protocols have a pre-process stage before the transfer. 
	// Usually, pre process is done once at the beginning of the protocol and will not be executed later, 
	// and then the transfer function could be called multiple times.
	// We implement the preprocess stage at construction time. 
	// A protocol that needs to call preprocess after the construction time, should create a new instance.
	//Call the utility function that executes the preprocess phase.
	preprocessOutput = OTFullSimReceiverPreprocessUtil::preProcess(dlog.get(), &zkProver, channel.get(), random.get());
}

/**
*
* Run the transfer phase of the OT protocol.<p>
* Transfer Phase (with input sigma) <p>
*		SAMPLE a random value r <- {0, . . . , q-1} <p>
*		COMPUTE<p>
*		4.	g = (gSigma)^r<p>
*		5.	h = (hSigma)^r<p>
*		SEND (g,h) to S<p>
*		WAIT for messages (u0,c0) and (u1,c1) from S<p>
*		IF  NOT<p>
*			u0, u1, c0, c1 in G<p>
*		      REPORT ERROR<p>
*		OUTPUT  xSigma = cSigma * (uSigma)^(-r)<p>
*/
shared_ptr<OTROutput> OTFullSimROMDDHOnGroupElementReceiver::transfer(CommParty* channel, OTRInput* input) {
	//Creates the utility class that executes the transfer phase.
	OTFullSimOnGroupElementReceiverTransferUtil transferUtil(dlog, random);
	return transferUtil.transfer(channel, input, preprocessOutput.get());
}

/**
* Constructor that sets the given dlogGroup, kdf, random oracle and random.
* @param dlog must be DDH secure.
* @param kdf
* @param ro random oracle
* @param random
* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
* @throws CheatAttemptException if the receiver suspects that the sender is trying to cheat in the preprocess phase.
* @throws IOException if there was a problem during the communication in the preprocess phase.
* @throws CommitValueException can occur in case of ElGamal commitment scheme.
*
*/
OTFullSimROMDDHOnByteArrayReceiver::OTFullSimROMDDHOnByteArrayReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random,
	const shared_ptr<DlogGroup> & dlog, const shared_ptr<KeyDerivationFunction> & kdf, const shared_ptr<RandomOracle> & oracle) {

	//The underlying dlog group must be DDH secure.
	auto ddh = dynamic_pointer_cast<DDH>(dlog);
	if (ddh == nullptr) {
		throw SecurityLevelException("DlogGroup should have DDH security level");
	}
	//Check that the given dlog is valid.
	// In Zp case, the check is done by Crypto++ library.
	//In elliptic curves case, by default SCAPI uploads a file with NIST recommended curves, 
	//and in this case we assume the parameters are always correct and the validateGroup function always return true.
	//It is also possible to upload a user-defined configuration file. In this case,
	//it is the user's responsibility to check the validity of the parameters by override the implementation of this function.
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("The given Dlog Group is not valid");

	this->dlog = dlog;
	this->random = random;
	this->ro = oracle;
	this->kdf = kdf;

	ZKPOKFiatShamirFromSigmaProver zkProver(channel, make_shared<SigmaDHProverComputation>(dlog, 80, random), ro);

	// Some OT protocols have a pre-process stage before the transfer. 
	// Usually, pre process is done once at the beginning of the protocol and will not be executed later, 
	// and then the transfer function could be called multiple times.
	// We implement the preprocess stage at construction time. 
	// A protocol that needs to call preprocess after the construction time, should create a new instance.
	//Call the utility function that executes the preprocess phase.
	preprocessOutput = OTFullSimReceiverPreprocessUtil::preProcess(dlog.get(), &zkProver, channel.get(), random.get());
}

/**
*
* Run the following part of the protocol:
* Transfer Phase (with input sigma) <p>
*		SAMPLE a random value r <- {0, . . . , q-1} <p>
*		COMPUTE<p>
*		4.	g = (gSigma)^r<p>
*		5.	h = (hSigma)^r<p>
*		SEND (g,h) to S<p>
*		WAIT for messages (u0,c0) and (u1,c1) from S<p>
*		IF  NOT<p>
*			u0, u1 in G, AND<p>
*			c0, c1 are binary strings of the same length<p>
*		      REPORT ERROR<p>
*		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)<p>
*/
shared_ptr<OTROutput> OTFullSimROMDDHOnByteArrayReceiver::transfer(CommParty* channel, OTRInput* input) {
	//Creates the utility class that executes the transfer phase.
	OTFullSimOnByteArrayReceiverTransferUtil transferUtil(dlog, kdf, random);
	return transferUtil.transfer(channel, input, preprocessOutput.get());
}

