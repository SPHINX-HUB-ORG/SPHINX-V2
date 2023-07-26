#include "../../include/interactive_mid_protocols/OTOneSidedSimulation.hpp"

OTOneSidedSimDDHSenderAbs::OTOneSidedSimDDHSenderAbs(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random, const shared_ptr<DlogGroup> & dlog)
	: zkVerifier(channel, make_shared<SigmaDlogVerifierComputation>(dlog, 80, random), make_shared<CmtRTrapdoorCommitPhaseOutput>(), dlog) {

	//The underlying dlog group must be DDH secure.
	auto ddh = dynamic_pointer_cast<DDH>(dlog);
	if (ddh == NULL) {
		throw SecurityLevelException("DlogGroup should have DDH security level");
	}

	//Check that the given dlog is valid.
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("The given Dlog Group is not valid");

	this->dlog = dlog;
	this->random = random;
	qMinusOne = dlog->getOrder() - 1;

	// This protocol has no pre process stage.
}

/**
* Runs the following line from the protocol:
* "WAIT for message (h0,h1) from R"
* @param channel
* @return the received message.
* @throws IOException if failed to receive a message.
* @throws ClassNotFoundException
*/
OTRGroupElementQuadMsg OTOneSidedSimDDHSenderAbs::waitForMessageFromReceiver(CommParty* channel) {
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);

	// create an empty OTRGroupElementPairMsg and initialize it with the received data. 
	OTRGroupElementQuadMsg msg;
	msg.initFromByteVector(raw_msg);

	return msg;
}

/**
* Runs the following line from the protocol:
* "Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG.
*  Use common input x.
*	If output is REJ, REPORT ERROR (cheat attempt) and HALT".
* @param channel
* @param h common input (x)
* @return the received message.
* @throws CheatAttemptException
* @throws IOException if failed to receive a message.
* @throws ClassNotFoundException
* @throws InvalidDlogGroupException
*/
void OTOneSidedSimDDHSenderAbs::runZKPOK(const shared_ptr<GroupElement> & h) {

	//If the output of the Zero Knowledge Proof Of Knowledge is REJ, throw CheatAttempException.
	SigmaDlogCommonInput input(h);
	auto msgA = make_shared<SigmaGroupElementMsg>(dlog->getGenerator()->generateSendableData());
	auto msgZ = make_shared<SigmaBIMsg>();
	if (!zkVerifier.verify(&input, msgA, msgZ)) {
		throw CheatAttemptException("ZKPOK verifier outputed REJECT");
	}
}

/**
* Runs the following lines from the protocol:
* "IF NOT
*	*	z0 != z1
*	*	x, y, z0, z1 in the DlogGroup
*	REPORT ERROR (cheat attempt)"
* @param z1
* @param z0
* @param y
* @param x
* @return the received message.
* @throws CheatAttemptException
*/
void OTOneSidedSimDDHSenderAbs::checkReceivedTuple(GroupElement* x, GroupElement* y, GroupElement* z0, GroupElement* z1) {

	if (!(dlog->isMember(x))) {
		throw new CheatAttemptException("x element is not a member in the current DlogGroup");
	}
	if (!(dlog->isMember(y))) {
		throw new CheatAttemptException("y element is not a member in the current DlogGroup");
	}
	if (!(dlog->isMember(z0))) {
		throw new CheatAttemptException("z0 element is not a member in the current DlogGroup");
	}
	if (!(dlog->isMember(z1))) {
		throw new CheatAttemptException("z1 element is not a member in the current DlogGroup");
	}

	if (*z0 == *z1) {
		throw new CheatAttemptException("z0 and z1 are equal");
	}

}

/**
* Runs the following lines from the protocol:
* "SEND (w0, c0) and (w1, c1) to R"
* @param channel
* @param message to send to the receiver
* @throws IOException if failed to send the message.
*/
void OTOneSidedSimDDHSenderAbs::sendTupleToReceiver(CommParty* channel, OTSMsg* message) {

	//Send the message by the channel.
	auto msgStr = message->toString();
	channel->writeWithSize(msgStr);
}

/**
* Runs the transfer phase of the protocol. <p>
* This is the part of the protocol where the sender input is necessary.<p>
* "WAIT for message a from R<p>
*	DENOTE the tuple a received by (x, y, z0, z1)<p>
*	Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG. Use common input x.<p>
*	If output is REJ, REPORT ERROR (cheat attempt) and HALT<p>
*	IF NOT<p>
*	*	z0 = z1<p>
*	*	x, y, z0, z1 in G<p>
*	REPORT ERROR (cheat attempt)<p>
*	SAMPLE random values u0,u1,v0,v1 <-  {0, . . . , q-1} <p>
*	COMPUTE:<p>
*	*	w0 = x^u0 * g^v0<p>
*	*	k0 = (z0)^u0 * y^v0<p>
*	*	w1 = x^u1 * g^v1<p>
*	*	k1 = (z1)^u1 * y^v1 <p>
*	*	c0 = x0 XOR KDF(|x0|,k0)<p>
*	*	c1 = x1 XOR KDF(|x1|,k1) <p>
*	SEND (w0, c0) and (w1, c1) to R<p>
*	OUTPUT nothing"
*/
void OTOneSidedSimDDHSenderAbs::transfer(CommParty* channel, OTSInput* input) {

	/* Runs the following part of the protocol:
	WAIT for message a from R
	DENOTE the tuple a received by (x, y, z0, z1)
	Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG. Use common input x.
	If output is REJ, REPORT ERROR (cheat attempt) and HALT
	IF NOT
	*	z0 != z1
	*	x, y, z0, z1 in G
	REPORT ERROR (cheat attempt)
	SAMPLE random values u0,u1,v0,v1 <-  {0, . . . , q-1}
	COMPUTE:
	*	w0 = x^u0 * g^v0
	*	k0 = (z0)^u0 * y^v0
	*	w1 = x^u1 * g^v1
	*	k1 = (z1)^u1 * y^v1
	COMPUTE: in byteArray scenario:
	*	c0 = x0 XOR KDF(|x0|,k0)
	*	c1 = x1 XOR KDF(|x1|,k1)
	OR in GroupElement scenario:
	*	c0 = x0 * k0
	*	c1 = x1 * k1
	SEND (w0, c0) and (w1, c1) to R
	OUTPUT nothing
	*/

	//Wait for message a from R
	OTRGroupElementQuadMsg message = waitForMessageFromReceiver(channel);
	
	//Reconstruct the group elements from the given message.
	auto x = dlog->reconstructElement(false, message.getX().get());
	auto y = dlog->reconstructElement(false, message.getY().get());
	auto z0 = dlog->reconstructElement(false, message.getZ0().get());
	auto z1 = dlog->reconstructElement(false, message.getZ1().get());
	
	//Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG.
	runZKPOK(x);
	
	//If not z0 = z1 and x, y, z0, z1 in G throw CheatAttemptException.
	checkReceivedTuple(x.get(), y.get(), z0.get(), z1.get());
	
	//Sample random values u0,u1,v0,v1 in  {0, . . . , q-1}
	biginteger u0 = getRandomInRange(0, qMinusOne, random.get());
	biginteger u1 = getRandomInRange(0, qMinusOne, random.get());
	biginteger v0 = getRandomInRange(0, qMinusOne, random.get());
	biginteger v1 = getRandomInRange(0, qMinusOne, random.get());

	//Compute values w0, k0, w1, k1
	auto g = dlog->getGenerator(); //Get the group generator.

	//Calculates w0 = x^u0 � g^v0
	auto w0 = dlog->multiplyGroupElements(dlog->exponentiate(x.get(), u0).get(), dlog->exponentiate(g.get(), v0).get());
	//Calculates k0 = (z0)^u0 � y^v0
	auto k0 = dlog->multiplyGroupElements(dlog->exponentiate(z0.get(), u0).get(), dlog->exponentiate(y.get(), v0).get());

	//Calculates w1 = x^u1 � g^v1
	auto w1 = dlog->multiplyGroupElements(dlog->exponentiate(x.get(), u1).get(), dlog->exponentiate(g.get(), v1).get());
	//Calculates k1 = (z1)^u1 � y^v1
	auto k1 = dlog->multiplyGroupElements(dlog->exponentiate(z1.get(), u1).get(), dlog->exponentiate(y.get(), v1).get());

	//Compute c0, c1		
	auto messageToSend = computeTuple(input, w0.get(), w1.get(), k0.get(), k1.get());

	sendTupleToReceiver(channel, messageToSend.get());

}

/**
* Runs the following lines from the protocol:
* "COMPUTE:
*			c0 = x0 * k0
*			c1 = x1 * k1"
* @param input MUST be OTSOnGroupElementInput.
* @param w0
* @param w1
* @param k0
* @param k1
* @return tuple contains (u, v0, v1) to send to the receiver.
*/
shared_ptr<OTSMsg> OTOneSidedSimDDHOnGroupElementSender::computeTuple(OTSInput* input, GroupElement* w0, GroupElement* w1, GroupElement* k0, GroupElement* k1) {
	// If input is not instance of OTSOnGroupElementInput, throw Exception.
	auto in = dynamic_cast<OTOnGroupElementSInput*>(input);
	if (in == nullptr) {
		throw invalid_argument("x0 and x1 should be DlogGroup elements");
	}

	//Set x0, x1.
	auto x0 = in->getX0();
	auto x1 = in->getX1();

	//Calculate c0:
	auto c0 = dlog->multiplyGroupElements(x0.get(), k0);

	//Calculate c1:
	auto c1 = dlog->multiplyGroupElements(x1.get(), k1);

	//Create and return sender message.
	return make_shared<OTOnGroupElementSMsg>(w0->generateSendableData(),
		c0->generateSendableData(), w1->generateSendableData(), c1->generateSendableData());
}

/**
* Runs the following lines from the protocol:
* "COMPUTE:
*			c0 = x0 XOR KDF(|x0|,k0)
*			c1 = x1 XOR KDF(|x1|,k1)"
* @param  iput NUST be an instance of OTSOnByteArrayInput.
* @param w0
* @param w1
* @param k0
* @param k1
* @return tuple contains (u, v0, v1) to send to the receiver.
*/
shared_ptr<OTSMsg> OTOneSidedSimDDHOnByteArraySender::computeTuple(OTSInput* input, GroupElement* w0, GroupElement* w1, GroupElement* k0, GroupElement* k1) {
	
	// If input is not instance of OTSOnGroupElementInput, throw Exception.
	auto in = dynamic_cast<OTOnByteArraySInput*>(input);
	if (in == nullptr) {
		throw invalid_argument("x0 and x1 should be binary strings");
	}

	//Get x0, x1.
	auto x0 = in->getX0();
	auto x1 = in->getX1();

	//If x0, x1 are not of the same length, throw Exception.
	if (x0.size() != x1.size()) {
		throw invalid_argument("x0 and x1 should be of the same length.");
	}
	
	//Calculate c0:
	auto k0Bytes = dlog->mapAnyGroupElementToByteArray(k0);
	int len = x0.size();
	auto c0 = kdf->deriveKey(k0Bytes, 0, k0Bytes.size(), len).getEncoded();
	
	//Xores the result from the kdf with x0.
	for (int i = 0; i<len; i++) {
		c0[i] = c0[i] ^ x0[i];
	}
	
	//Calculate c1:
	auto k1Bytes = dlog->mapAnyGroupElementToByteArray(k1);
	auto c1 = kdf->deriveKey(k1Bytes, 0, k1Bytes.size(), len).getEncoded();
	
	//Xores the result from the kdf with x1.
	for (int i = 0; i<len; i++) {
		c1[i] = c1[i] ^ x1[i];
	}
	
	//Create and return sender message.
	return make_shared<OTOnByteArraySMsg>(w0->generateSendableData(), c0, w1->generateSendableData(), c1);
}

/**
* Constructor that sets the given dlogGroup and random.
* @param dlog must be DDH secure.
* @param random
* @throws SecurityLevelException if the given dlog is not DDH secure
* @throws InvalidDlogGroupException if the given DlogGroup is not valid.
*/
OTOneSidedSimDDHReceiverAbs::OTOneSidedSimDDHReceiverAbs(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random, const shared_ptr<DlogGroup> & dlog)
	: zkProver(channel, make_shared<SigmaDlogProverComputation>(dlog, 80, random), dlog) {
	// The underlying dlog group must be DDH secure.
	auto ddh = dynamic_pointer_cast<DDH>(dlog);
	if (ddh == NULL) {
		throw SecurityLevelException("DlogGroup should have DDH security level");
	}

	//Check that the given dlog is valid.
	// In Zp case, the check is done by Crypto++ library.
	//In elliptic curves case, by default SCAPI uploads a file with NIST recommended curves, 
	//and in this case we assume the parameters are always correct and the validateGroup function always return true.
	//It is also possible to upload a user-defined configuration file. In this case,
	//it is the user's responsibility to check the validity of the parameters by override the implementation of this function.
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("");

	this->dlog = dlog;
	this->random = random;
	qMinusOne = dlog->getOrder() - 1;

	// This protocol has no pre process stage.
}

/**
* Runs the following lines from the protocol:
* "COMPUTE a as follows:
*			1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)
*			2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))"
* @param sigma input for the protocol
* @param alpha random value sampled in the protocol
* @param beta random value sampled in the protocol
* @param gAlpha g^alpha
* @return OTRPrivacyOnlyMessage contains the tuple (x, y, z0, z1).
*/
OTRGroupElementQuadMsg OTOneSidedSimDDHReceiverAbs::computeTuple(byte sigma, biginteger & alpha, biginteger & beta, GroupElement* gAlpha) {
	//Sample random value gamma in [0, . . . , q-1]
	biginteger gamma = getRandomInRange(0, qMinusOne, random.get());

	//Calculates g^beta, g^(alpha*beta), g^gamma.
	auto g = dlog->getGenerator();
	auto gBeta = dlog->exponentiate(g.get(), beta);
	auto gGamma = dlog->exponentiate(g.get(), gamma);
	auto gAlphaBeta = dlog->exponentiate(g.get(), alpha * beta);

	//Create the tuple.
	if (sigma == 0) {
		return OTRGroupElementQuadMsg(gAlpha->generateSendableData(),
			gBeta->generateSendableData(),
			gAlphaBeta->generateSendableData(),
			gGamma->generateSendableData());
	}
	else {
		return OTRGroupElementQuadMsg(gAlpha->generateSendableData(),
			gBeta->generateSendableData(),
			gGamma->generateSendableData(),
			gAlphaBeta->generateSendableData());
	}
}

/**
* Runs the following line from the protocol:
* "SEND a to S"
* @param channel
* @param a the tuple to send to the sender.
* @throws IOException
*/
void OTOneSidedSimDDHReceiverAbs::sendTupleToSender(CommParty* channel, OTRGroupElementQuadMsg a) {
	//Send the message by the channel.
	auto msgStr = a.toString();
	channel->writeWithSize(msgStr);
}

/**
* Runs the transfer phase of the OT protocol.<p>
* This is the part of the protocol where the receiver input is necessary.<p>
* "SAMPLE random values alpha, beta, gamma in {0, . . . , q-1} <p>
*	COMPUTE a as follows:<p>
*	1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)<p>
*	2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))<p>
*	SEND a to S<p>
*	Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG. Use common input x and private input alpha.<p>
*	WAIT for message pairs (w0, c0) and (w1, c1)  from S<p>
*	In ByteArray scenario:<p>
*		IF  NOT <p>
*			1. w0, w1 in the DlogGroup, AND<p>
*			2. c0, c1 are binary strings of the same length<p>
*			  REPORT ERROR<p>
*		COMPUTE kSigma = (wSigma)^beta<p>
*		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,kSigma)<p>
*	In GroupElement scenario:<p>
*		IF  NOT <p>
*			1. w0, w1, c0, c1 in the DlogGroup<p>
*			  REPORT ERROR<p>
*		COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)<p>
*		OUTPUT  xSigma = cSigma * (kSigma)^(-1)"<p>
* @return OTROutput, the output of the protocol.
*/
shared_ptr<OTROutput> OTOneSidedSimDDHReceiverAbs::transfer(CommParty* channel, OTRInput* input) {
	//check if the input is valid.
	//If input is not instance of OTRBasicInput, throw Exception.
	auto in = dynamic_cast<OTRBasicInput*>(input);
	if (in == nullptr) {
		throw invalid_argument("input should contain sigma.");
	}

	byte sigma = in->getSigma();

	//The given sigma should be 0 or 1.
	if ((sigma != 0) && (sigma != 1)) {
		throw invalid_argument("Sigma should be 0 or 1");
	}

	/* Run the following part of the protocol:
	SAMPLE random values alpha, beta, gamma in [0, . . . , q-1]
	COMPUTE a as follows:
	1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)
	2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))
	SEND a to S
	Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG. Use gAlpha and private input alpha.
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

	//Sample random values alpha, beta in [0, . . . , q-1]
	biginteger alpha = getRandomInRange(0, qMinusOne, random.get());
	biginteger beta = getRandomInRange(0, qMinusOne, random.get());

	//Compute g^alpha
	auto g = dlog->getGenerator();
	auto gAlpha = dlog->exponentiate(g.get(), alpha);

	//complete calculations for tuple and create tuple for sender.
	OTRGroupElementQuadMsg a = computeTuple(sigma, alpha, beta, gAlpha.get());

	//Send tuple to sender.
	sendTupleToSender(channel, a);

	//Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG.
	zkProver.prove(make_shared<SigmaDlogProverInput>(gAlpha, alpha));

	//Compute the final calculations to get xSigma.
	return getMsgAndComputeXSigma(channel, sigma, beta);
}

/**
* Run the following line from the protocol:
* "IF  NOT
*		1. w0, w1, c0, c1 in the DlogGroup
*	REPORT ERROR"
* @param c1
* @param c0
* @param w1
* @param w0
* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
*/
void OTOneSidedSimDDHOnGroupElementReceiver::checkReceivedTuple(GroupElement* w0, GroupElement* w1, GroupElement* c0, GroupElement* c1) {

	if (!(dlog->isMember(w0))) {
		throw new CheatAttemptException("w0 element is not a member in the current DlogGroup");
	}
	if (!(dlog->isMember(w1))) {
		throw new CheatAttemptException("w1 element is not a member in the current DlogGroup");
	}
	if (!(dlog->isMember(c0))) {
		throw new CheatAttemptException("c0 element is not a member in the current DlogGroup");
	}
	if (!(dlog->isMember(c1))) {
		throw new CheatAttemptException("c1 element is not a member in the current DlogGroup");
	}
}

/**
* Run the following lines from the protocol:
* "IF  NOT
*		1. w0, w1, c0, c1 in the DlogGroup
*	REPORT ERROR
*  COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)
*	OUTPUT  xSigma = cSigma * (kSigma)^(-1)"
* @param sigma input of the protocol
* @param beta random value sampled in the protocol
* @param message received from the sender
* @return OTROutput contains xSigma
* @throws CheatAttemptException
*/
shared_ptr<OTROutput> OTOneSidedSimDDHOnGroupElementReceiver::getMsgAndComputeXSigma(CommParty* channel, byte sigma, biginteger & beta) {
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);

	// create an empty OTRGroupElementPairMsg and initialize it with the received data. 
	OTOnGroupElementSMsg msg;
	msg.initFromByteVector(raw_msg);

	//Reconstruct the group elements from the given message.
	auto w0 = dlog->reconstructElement(false, msg.getW0().get());
	auto w1 = dlog->reconstructElement(false, msg.getW1().get());
	auto c0 = dlog->reconstructElement(false, msg.getC0().get());
	auto c1 = dlog->reconstructElement(false, msg.getC1().get());

	//Compute the validity checks of the given message.
	checkReceivedTuple(w0.get(), w1.get(), c0.get(), c1.get());

	shared_ptr<GroupElement> kSigma, cSigma;
	biginteger minusBeta = dlog->getOrder() - beta;

	//If sigma = 0, compute w0^beta and set cSigma to c0.
	if (sigma == 0) {
		kSigma = dlog->exponentiate(w0.get(), minusBeta);
		cSigma = c0;
	}

	//If sigma = 0, compute w1^beta and set cSigma to c1.
	if (sigma == 1) {
		kSigma = dlog->exponentiate(w1.get(), minusBeta);
		cSigma = c1;
	}

	auto xSigma = dlog->multiplyGroupElements(cSigma.get(), kSigma.get());

	//Create and return the output containing xSigma
	return make_shared<OTOnGroupElementROutput>(xSigma);
}

/**
* Run the following line from the protocol:
* "IF NOT
*		1. w0, w1 in the DlogGroup, AND
*		2. c0, c1 are binary strings of the same length
*	   REPORT ERROR"
* @param w0
* @param w1
* @param c0
* @param c1
* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
*/
void OTOneSidedSimDDHOnByteArrayReceiver::checkReceivedTuple(GroupElement* w0, GroupElement* w1, vector<byte> & c0, vector<byte> & c1) {

	if (!(dlog->isMember(w0))) {
		throw new CheatAttemptException("w0 element is not a member in the current DlogGroup");
	}
	if (!(dlog->isMember(w1))) {
		throw new CheatAttemptException("w1 element is not a member in the current DlogGroup");
	}

	if (c0.size() != c1.size()) {
		throw CheatAttemptException("c0 and c1 is not in the same length");
	}
}

/**
* Run the following lines from the protocol:
* "IF  NOT
*			1. w0, w1 in the DlogGroup, AND
*			2. c0, c1 are binary strings of the same length
*		   REPORT ERROR
* COMPUTE kSigma = (wSigma)^beta
* OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,kSigma)"
* @param sigma input of the protocol
* @param beta random value sampled in the protocol
* @param message received from the sender
* @return OTROutput contains xSigma
* @throws CheatAttemptException
*/
shared_ptr<OTROutput> OTOneSidedSimDDHOnByteArrayReceiver::getMsgAndComputeXSigma(CommParty* channel, byte sigma, biginteger & beta) {
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);

	// create an empty OTRGroupElementPairMsg and initialize it with the received data. 
	OTOnByteArraySMsg msg;
	msg.initFromByteVector(raw_msg);
	
	//Reconstruct the group elements from the given message.
	auto w0 = dlog->reconstructElement(false, msg.getW0().get());
	auto w1 = dlog->reconstructElement(false, msg.getW1().get());
	//Get the byte arrays from the given message.
	auto c0 = msg.getC0();
	auto c1 = msg.getC1();

	//Compute the validity checks of the given message.
	checkReceivedTuple(w0.get(), w1.get(), c0, c1);

	shared_ptr<GroupElement> kSigma;
	vector<byte> cSigma;

	//If sigma = 0, compute w0^beta and set cSigma to c0.
	if (sigma == 0) {
		kSigma = dlog->exponentiate(w0.get(), beta);
		cSigma = c0;
	}

	//If sigma = 1, compute w1^beta and set cSigma to c1.
	if (sigma == 1) {
		kSigma = dlog->exponentiate(w1.get(), beta);
		cSigma = c1;
	}

	//Compute kdf result:
	int len = c0.size(); // c0 and c1 have the same size.
	auto kBytes = dlog->mapAnyGroupElementToByteArray(kSigma.get());
	auto xSigma = kdf->deriveKey(kBytes, 0, kBytes.size(), len).getEncoded();

	//Xores the result from the kdf with vSigma.
	for (int i = 0; i<len; i++) {
		xSigma[i] = cSigma[i] ^ xSigma[i];
	}

	//Create and return the output containing xSigma
	return make_shared<OTOnByteArrayROutput>(xSigma);
}

