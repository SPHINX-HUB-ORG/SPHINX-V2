#include "../../include/interactive_mid_protocols/OTFullSimulation.hpp"

string OTFullSimDDHReceiverMsg::toString() {
	return h0->toString() + ":" + h1->toString() + ":" + g1->toString();
}

void OTFullSimDDHReceiverMsg::initFromString(const string & row) {
	auto str_vec = explode(row, ':');
	int size = str_vec.size();
	assert(size == 3 || size == 6);
	if (size == 3) {
		h0 = make_shared<ZpElementSendableData>(0);
		h1 = make_shared<ZpElementSendableData>(0);
		g1 = make_shared<ZpElementSendableData>(0);
		h0->initFromString(str_vec[0]);
		h1->initFromString(str_vec[1]);
		g1->initFromString(str_vec[2]);
	}
	else {
		h0 = make_shared<ECElementSendableData>(0, 0);
		h1 = make_shared<ECElementSendableData>(0, 0);
		g1 = make_shared<ECElementSendableData>(0, 0);
		h0->initFromString(str_vec[0] + ":" + str_vec[1]);
		h1->initFromString(str_vec[2] + ":" + str_vec[3]);
		g1->initFromString(str_vec[4] + ":" + str_vec[5]);
	}
}

/**
* Runs the following line from the protocol:
* "WAIT for message (h0,h1) from R"
* @param channel
* @return the received message.
* @throws ClassNotFoundException
* @throws IOException if failed to receive a message.
*/
OTFullSimDDHReceiverMsg OTFullSimSenderPreprocessUtil::waitForFullSimMessageFromReceiver(CommParty* channel) {
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);

	// create an empty OTRGroupElementPairMsg and initialize it with the received data. 
	OTFullSimDDHReceiverMsg msg;
	msg.initFromByteVector(raw_msg);

	return msg;
}

/**
* Runs the preprocess phase of the OT protocol, where the sender input is not yet necessary.<p>
* "WAIT for message from R<p>
* DENOTE the values received by (g1,h0,h1) <p>
* Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH. Use common input (g0,g1,h0,h1/g1).<p>
* If output is REJ, REPORT ERROR (cheat attempt) and HALT."<p>
* @param channel used to communicate between the parties.
* @param dlog
* @param zkVerifier used to verify the ZKPOK_FROM_SIGMA
* @return the values calculated in the preprocess
* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
* @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat in the preprocess phase.
* @throws IOException if there was a problem during the communication in the preprocess phase.
* @throws CommitValueException can occur in case of ElGamal commitment scheme.
*/
shared_ptr<OTFullSimPreprocessPhaseValues> OTFullSimSenderPreprocessUtil::preProcess(CommParty* channel, DlogGroup* dlog, ZKPOKVerifier* zkVerifier) {
	//Wait for message from R
	OTFullSimDDHReceiverMsg message = waitForFullSimMessageFromReceiver(channel);

	auto g1 = dlog->reconstructElement(true, message.getG1().get());
	auto h0 = dlog->reconstructElement(true, message.getH0().get());
	auto h1 = dlog->reconstructElement(true, message.getH1().get());

	//Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH.
	auto g1Inv = dlog->getInverse(g1.get());
	auto h1DivG1 = dlog->multiplyGroupElements(h1.get(), g1Inv.get());

	//If the output of the Zero Knowledge Proof Of Knowledge is REJ, throw CheatAttempException.
	SigmaDHCommonInput input(g1, h0, h1DivG1);
	auto msgA = make_shared<SigmaDHMsg>(dlog->getGenerator()->generateSendableData(), dlog->getGenerator()->generateSendableData());
	auto msgZ = make_shared<SigmaBIMsg>();
	
	if (!zkVerifier->verify(&input, msgA, msgZ)) {
		throw CheatAttemptException("ZKPOK verifier outputed REJECT");
	}
	
	return make_shared<OTFullSimPreprocessPhaseValues>(dlog->getGenerator(), g1, h0, h1);
}

/**
* Runs the preprocess phase of the protocol, where the receiver input is not yet necessary.<p>
* 	"SAMPLE random values y, alpha0 <- {0, . . . , q-1} <p>
*	SET alpha1 = alpha0 + 1 <p>
*	COMPUTE <p>
*    1. g1 = (g0)^y<p>
*	  2. h0 = (g0)^(alpha0)<p>
*	  3. h1 = (g1)^(alpha1)<p>
*	SEND (g1,h0,h1) to S<p>
*  Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH. Use common input (g0,g1,h0,h1/g1) and private input alpha0."
* @param channel
* @param dlog
* @param zkProver used to prove the ZKPOK_FROM_SIGMA
* @param random
* @return the values calculated in the preprocess
* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
* @throws CheatAttemptException if the receiver suspects that the sender is trying to cheat in the preprocess phase.
* @throws IOException if there was a problem during the communication in the preprocess phase.
* @throws CommitValueException can occur in case of ElGamal commitment scheme.
*/
shared_ptr<OTFullSimPreprocessPhaseValues> OTFullSimReceiverPreprocessUtil::preProcess(DlogGroup* dlog, ZKPOKProver* zkProver, CommParty* channel, PrgFromOpenSSLAES* random) {
	biginteger qMinusOne = dlog->getOrder() - 1;

	//Sample random values 
	biginteger y = getRandomInRange(0, qMinusOne, random);
	biginteger alpha0 = getRandomInRange(0, qMinusOne, random);

	//Set alpha1 = alpha0 + 1 
	biginteger alpha1 = alpha0 + 1;

	//Calculate tuple elements
	auto g0 = dlog->getGenerator();
	auto g1 = dlog->exponentiate(g0.get(), y);
	auto h0 = dlog->exponentiate(g0.get(), alpha0);
	auto h1 = dlog->exponentiate(g1.get(), alpha1);

	OTFullSimDDHReceiverMsg tuple(g1->generateSendableData(), h0->generateSendableData(), h1->generateSendableData());

	//Send tuple to sender.
	//Send the message by the channel.
	auto msgStr = tuple.toString();
	channel->writeWithSize(msgStr);

	//Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH.
	auto g1Inv = dlog->getInverse(g1.get());
	auto h1DivG1 = dlog->multiplyGroupElements(h1.get(), g1Inv.get());

	zkProver->prove(make_shared<SigmaDHProverInput>(g1, h0, h1DivG1, alpha0));

	return make_shared<OTFullSimPreprocessPhaseValues>(g0, g1, h0, h1);
}

/**
* Runs the following line from the protocol:
* "WAIT for message (h0,h1) from R"
* @param channel
* @return the received message.
* @throws ClassNotFoundException
* @throws IOException if failed to receive a message.
*/
OTRGroupElementPairMsg OTFullSimSenderTransferUtilAbs::waitForMessageFromReceiver(CommParty* channel) {
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);

	// create an empty OTRGroupElementPairMsg and initialize it with the received data. 
	OTRGroupElementPairMsg msg;
	msg.initFromByteVector(raw_msg);

	return msg;
}

/**
* Runs the transfer phase of the OT protocol.<p>
* Transfer Phase (with inputs x0,x1)<p>
*	WAIT for message from R<p>
*	DENOTE the values received by (g,h) <p>
*	COMPUTE (u0,v0) = RAND(g0,g,h0,h)<p>
*	COMPUTE (u1,v1) = RAND(g1,g,h1,h)<p>
*	in the byte array scenario:<p>
*		COMPUTE c0 = x0 XOR KDF(|x0|,v0)<p>
*		COMPUTE c1 = x1 XOR KDF(|x1|,v1)<p>
*	in the GroupElement scenario:<p>
*		COMPUTE c0 = x0 * v0<p>
*		COMPUTE c1 = x1 * v1<p>
*	SEND (u0,c0) and (u1,c1) to R<p>
*	OUTPUT nothing<p>
* This is the transfer stage of OT protocol which can be called several times in parallel.<p>
* The OT implementation support usage of many calls to transfer, with single preprocess execution. <p>
* This way, one can execute batch OT by creating the OT receiver once and call the transfer function for each input couple.<p>
* In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages.
* This way the parallel executions of the function will not block each other.
* @param channel each call should get a different one.
* @param input the parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
* @param preprocessValues hold the values calculated in the preprocess phase.
* @return OTROutput, the output of the protocol.
* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
* @throws IOException if the send or receive functions failed
* @throws ClassNotFoundException if there was a problem during the serialization mechanism
*/
void OTFullSimSenderTransferUtilAbs::transfer(CommParty* channel, OTSInput* input, OTFullSimPreprocessPhaseValues* preprocessValues) {
	//Wait for message from R
	OTRGroupElementPairMsg message = waitForMessageFromReceiver(channel);

	auto g = dlog->reconstructElement(true, message.getFirstGE().get());
	auto h = dlog->reconstructElement(true, message.getSecondGE().get());

	//COMPUTE (u0,v0) = RAND(g0,g,h0,h)
	//COMPUTE (u1,v1) = RAND(g1,g,h1,h)
	auto g0 = preprocessValues->getG0(); //Get the group generator.
	auto tuple0 = OTUtil::rand(dlog.get(), g0.get(), g.get(), preprocessValues->getH0().get(), h.get(), random.get());
	auto tuple1 = OTUtil::rand(dlog.get(), preprocessValues->getG1().get(), g.get(), preprocessValues->getH1().get(), h.get(), random.get());
	auto u0 = tuple0.getU();
	auto v0 = tuple0.getV();
	auto u1 = tuple1.getU();
	auto v1 = tuple1.getV();

	//Compute c0, c1.
	auto tuple = computeTuple(input, u0.get(), u1.get(), v0.get(), v1.get());

	//Send the tuple for the receiver.
	auto msgStr = tuple->toString();
	channel->writeWithSize(msgStr);

}


/**
* Runs the following lines from the protocol:
* "COMPUTE:
*		c0 = x0 * v0
*		c1 = x1 * v1"
* @param input MUST be OTSOnGroupElementInput.
* @param u0
* @param u1
* @param v0
* @param v1
* @return tuple contains (u0, c0, u1, c1) to send to the receiver.
*/
shared_ptr<OTSMsg> OTFullSimOnGroupElementSenderTransferUtil::computeTuple(OTSInput* input, GroupElement* u0, GroupElement* u1, GroupElement* v0, GroupElement* v1) {
	//If input is not instance of OTSOnGroupElementInput, throw Exception.
	auto in = dynamic_cast<OTOnGroupElementSInput*>(input);
	if (in == nullptr) {
		throw invalid_argument("x0 and x1 should be DlogGroup elements");
	}

	//Get x0, x1.
	auto x0 = in->getX0();
	auto x1 = in->getX1();

	//Calculate c0:
	auto c0 = dlog->multiplyGroupElements(x0.get(), v0);

	//Calculate c1:
	auto c1 = dlog->multiplyGroupElements(x1.get(), v1);

	//Create and return sender message.
	return make_shared<OTOnGroupElementSMsg>(u0->generateSendableData(),
		c0->generateSendableData(), u1->generateSendableData(), c1->generateSendableData());
}

/**
* Runs the following lines from the protocol:
* "COMPUTE:
*		COMPUTE c0 = x0 XOR KDF(|x0|,v0)
*		COMPUTE c1 = x1 XOR KDF(|x1|,v1)"
* @param input must be a OTSOnByteArrayInput.
* @param u0
* @param u1
* @param v0
* @param v1
* @return tuple contains (u0, c0, u1, c1) to send to the receiver.
*/
shared_ptr<OTSMsg> OTFullSimOnByteArraySenderTransferUtil::computeTuple(OTSInput* input, GroupElement* u0, GroupElement* u1, GroupElement* v0, GroupElement* v1) {
	//If input is not instance of OTOnByteArraySInput, throw Exception.
	auto in = dynamic_cast<OTOnByteArraySInput*>(input);
	if (in == nullptr) {
		throw invalid_argument("x0 and x1 should be binary strings");
	}

	//Get x0, x1.
	auto x0 = in->getX0();
	auto x1 = in->getX1();

	//If x0, x1 are not of the same length, throw Exception.
	if (x0.size() != x1.size()) {
		throw invalid_argument("x0 and x1 should be of the same length");
	}

	//Calculate c0:
	auto v0Bytes = dlog->mapAnyGroupElementToByteArray(v0);
	int len = x0.size();
	auto c0 = kdf->deriveKey(v0Bytes, 0, v0Bytes.size(), len).getEncoded();

	//Xores the result from the kdf with x0.
	for (int i = 0; i<len; i++) {
		c0[i] = (byte)(c0[i] ^ x0[i]);
	}

	//Calculate c1:
	auto v1Bytes = dlog->mapAnyGroupElementToByteArray(v1);
	auto c1 = kdf->deriveKey(v1Bytes, 0, v1Bytes.size(), len).getEncoded();

	//Xores the result from the kdf with x1.
	for (int i = 0; i<len; i++) {
		c1[i] = c1[i] ^ x1[i];
	}

	//Create and return sender message.
	return make_shared<OTOnByteArraySMsg>(u0->generateSendableData(), c0, u1->generateSendableData(), c1);
}

/**
* Sets the given dlog, kdf and random.
* @param dlog
* @param kdf
* @param random
*/
OTFullSimOnByteArraySenderTransferUtil::OTFullSimOnByteArraySenderTransferUtil(const shared_ptr<DlogGroup> & dlog, const shared_ptr<KeyDerivationFunction> & kdf, const shared_ptr<PrgFromOpenSSLAES> & random)
	: OTFullSimSenderTransferUtilAbs(dlog, random) {
	this->kdf = kdf;
}

/**
* Runs the following lines from the protocol:
* "COMPUTE
* 4.	g = (gSigma)^r
* 5.	h = (hSigma)^r"
* @param sigma input of the protocol
* @param r random value sampled in the protocol
* @return OTRFullSimMessage contains the tuple (g,h).
*/
OTRGroupElementPairMsg OTFullSimReceiverTransferUtilAbs::computeSecondTuple(byte sigma, biginteger & r, OTFullSimPreprocessPhaseValues* preprocessValues) {
	shared_ptr<GroupElement> g, h;

	if (sigma == 0) {
		g = dlog->exponentiate(preprocessValues->getG0().get(), r);
		h = dlog->exponentiate(preprocessValues->getH0().get(), r);
	}
	else {
		g = dlog->exponentiate(preprocessValues->getG1().get(), r);
		h = dlog->exponentiate(preprocessValues->getH1().get(), r);
	}

	return OTRGroupElementPairMsg(g->generateSendableData(), h->generateSendableData());
}

/**
* Sets the given dlog and random.
* @param dlog
* @param random
*/
OTFullSimReceiverTransferUtilAbs::OTFullSimReceiverTransferUtilAbs(const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & random)
	: random(random), dlog(dlog) {
	qMinusOne = dlog->getOrder() - 1;
}

/**
*
* Run the transfer phase of the OT protocol.<p>
* Transfer Phase (with inputs sigma) <p>
*		SAMPLE a random value r <- {0, . . . , q-1} <p>
*		COMPUTE<p>
*		4.	g = (gSigma)^r<p>
*		5.	h = (hSigma)^r<p>
*		SEND (g,h) to S<p>
*		WAIT for messages (u0,c0) and (u1,c1) from S<p>
*		In ByteArray scenario:<p>
*		IF  NOT<p>
*			u0, u1 in G, AND<p>
*			c0, c1 are binary strings of the same length<p>
*		      REPORT ERROR<p>
*		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)<p>
*		In GroupElement scenario:<p>
*		IF  NOT<p>
*			u0, u1, c0, c1 in G<p>
*		      REPORT ERROR<p>
*		OUTPUT  xSigma = cSigma * (uSigma)^(-r)<p>
* This is the transfer stage of OT protocol which can be called several times in parallel.<p>
* The OT implementation support usage of many calls to transfer, with single preprocess execution. <p>
* This way, one can execute batch OT by creating the OT receiver once and call the transfer function for each input couple.<p>
* In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages.
* This way the parallel executions of the function will not block each other.
* @param channel each call should get a different one.
* @param input MUST be OTRBasicInput. The parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
* @param preprocessValues hold the values calculated in the preprocess phase.
* @return OTROutput, the output of the protocol.
* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
* @throws IOException if the send or receive functions failed
* @throws ClassNotFoundException if there was a problem during the serialization mechanism
*/
shared_ptr<OTROutput> OTFullSimReceiverTransferUtilAbs::transfer(CommParty* channel, OTRInput* input, OTFullSimPreprocessPhaseValues* preprocessValues) {
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

	//Sample a random value r <- {0, . . . , q-1} 
	biginteger r = getRandomInRange(0, qMinusOne, random.get());

	//Compute tuple (g,h) for sender.
	OTRGroupElementPairMsg a = computeSecondTuple(sigma, r, preprocessValues);

	//Send tuple to sender.
	auto msgStr = a.toString();
	channel->writeWithSize(msgStr);

	//Compute the final calculations to get xSigma.
	return getMsgAndComputeXSigma(channel, sigma, r);
}

/**
* Run the following line from the protocol:
* "IF  NOT
*		1. u0, u1, c0, c1 in the DlogGroup
*	REPORT ERROR"
* @param c1
* @param c0
* @param u1
* @param u0
* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
*/
void OTFullSimOnGroupElementReceiverTransferUtil::checkReceivedTuple(GroupElement* u0, GroupElement* u1, GroupElement* c0, GroupElement* c1) {

	if (!(dlog->isMember(u0))) {
		throw CheatAttemptException("u0 element is not a member in the current DlogGroup");
	}
	if (!(dlog->isMember(u1))) {
		throw CheatAttemptException("u1 element is not a member in the current DlogGroup");
	}
	if (!(dlog->isMember(c0))) {
		throw CheatAttemptException("c0 element is not a member in the current DlogGroup");
	}
	if (!(dlog->isMember(c1))) {
		throw CheatAttemptException("c1 element is not a member in the current DlogGroup");
	}
}

/**
* Run the following lines from the protocol:
* "COMPUTE xSigma = cSigma * (uSigma)^(-r)"
* @param sigma input of the protocol
* @param r random value sampled in the protocol
* @param message received from the sender
* @return OTROutput contains xSigma
* @throws CheatAttemptException
*/
shared_ptr<OTROutput> OTFullSimOnGroupElementReceiverTransferUtil::getMsgAndComputeXSigma(CommParty* channel, byte sigma, biginteger & r) {
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);

	// create an empty OTRGroupElementPairMsg and initialize it with the received data. 
	OTOnGroupElementSMsg msg;
	msg.initFromByteVector(raw_msg);

	//Reconstruct the group elements from the given message.
	auto u0 = dlog->reconstructElement(true, msg.getW0().get());
	auto u1 = dlog->reconstructElement(true, msg.getW1().get());
	auto c0 = dlog->reconstructElement(true, msg.getC0().get());
	auto c1 = dlog->reconstructElement(true, msg.getC1().get());

	//Compute the validity checks of the given message.		
	checkReceivedTuple(u0.get(), u1.get(), c0.get(), c1.get());

	shared_ptr<GroupElement> xSigma, cSigma;
	biginteger minusR = dlog->getOrder() - r;

	//If sigma = 0, compute (uSigma)^(-r) and set cSigma to c0.
	if (sigma == 0) {
		xSigma = dlog->exponentiate(u0.get(), minusR);
		cSigma = c0;
	}

	//If sigma = 1, compute w1^beta and set cSigma to c1.
	if (sigma == 1) {
		xSigma = dlog->exponentiate(u1.get(), minusR);
		cSigma = c1;
	}

	xSigma = dlog->multiplyGroupElements(cSigma.get(), xSigma.get());

	//Create and return the output containing xSigma
	return make_shared<OTOnGroupElementROutput>(xSigma);
}

/**
* Run the following line from the protocol:
* "IF NOT
*		1. u0, u1 in the DlogGroup, AND
*		2. c0, c1 are binary strings of the same length
*	   REPORT ERROR"
* @param c1
* @param c0
* @param u1
* @param u0
* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
*/
void OTFullSimOnByteArrayReceiverTransferUtil::checkReceivedTuple(GroupElement* u0, GroupElement* u1, vector<byte> & c0, vector<byte> & c1) {

	if (!(dlog->isMember(u0))) {
		throw new CheatAttemptException("u0 element is not a member in the current DlogGroup");
	}
	if (!(dlog->isMember(u1))) {
		throw new CheatAttemptException("u1 element is not a member in the current DlogGroup");
	}

	if (c0.size() != c1.size()) {
		throw new CheatAttemptException("c0 and c1 is not in the same length");
	}
}

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
shared_ptr<OTROutput> OTFullSimOnByteArrayReceiverTransferUtil::getMsgAndComputeXSigma(CommParty* channel, byte sigma, biginteger & r) {
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);

	// create an empty OTRGroupElementPairMsg and initialize it with the received data. 
	OTOnByteArraySMsg msg;
	msg.initFromByteVector(raw_msg);

	//Reconstruct the group elements from the given message.
	auto u0 = dlog->reconstructElement(true, msg.getW0().get());
	auto u1 = dlog->reconstructElement(true, msg.getW1().get());

	//Get the byte arrays from the given message.
	auto c0 = msg.getC0();
	auto c1 = msg.getC1();

	//Compute the validity checks of the given message.		
	checkReceivedTuple(u0.get(), u1.get(), c0, c1);

	shared_ptr<GroupElement> kdfInput;
	vector<byte> cSigma;

	//If sigma = 0, compute u0^r and set cSigma to c0.
	if (sigma == 0) {
		kdfInput = dlog->exponentiate(u0.get(), r);
		cSigma = c0;
	}

	//If sigma = 1, compute u1^r and set cSigma to c1.
	if (sigma == 1) {
		kdfInput = dlog->exponentiate(u1.get(), r);
		cSigma = c1;
	}

	//Compute kdf result:
	int len = c0.size(); // c0 and c1 have the same size.
	auto kdfBytes = dlog->mapAnyGroupElementToByteArray(kdfInput.get());
	auto xSigma = kdf->deriveKey(kdfBytes, 0, kdfBytes.size(), len).getEncoded();

	//Xores the result from the kdf with vSigma.
	for (int i = 0; i<len; i++) {
		xSigma[i] = cSigma[i] ^ xSigma[i];
	}

	//Create and return the output containing xSigma
	return make_shared<OTOnByteArrayROutput>(xSigma);
}

/**
* Constructor that sets the given channel, dlogGroup and random.
* @param channel
* @param dlog must be DDH secure.
* @param random
*/
OTFullSimDDHOnGroupElementSender::OTFullSimDDHOnGroupElementSender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random,
	const shared_ptr<DlogGroup> & dlog) {

	//The underlying dlog group must be DDH secure.
	auto ddh = dynamic_pointer_cast<DDH>(dlog);
	if (ddh == NULL) {
		throw SecurityLevelException("DlogGroup should have DDH security level");
	}

	// Runs the following part of the protocol:
	//	IF NOT VALID_PARAMS(G,q,g0)
	//   REPORT ERROR and HALT.
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("The given DlogGRoup is not valid");

	this->dlog = dlog;
	this->random = random;

	//Create the underlying ZKPOK
	ZKPOKFromSigmaCmtPedersenVerifier zkVerifier(channel, make_shared<SigmaDHVerifierComputation>(dlog, 80, random), make_shared<CmtRTrapdoorCommitPhaseOutput>(), dlog);

	// Some OT protocols have a pre-process stage before the transfer. 
	// Usually, pre process is done once at the beginning of the protocol and will not be executed later, 
	// and then the transfer function could be called multiple times.
	// We implement the preprocess stage at construction time. 
	// A protocol that needs to call preprocess after the construction time, should create a new instance.
	//Call the utility function that executes the preprocess phase.
	preprocessOutput = OTFullSimSenderPreprocessUtil::preProcess(channel.get(), dlog.get(), &zkVerifier);
}

/**
* Runs the transfer phase of the OT protocol.<p>
*	Transfer Phase (with inputs x0,x1)<p>
*	WAIT for message from R<p>
*	DENOTE the values received by (g,h) <p>
*	COMPUTE (u0,v0) = RAND(g0,g,h0,h)<p>
*	COMPUTE (u1,v1) = RAND(g1,g,h1,h)<p>
*	COMPUTE c0 = x0 * v0<p>
*	COMPUTE c1 = x1 * v1<p>
*	SEND (u0,c0) and (u1,c1) to R<p>
*	OUTPUT nothing<p>
*/
void OTFullSimDDHOnGroupElementSender::transfer(CommParty* channel, OTSInput* input) {
	//Creates the utility class that executes the transfer phase.
	OTFullSimOnGroupElementSenderTransferUtil transferUtil(dlog, random);
	transferUtil.transfer(channel, input, preprocessOutput.get());

}

/**
* Constructor that sets the given channel, dlogGroup and random.
* @param channel
* @param dlog must be DDH secure.
* @param kdf
* @param random
* @throws SecurityLevelException if the given dlog is not DDH secure
* @throws InvalidDlogGroupException
* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
* @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat in the preprocess phase.
* @throws IOException if there was a problem during the communication in the preprocess phase.
* @throws CommitValueException can occur in case of ElGamal commitment scheme.
*/
OTFullSimDDHOnByteArraySender::OTFullSimDDHOnByteArraySender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random,
	const shared_ptr<DlogGroup> & dlog, const shared_ptr<KeyDerivationFunction> & kdf) {

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
	this->kdf = kdf;
	this->random = random;

	//Create the underlying ZKPOK
	ZKPOKFromSigmaCmtPedersenVerifier zkVerifier(channel, make_shared<SigmaDHVerifierComputation>(dlog, 80, random), make_shared<CmtRTrapdoorCommitPhaseOutput>(), dlog);

	// Some OT protocols have a pre-process stage before the transfer. 
	// Usually, pre process is done once at the beginning of the protocol and will not be executed later, 
	// and then the transfer function could be called multiple times.
	// We implement the preprocess stage at construction time. 
	// A protocol that needs to call preprocess after the construction time, should create a new instance.
	//Call the utility function that executes the preprocess phase.
	preprocessOutput = OTFullSimSenderPreprocessUtil::preProcess(channel.get(), dlog.get(), &zkVerifier);
}

/**
* Runs the transfer phase of the OT protocol.<p>
* This is the part of the protocol where the sender's input is necessary as follows:<p>
*	Transfer Phase (with inputs x0,x1)<p>
*	WAIT for message from R<p>
*	DENOTE the values received by (g,h) <p>
*	COMPUTE (u0,v0) = RAND(g0,g,h0,h)<p>
*	COMPUTE (u1,v1) = RAND(g1,g,h1,h)<p>
*	COMPUTE c0 = x0 XOR KDF(|x0|,v0)<p>
*	COMPUTE c1 = x1 XOR KDF(|x1|,v1)<p>
*	SEND (u0,c0) and (u1,c1) to R<p>
*	OUTPUT nothing<p>
*/
void OTFullSimDDHOnByteArraySender::transfer(CommParty* channel, OTSInput* input) {
	//Creates the utility class that executes the transfer phase.
	OTFullSimOnByteArraySenderTransferUtil transferUtil(dlog, kdf, random);
	transferUtil.transfer(channel, input, preprocessOutput.get());
}

/**
* Constructor that sets the given channel, dlogGroup and random.
* @param channel
* @param dlog must be DDH secure.
* @param random
* @throws SecurityLevelException if the given dlog is not DDH secure
* @throws InvalidDlogGroupException if the given DlogGroup is not valid.
* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
* @throws CheatAttemptException if the receiver suspects that the sender is trying to cheat in the preprocess phase.
* @throws IOException if there was a problem during the communication in the preprocess phase.
* @throws CommitValueException can occur in case of ElGamal commitment scheme.
*/
OTFullSimDDHOnGroupElementReceiver::OTFullSimDDHOnGroupElementReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random,
	const shared_ptr<DlogGroup> & dlog) {

	//The underlying dlog group must be DDH secure.
	auto ddh = dynamic_pointer_cast<DDH>(dlog);
	if (ddh == NULL) {
		throw SecurityLevelException("DlogGroup should have DDH security level");
	}

	//Check that the given dlog is valid.
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("The given DlogGroup is not valid");

	this->dlog = dlog;
	this->random = random;

	//Creates the underlying ZKPOK. 
	ZKPOKFromSigmaCmtPedersenProver zkProver(channel, make_shared<SigmaDHProverComputation>(dlog, 80, random), dlog);

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
shared_ptr<OTROutput> OTFullSimDDHOnGroupElementReceiver::transfer(CommParty* channel, OTRInput* input) {
	//Creates the utility class that executes the transfer phase.
	OTFullSimOnGroupElementReceiverTransferUtil transferUtil(dlog, random);
	return transferUtil.transfer(channel, input, preprocessOutput.get());
}

/**
* Constructor that sets the given channel, dlogGroup and random.
* @param channel
* @param dlog must be DDH secure.
* @param random
* @throws SecurityLevelException if the given dlog is not DDH secure
* @throws InvalidDlogGroupException if the given DlogGroup is not valid.
* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
* @throws CheatAttemptException if the receiver suspects that the sender is trying to cheat in the preprocess phase.
* @throws IOException if there was a problem during the communication in the preprocess phase.
* @throws CommitValueException can occur in case of ElGamal commitment scheme.
*/
OTFullSimDDHOnByteArrayReceiver::OTFullSimDDHOnByteArrayReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random,
	const shared_ptr<DlogGroup> & dlog, const shared_ptr<KeyDerivationFunction> & kdf) {

	//The underlying dlog group must be DDH secure.
	auto ddh = dynamic_pointer_cast<DDH>(dlog);
	if (ddh == NULL) {
		throw SecurityLevelException("DlogGroup should have DDH security level");
	}

	//Check that the given dlog is valid.
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("The given Dlog Group is not valid");

	this->kdf = kdf;
	this->dlog = dlog;
	this->random = random;

	//Creates the underlying ZKPOK. 
	ZKPOKFromSigmaCmtPedersenProver zkProver(channel, make_shared<SigmaDHProverComputation>(dlog, 80, random), dlog);

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
* Run the transfer phase of the protocol.<p>
* Transfer Phase (with input sigma) <p>
*	SAMPLE a random value r <- {0, . . . , q-1} <p>
*	COMPUTE<p>
*	4.	g = (gSigma)^r<p>
*	5.	h = (hSigma)^r<p>
*	SEND (g,h) to S<p>
*	WAIT for messages (u0,c0) and (u1,c1) from S<p>
*	IF  NOT<p>
*		u0, u1 in G, AND<p>
*		c0, c1 are binary strings of the same length<p>
*		   REPORT ERROR<p>
*	OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)<p>
*/
shared_ptr<OTROutput> OTFullSimDDHOnByteArrayReceiver::transfer(CommParty* channel, OTRInput* input) {
	//Creates the utility class that executes the transfer phase.
	OTFullSimOnByteArrayReceiverTransferUtil transferUtil(dlog, kdf, random);
	return transferUtil.transfer(channel, input, preprocessOutput.get());
}