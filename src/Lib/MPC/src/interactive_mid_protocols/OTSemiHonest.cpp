#include "../../include/interactive_mid_protocols/OTSemiHonest.hpp"

string OTSemiHonestDDHOnGroupElementSenderMsg::toString() {
	return u->toString() + ":" + v0->toString() + ":" + v1->toString();

}
void OTSemiHonestDDHOnGroupElementSenderMsg::initFromString(const string & row) {
	auto str_vec = explode(row, ':');
	int size = str_vec.size();
	assert(size == 3 || size == 6);
	if (size == 3) {
		u = make_shared<ZpElementSendableData>(0);
		v0 = make_shared<ZpElementSendableData>(0);
		v1 = make_shared<ZpElementSendableData>(0);
		u->initFromString(str_vec[0]);
		v0->initFromString(str_vec[1]);
		v1->initFromString(str_vec[2]);
	}
	else {
		u = make_shared<ECElementSendableData>(0,0);
		v0 = make_shared<ECElementSendableData>(0,0);
		v1 = make_shared<ECElementSendableData>(0,0);
		u->initFromString(str_vec[0] + ":" + str_vec[1]);
		v0->initFromString(str_vec[2] + ":" + str_vec[3]);
		v1->initFromString(str_vec[4] + ":" + str_vec[5]);
	}
}

string OTSemiHonestDDHOnByteArraySenderMsg::toString() {
	string output = u->toString() + ":";
	output += string(reinterpret_cast<char const*>(v0.data()), v0.size());
	output += ":";
	output += string(reinterpret_cast<char const*>(v1.data()), v1.size());
	return output; 
}

void OTSemiHonestDDHOnByteArraySenderMsg::initFromString(const string & row) {
	auto str_vec = explode(row, ':');
	int size = str_vec.size();
	assert(size == 3 || size == 4);
	if (size == 3) {
		u = make_shared<ZpElementSendableData>(0);
		u->initFromString(str_vec[0]);
		v0.assign(str_vec[1].begin(), str_vec[1].end());
		v1.assign(str_vec[2].begin(), str_vec[2].end());
	}
	else {
		u = make_shared<ECElementSendableData>(0, 0);
		u->initFromString(str_vec[0] + ":" + str_vec[1]);
		v0.assign(str_vec[2].begin(), str_vec[2].end());
		v1.assign(str_vec[3].begin(), str_vec[3].end());
	}
}

void OTSemiHonestDDHSenderAbs::transfer(CommParty* channel, OTSInput* input) {
	//WAIT for message (h0,h1) from R
	auto message = waitForMessageFromReceiver(channel);
	
	//SAMPLE a random value r in  [0, . . . , q-1] 
	biginteger r = getRandomInRange(0, qMinusOne, random.get());
	
	//Compute u, k0, k1
	auto u = computeU(r);
	auto k0 = computeK0(r, message.get());
	auto k1 = computeK1(r, message.get());
	
	auto messageToSend = computeTuple(input, u.get(), k0.get(), k1.get());
	sendTupleToReceiver(channel, messageToSend.get());
}

/**
* Constructor that sets the given dlogGroup and random.
* @param dlog must be DDH secure.
* @param random
* @throws SecurityLevelException if the given dlog is not DDH secure
*/
OTSemiHonestDDHSenderAbs::OTSemiHonestDDHSenderAbs(const shared_ptr<PrgFromOpenSSLAES> & random, const shared_ptr<DlogGroup> & dlog) {
	//The underlying dlog group must be DDH secure.
	auto ddh = dynamic_pointer_cast<DDH>(dlog);
	if (ddh == NULL) {
		throw SecurityLevelException("DlogGroup should have DDH security level");
	}

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
* @throws ClassNotFoundException
* @throws IOException if failed to receive a message.
*/
shared_ptr<OTRGroupElementPairMsg> OTSemiHonestDDHSenderAbs::waitForMessageFromReceiver(CommParty* channel) {
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);

	// create an empty OTRGroupElementPairMsg and initialize it with the received data. 
	auto msg = make_shared<OTRGroupElementPairMsg>();
	msg->initFromByteVector(raw_msg);

	return msg;
}

/**
* Runs the following line from the protocol:
* "COMPUTE u = g^r"
* @param r the exponent
* @return the computed u.
*/
shared_ptr<GroupElement> OTSemiHonestDDHSenderAbs::computeU(biginteger & r) {
	auto g = dlog->getGenerator(); //Get the group generator.

									//Calculate u = g^r.
	return dlog->exponentiate(g.get(), r);
}

/**
* Runs the following line from the protocol:
* "COMPUTE k0 = h0^r"
* @param r the exponent
* @param message contains h0
* @return the computed k0
*/
shared_ptr<GroupElement> OTSemiHonestDDHSenderAbs::computeK0(biginteger & r, OTRGroupElementPairMsg* message) {

	//Recreate h0 from the data in the received message.
	auto h0 = dlog->reconstructElement(true, message->getFirstGE().get());

	//Calculate k0 = h0^r.
	return dlog->exponentiate(h0.get(), r);
}

/**
* Runs the following line from the protocol:
* "COMPUTE k1 = h1^r"
* @param r the exponent
* @param message contains h1
* @return the computed k1
*/
shared_ptr<GroupElement> OTSemiHonestDDHSenderAbs::computeK1(biginteger & r, OTRGroupElementPairMsg* message) {

	//Recreate h0, h1 from the data in the received message.
	auto h1 = dlog->reconstructElement(true, message->getSecondGE().get());

	//Calculate k1 = h1^r.
	return dlog->exponentiate(h1.get(), r);
}

/**
* Runs the following lines from the protocol:
* "SEND (u,v0,v1) to R"
* @param channel
* @param message to send to the receiver
* @throws IOException if failed to send the message.
*/
void OTSemiHonestDDHSenderAbs::sendTupleToReceiver(CommParty* channel, OTSMsg* message) {

	//Send the message by the channel.
	auto msgStr = message->toString();
	channel->writeWithSize(msgStr);
}

	
/**
* Runs the following lines from the protocol:
* "COMPUTE:
*			v0 = x0 * k0
*			v1 = x1 * k1"
* @param input MUST be an instance of OTSOnGroupElementInput
* @param k1
* @param k0
* @param u
* @return tuple contains (u, v0, v1) to send to the receiver.
*/
shared_ptr<OTSMsg> OTSemiHonestDDHOnGroupElementSender::computeTuple(OTSInput* input, GroupElement* u, GroupElement* k0, GroupElement* k1) {
	//If input is not instance of OTSOnGroupElementInput, throw Exception.
	auto in = dynamic_cast<OTOnGroupElementSInput*>(input);
	if (in == nullptr) {
		throw invalid_argument("x0 and x1 should be DlogGroup elements");
	}

	//Set x0, x1.
	auto x0 = in->getX0();
	auto x1 = in->getX1();

	//Calculate v0:
	auto v0 = dlog->multiplyGroupElements(x0.get(), k0);

	//Calculate v1:
	auto v1 = dlog->multiplyGroupElements(x1.get(), k1);

	//Create and return sender message.
	return make_shared<OTSemiHonestDDHOnGroupElementSenderMsg>(u->generateSendableData(), v0->generateSendableData(), v1->generateSendableData());
}

/**
* Runs the following lines from the protocol:
* "COMPUTE:
*			v0 = x0 XOR KDF(|x0|,k0)
*			v1 = x1 XOR KDF(|x1|,k1)"
* @param input MUST be an instance of OTSOnByteArrayInput
* @param k1
* @param k0
* @param u
* @return tuple contains (u, v0, v1) to send to the receiver.
*/
shared_ptr<OTSMsg> OTSemiHonestDDHOnByteArraySender::computeTuple(OTSInput* input, GroupElement* u, GroupElement* k0, GroupElement* k1) {
	//If input is not instance of OTSOnByteArrayInput, throw Exception.
	auto in = dynamic_cast<OTOnByteArraySInput*>(input);
	if (in == nullptr) {
		throw invalid_argument("x0 and x1 should be binary strings.");
	}

	auto x0 = in->getX0();
	auto x1 = in->getX1();

	//If x0, x1 are not of the same length, throw Exception.
	if (x0.size() != x1.size()) {
		throw invalid_argument("x0 and x1 should be of the same length.");
	}

	//Calculate v0:
	auto k0Bytes = dlog->mapAnyGroupElementToByteArray(k0);

	int len = x0.size();
	auto v0 = kdf->deriveKey(k0Bytes, 0, k0Bytes.size(), len).getEncoded();

	//Xores the result from the kdf with x0.
	for (int i = 0; i<len; i++) {
		v0[i] = v0[i] ^ x0[i];
	}

	//Calculate v1:
	auto k1Bytes = dlog->mapAnyGroupElementToByteArray(k1);
	auto v1 = kdf->deriveKey(k1Bytes, 0, k1Bytes.size(), len).getEncoded();

	//Xores the result from the kdf with x1.
	for (int i = 0; i<len; i++) {
		v1[i] = v1[i] ^ x1[i];
	}

	//Create and return sender message.
	return make_shared<OTSemiHonestDDHOnByteArraySenderMsg>(u->generateSendableData(), v0, v1);
	}

/**
* Run the transfer phase of the protocol.<p>
* "SAMPLE random values alpha in Zq and h in the DlogGroup <p>
*		COMPUTE h0,h1 as follows:<p>
*			1.	If sigma = 0 then h0 = g^alpha  and h1 = h<p>
*			2.	If sigma = 1 then h0 = h and h1 = g^alpha <p>
*		SEND (h0,h1) to S<p>
*		WAIT for the message (u, v0,v1) from S<p>
*		COMPUTE kSigma = (u)^alpha							- in byte array scenario<p>
*			 OR (kSigma)^(-1) = u^(-alpha)					- in GroupElement scenario<p>
*		OUTPUT  xSigma = vSigma XOR KDF(|cSigma|,kSigma)	- in byte array scenario<p>
*			 OR xSigma = vSigma * (kSigma)^(-1)" 			- in GroupElement scenario<p>
*/
shared_ptr<OTROutput> OTSemiHonestDDHReceiverAbs::transfer(CommParty* channel, OTRInput* input){
	//check if the input is valid.
	//If input is not instance of OTRBasicInput, throw Exception.
	auto in = dynamic_cast<OTRBasicInput*>(input);
	if (in == nullptr) {
		throw invalid_argument("input should contain sigma.");
	}

	bool sigma = in->getSigma();
	//The given sigma should be 0 or 1.
	if ((sigma != 0) && (sigma != 1)) {
		throw  invalid_argument("Sigma should be 0 or 1");
	}

	//Sample random alpha
	biginteger alpha = getRandomInRange(0, qMinusOne, random.get());
	
	//Compute h0, h1
	auto tuple = computeTuple(alpha, sigma);
	
	//Send the tuple to sender
	sendTupleToSender(channel, tuple.get());
	
	//Wait for message from sender and Compute xSigma
	return getMsgAndComputeXSigma(channel, sigma, alpha);

}


/**
* Constructor that sets the given dlogGroup and random.
* @param dlog must be DDH secure.
* @param random
* @throws SecurityLevelException if the given dlog is not DDH secure.
*/
OTSemiHonestDDHReceiverAbs::OTSemiHonestDDHReceiverAbs(const shared_ptr<PrgFromOpenSSLAES> & random, const shared_ptr<DlogGroup> & dlog) {
	//The underlying dlog group must be DDH secure.
	auto ddh = dynamic_pointer_cast<DDH>(dlog);
	if (ddh == NULL) {
		throw SecurityLevelException("DlogGroup should have DDH security level");
	}

	this->dlog = dlog;
	this->random = random;
	qMinusOne = dlog->getOrder() - 1;

	// This protocol has no pre process stage.
}

/**
* Runs the following lines from the protocol:
*  COMPUTE h0,h1 as follows:
*		1.	If sigma = 0 then h0 = g^alpha  and h1 = h
*		2.	If sigma = 1 then h0 = h and h1 = g^alpha"
* @param alpha random value sampled by the protocol
* @param sigma input for the protocol
* @return OTRSemiHonestMessage contains the tuple (h0, h1).
*/
shared_ptr<OTRGroupElementPairMsg> OTSemiHonestDDHReceiverAbs::computeTuple(biginteger & alpha, bool sigma) {

	//Sample random h.
	auto h = dlog->createRandomElement();

	//Calculate g^alpha.
	auto g = dlog->getGenerator();
	auto gAlpha = dlog->exponentiate(g.get(), alpha);

	shared_ptr<GroupElement> h0, h1;
	if (sigma == 0) {
		h0 = gAlpha;
		h1 = h;
	}
	if (sigma == 1) {
		h0 = h;
		h1 = gAlpha;
	}
	return make_shared<OTRGroupElementPairMsg>(h0->generateSendableData(), h1->generateSendableData());
}

/**
* Runs the following line from the protocol:
* "SEND (h0,h1) to S"
* @param channel
* @param tuple contains (h0,h1)
* @throws IOException if failed to send the message.
*/
void OTSemiHonestDDHReceiverAbs::sendTupleToSender(CommParty* channel, OTRGroupElementPairMsg* tuple) {
	//Send the message by the channel.
	auto msgStr = tuple->toString();
	channel->writeWithSize(msgStr);
}

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
shared_ptr<OTROutput> OTSemiHonestDDHOnGroupElementReceiver::getMsgAndComputeXSigma(CommParty* channel, bool sigma, biginteger & alpha) {
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);

	// create an empty OTRGroupElementPairMsg and initialize it with the received data. 
	auto msg = make_shared<OTSemiHonestDDHOnGroupElementSenderMsg>();
	msg->initFromByteVector(raw_msg);

	//Compute (kSigma)^(-1) = u^(-alpha):
	auto u = dlog->reconstructElement(true, msg->getU().get());	//Get u
	biginteger beta = dlog->getOrder() - alpha;			//Get -alpha
	auto kSigma = dlog->exponentiate(u.get(), beta);

	//Get v0 or v1 according to sigma.
	shared_ptr<GroupElement> vSigma;
	if (sigma == 0) {
		vSigma = dlog->reconstructElement(true, msg->getV0().get());
	}
	if (sigma == 1) {
		vSigma = dlog->reconstructElement(true, msg->getV1().get());
	}

	//Compue xSigma
	auto xSigma = dlog->multiplyGroupElements(vSigma.get(), kSigma.get());

	//Create and return the output containing xSigma
	return make_shared<OTOnGroupElementROutput>(xSigma);
}

/**
* Runs the following lines from the protocol:
* "COMPUTE kSigma = (u)^alpha
*	OUTPUT  xSigma = vSigma XOR KDF(|cSigma|,kSigma)"
* @param sigma input for the protocol
* @param alpha random value sampled by the protocol
* @param message received from the sender. must be OTSOnByteArraySemiHonestMessage.
* @return OTROutput contains xSigma
*/
shared_ptr<OTROutput> OTSemiHonestDDHOnByteArrayReceiver::getMsgAndComputeXSigma(CommParty* channel, bool sigma, biginteger & alpha) {
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);

	// create an empty OTRGroupElementPairMsg and initialize it with the received data. 
	OTSemiHonestDDHOnByteArraySenderMsg msg;
	msg.initFromByteVector(raw_msg);
	
	//Compute kSigma:
	auto u = dlog->reconstructElement(true, msg.getU().get());
	auto kSigma = dlog->exponentiate(u.get(), alpha);
	auto kBytes = dlog->mapAnyGroupElementToByteArray(kSigma.get());

	//Get v0 or v1 according to sigma.
	vector<byte> vSigma;
	if (sigma == 0) {
		vSigma = msg.getV0();
	}
	if (sigma == 1) {
		vSigma = msg.getV1();
	}

	//Compute kdf result:
	int len = vSigma.size();
	auto xSigma = kdf->deriveKey(kBytes, 0, kBytes.size(), len).getEncoded();

	//Xores the result from the kdf with vSigma.
	for (int i = 0; i<len; i++) {
		xSigma[i] = vSigma[i] ^ xSigma[i];
	}

	//Create and return the output containing xSigma
	return make_shared<OTOnByteArrayROutput>(xSigma);
}