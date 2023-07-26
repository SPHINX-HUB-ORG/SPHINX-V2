#pragma once

#include "../comm/Comm.hpp"
#include "../primitives/Dlog.hpp"

/**
* Every OT sender needs inputs during the protocol execution, but every concrete protocol needs
* different inputs.
* This is a marker class for OT sender input, where there is a derived class
* for each OT protocol.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTSInput {
public:
	virtual ~OTSInput() {}

};

/**
* Concrete implementation of OT sender (on GroupElement) input.
* In the GroupElement scenario, the sender gets two DlogGroup elements x0, x1.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTOnGroupElementSInput : public OTSInput {
private:
	shared_ptr<GroupElement> x0;
	shared_ptr<GroupElement> x1;

public:
	/**
	* Constructor that sets two byte arrays - x0, x1.
	*/
	OTOnGroupElementSInput(const shared_ptr<GroupElement> & x0, const shared_ptr<GroupElement> & x1) : x0(x0), x1(x1) {}

	/**
	* Returns the first group element input.
	*/
	shared_ptr<GroupElement> getX0() { return x0; }

	/**
	* Returns the second group element input.
	*/
	shared_ptr<GroupElement> getX1() { return x1; }
};

/**
* Concrete implementation of OT sender (on byteArray) input.
* In the byteArray scenario, the sender gets two binary strings x0, x1 of the same (arbitrary) length.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTOnByteArraySInput : public OTSInput {

private:
	vector<byte> x0;
	vector<byte> x1;

public:
	/**
	* Constructor that sets two byte arrays - x0, x1.
	*/
	OTOnByteArraySInput(vector<byte> & x0, vector<byte> & x1) : x0(x0), x1(x1) {}

	/**
	* Returns the first byte array input.
	*/
	vector<byte> getX0() { return x0; }

	/**
	* Returns the second byte array input.
	*/
	vector<byte> getX1() { return x1; }
};

/**
* Every OT receiver needs inputs during the protocol execution, but every concrete protocol needs
* different inputs. 
* This is a marker class for OT receiver input, where there is a derived class for each OT protocol.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTRInput {
public:
	virtual ~OTRInput() {}
};

/**
* Concrete implementation of OT receiver input.
* In the basic scenario, the receiver gets a single bit representing 0/1.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTRBasicInput : public OTRInput {

	//Because java has no bit data type, we decided to hold the given bit in the smallest data type - byte. 
	//in order to use small memory space without use bit manipulation. 
private:
	bool sigma;

public:
	OTRBasicInput(bool sigma) : sigma(sigma) {}

	/**
	* Returns the sigma input.
	*/
	bool getSigma() { return sigma;	}
};

/**
* Every OT receiver outputs a result in the end of the protocol execution, but every concrete
* protocol output different data.
* This is a marker class for OT receiver output, where there is a derived class for each OT protocol.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTROutput {
public:
	virtual ~OTROutput() {}
};

/**
* Concrete implementation of OT receiver (on GroupElement) output.
* In the GroupElement scenario, the receiver outputs xSigma as a GroupElement.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTOnGroupElementROutput : public OTROutput {

private:
	shared_ptr<GroupElement> xSigma;

	/**
	* Constructor that sets the output of the protocol.
	* @param xSigma outputed from the protocol.
	*/
public:
	OTOnGroupElementROutput(const shared_ptr<GroupElement> & xSigma) : xSigma(xSigma) {}

	/**
	* Return the output of the protocol.
	*/
	shared_ptr<GroupElement> getXSigma() { return xSigma; }

};

/**
* Every Batch OT receiver outputs a result in the end of the protocol execution, but every concrete
* protocol output different data.
* This is a marker class for OT receiver output, where there is a derived class for each OT protocol.
*/
class OTBatchROutput {
public:
	virtual ~OTBatchROutput() { }
};

/**
* Concrete implementation of OT receiver (on byteArray) output.
* In the byteArray scenario, the receiver outputs xSigma as a byte array.
*
* This output class also can be viewed as the output of batch OT when xSigma is a concatenation of all xSigma byte array of all OTs.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTOnByteArrayROutput : public OTROutput, public OTBatchROutput {

protected:
	vector<byte> xSigma;

public:
	/**
	* Constructor that sets the output array of the protocol.
	* @param xSigma outputed from the protocol.
	*/
	OTOnByteArrayROutput(vector<byte> & xSigma) : xSigma(xSigma) {}
	OTOnByteArrayROutput(){}

	/**
	* Return the output array of the protocol.
	*/
	vector<byte> getXSigma() {	return xSigma;	}

	int getLength() { return xSigma.size();	}
};

/**
* General interface. Every class that implements it is signed as Oblivious Transfer sender.
*
* Oblivious Transfer is the situation where a sender has n messages, and the receiver has an
* index i. The receiver wishes to receive the i-th among the sender's messages,
* without the sender learning i, while the sender wants to ensure that the receiver receive
* only one of the n messages.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTSender {

public:
	// Some OT protocols have a pre-process stage before the transfer. 
	// Usually, pre process is done once at the beginning of the protocol and will not be executed later, 
	// then the transfer function could be called multiple times.
	// We implement the pre process stage at construction time. 
	// A protocol that needs to call pre process after the construction time, should create a new instance.

	/**
	* The transfer stage of OT protocol which can be called several times in parallel.<p>
	* The OT implementation support usage of many calls to transfer, with single preprocess execution. <p>
	* This way, one can execute batch OT by creating the OT sender once and call the transfer function for each input couple.<p>
	* In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages.
	* This way the parallel executions of the function will not block each other.
	* @param channel each call should get a different one.
	* @param input The parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
	* @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat.
	* @throws InvalidDlogGroupException if the given DlogGRoup is not valid.
	*/
	virtual void transfer(CommParty* channel, OTSInput* input) = 0;
};

/**
* General class. Every derived class is signed as Oblivious Transfer receiver.
*
* Oblivious Transfer is is a type of protocol in which a sender has n messages, and the receiver has an
* index i. The receiver wishes to receive the i-th among the sender's messages,
* without the sender learning i, while the sender wants to ensure that the receiver receive
* only one of the n messages.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTReceiver {

	// Some OT protocols have a pre-process stage before the transfer. 
	// Usually, pre process is done once at the beginning of the protocol and will not be executed later, 
	// and then the transfer function could be called multiple times.
	// We implement the preprocess stage at construction time. 
	// A protocol that needs to call preprocess after the construction time, should create a new instance.

public:
	/**
	* The transfer stage of OT protocol which can be called several times in parallel.<p>
	* The OT implementation support usage of many calls to transfer, with single preprocess execution. <p>
	* This way, one can execute batch OT by creating the OT receiver once and call the transfer function for each input couple.<p>
	* In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages.
	* This way the parallel executions of the function will not block each other.
	* @param channel each call should get a different one.
	* @param input The parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
	* @return OTROutput, the output of the protocol.
	* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	*/
	virtual shared_ptr<OTROutput> transfer(CommParty* channel, OTRInput* input) = 0;
};


/**
* Concrete implementation of OT receiver message. 
* This implementation is common for OT on byteArray and on GroupElement.
* The message contains tuple of two GroupElements - (h0, h1).
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTRGroupElementPairMsg : public NetworkSerialized {

private:
	shared_ptr<GroupElementSendableData> h0;
	shared_ptr<GroupElementSendableData> h1;

public:
	OTRGroupElementPairMsg() {}
	OTRGroupElementPairMsg(const shared_ptr<GroupElementSendableData> & h0, const shared_ptr<GroupElementSendableData> & h1) : h0(h0), h1(h1) {}

	shared_ptr<GroupElementSendableData> getFirstGE() {	return h0;	}

	shared_ptr<GroupElementSendableData> getSecondGE() { return h1;	}

	string toString();
	void initFromString(const string & row);
};

/**
* Concrete implementation of OT receiver message used by some OT receivers implementations. 
* This implementation is common for OT on byteArray and on GroupElement.
* The message contains tuple of four GroupElements - (x, y, z0, z1).
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTRGroupElementQuadMsg : public NetworkSerialized {

private:
	shared_ptr<GroupElementSendableData> x;
	shared_ptr<GroupElementSendableData> y;
	shared_ptr<GroupElementSendableData> z0;
	shared_ptr<GroupElementSendableData> z1;

public:
	OTRGroupElementQuadMsg() {}
	OTRGroupElementQuadMsg(const shared_ptr<GroupElementSendableData> & x, const shared_ptr<GroupElementSendableData> & y,
		const shared_ptr<GroupElementSendableData> & z0, const shared_ptr<GroupElementSendableData> & z1) 
		: x(x), y(y), z0(z0), z1(z1){}

	shared_ptr<GroupElementSendableData> getX() { return x;	}

	shared_ptr<GroupElementSendableData> getY() { return y; }

	shared_ptr<GroupElementSendableData> getZ0() { return z0; }

	shared_ptr<GroupElementSendableData> getZ1() { return z1; }

	string toString();
	void initFromString(const string & row);
};

/**
* Every OT sender should send a message to the receiver, but every concrete protocol sends different data.
* This is a marker class for OT sender message, where there is a derived class for each OT protocol.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTSMsg : public NetworkSerialized {};

/**
* Concrete implementation of OT sender (on GroupElement) message.
* In the GroupElement scenario, the sender sends four GroupElements - w0, w1, c0 and c1.
* This class is used by most of OT implementations. 
* An OT protocol that does not use this class (like OT SemiHonest) will create a separate
* class that matches what it needs.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTOnGroupElementSMsg : public OTSMsg {

private:
	shared_ptr<GroupElementSendableData> w0;
	shared_ptr<GroupElementSendableData> w1;
	shared_ptr<GroupElementSendableData> c0;
	shared_ptr<GroupElementSendableData> c1;

public:

	OTOnGroupElementSMsg() {}

	/**
	* Constructor that sets the tuples (w0,c0), (w1, c1) calculated by the protocol.
	*/
	OTOnGroupElementSMsg(const shared_ptr<GroupElementSendableData> & w0,
		const shared_ptr<GroupElementSendableData> & c0, const shared_ptr<GroupElementSendableData> & w1,
		const shared_ptr<GroupElementSendableData> & c1) : w0(w0), w1(w1), c0(c0), c1(c1) {}

	shared_ptr<GroupElementSendableData> getW0() {	return w0; }

	shared_ptr<GroupElementSendableData> getW1() {	return w1; }

	shared_ptr<GroupElementSendableData> getC0() {	return c0;	}

	shared_ptr<GroupElementSendableData> getC1() {	return c1;	}

	string toString();
	void initFromString(const string & row);
};

/**
* Concrete implementation of OT sender (on byte array) message.
* In the byteArray scenario, the sender sends two GroupElement - w0 and w1 and two byte arrays - c0 and c1.
* This class is used by most of OT implementations. 
* An OT protocol that does not use this class (like OT SemiHonest) will create a separate
* class that matches what it needs.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTOnByteArraySMsg : public OTSMsg {

private:
	shared_ptr<GroupElementSendableData> w0;
	shared_ptr<GroupElementSendableData> w1;
	vector<byte> c0;
	vector<byte> c1;

	/**
	* Constructor that sets the tuples (w0,c0), (w1, c1) calculated by the protocol.
	* @param w0
	* @param c0
	* @param w1
	* @param c1
	*/
public:
	OTOnByteArraySMsg() {}

	OTOnByteArraySMsg(const shared_ptr<GroupElementSendableData> & w0, vector<byte> & c0,
		const shared_ptr<GroupElementSendableData> & w1, vector<byte> & c1) 
		: w0(w0), w1(w1), c0(c0), c1(c1) {}

	shared_ptr<GroupElementSendableData> getW0() { return w0; }

	shared_ptr<GroupElementSendableData> getW1() { return w1; }

	vector<byte> getC0() { return c0; }

	vector<byte> getC1() { return c1; }

	string toString();
	void initFromString(const string & row);
};

/**
* Utility class used by OT implementations.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTUtil {
public:

	/**
	* Holds the output of the above RAND function.
	*
	*/
	class RandOutput {
	private:
		shared_ptr<GroupElement> u;
		shared_ptr<GroupElement> v;

	public:
		RandOutput(const shared_ptr<GroupElement> & u, const shared_ptr<GroupElement> & v) : u(u), v(v) {}

		shared_ptr<GroupElement> getU() {
			return u;
		}

		shared_ptr<GroupElement> getV() {
			return v;
		}
	};

	/**
	* Some OT protocols uses the function RAND(w,x,y,z).
	* This function defined as follows.<p>
	*	1.	SAMPLE random values s,t <- {0, . . . , q-1}<p>
	*	2.	COMPUTE u = w^s * y^t<p>
	*	3.	COMPUTE v = x^s * z^t<p>
	*	4.	OUTPUT (u,v)
	*/
	static OTUtil::RandOutput rand(DlogGroup* dlog, GroupElement* w, GroupElement* x, GroupElement* y, GroupElement* z, PrgFromOpenSSLAES* random);
};



