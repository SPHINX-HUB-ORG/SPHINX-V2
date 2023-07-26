/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* Libscapi uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


#pragma once
#include "../infra/Common.hpp"
#include "../primitives/Dlog.hpp"

/**
* This is a marker interface. It allows the generation of an AsymmetricCiphertext at
* an abstract level.
*/
class PlaintextSendableData : public NetworkSerialized {};


/**
* This is a marker interface for all plain-texts.
*/
class Plaintext {
public:
	/**
	* This function is used when a Plaintex needs to be sent via 
	* a Channel or any other means of sending data (including serialization).
	* It retrieves all the data needed to reconstruct this Plaintext at a later time
	* and/or in a different environment.
	* It puts all the data in an instance of the relevant class that implements the
	* PlaintextSendableData interface.
	* @return the PlaintextSendableData object
	*/
	virtual shared_ptr<PlaintextSendableData> generateSendableData()=0;
	virtual bool operator==(const Plaintext &other) const = 0;
};

/**
* This class holds the plaintext as a BigInteger.
*/
class BigIntegerPlainText : public Plaintext, public PlaintextSendableData {
private:
	biginteger x;

public:
	biginteger getX() const { return x; };
	BigIntegerPlainText(biginteger x) { this->x = x; };
	BigIntegerPlainText(string s) { this->x = biginteger(s); };
	bool operator==(const Plaintext &other) const {
		auto temp = dynamic_cast<const BigIntegerPlainText*>(&other);

		const biginteger x1 = temp->getX();
		return (x1==x);
	};

	shared_ptr<PlaintextSendableData> generateSendableData() override {
		// since BigIntegerPlainText is both a Plaintext and a PlaintextSendableData, 
		// on the one hand it has to implement the generateSendableData() function, 
		// but on the other hand it is in itself an PlaintextSendableData, so we do not really
		// generate sendable data, but just return this object.
		shared_ptr<PlaintextSendableData> res(this);
		return res;
	}

	string toString() override { return x.str(); };
	void initFromString(const string & raw) override { x = biginteger(raw); }
};

/**
* This class holds the plaintext as a ByteArray.
*/
class ByteArrayPlaintext : public Plaintext, public PlaintextSendableData {
private:
	vector<byte> text;
public:
	ByteArrayPlaintext(vector<byte> text) { this->text = text; };
	vector<byte> getText() const { return text; };
	int getTextSize() const { return text.size(); };

	bool operator==(const Plaintext &other) const {
		auto temp = dynamic_cast<const ByteArrayPlaintext*>(&other);

		vector<byte> text2 = temp->getText();
		int len2 = temp->getTextSize();
		int len = getTextSize();
		if (len2 != len)
			return false;
		for (int i = 0; i<len; i++)
			if (text[i] != text2[i])
				return false;
		return true;
	};
	shared_ptr<PlaintextSendableData> generateSendableData() override {
		// since ByteArrayPlainText is both a Plaintext and a PlaintextSendableData, 
		// on the one hand it has to implement the generateSendableData() function, 
		// but on the other hand it is in itself an PlaintextSendableData, so we do not really
		// generate sendable data, but just return this object.
		shared_ptr<PlaintextSendableData> res(this);
		return res;
	};

	string toString() override {
		const byte * uc = &(text[0]);
		return string(reinterpret_cast<char const*>(uc), text.size());
	};

	void initFromString(const string & raw) override { 
		text.assign(raw.begin(), raw.end()); }

};

/**
* This class holds the plaintext as a GroupElement.
*/
class GroupElementPlaintext : public Plaintext {
private:
	shared_ptr<GroupElement> element;

public:
	GroupElementPlaintext(shared_ptr<GroupElement> el) { element = el; };
	shared_ptr<GroupElement> getElement() const { return element; };

	bool operator==(const Plaintext &other) const {
		auto temp = dynamic_cast<const GroupElementPlaintext*>(&other);

		return (*(temp->getElement()) == *(this->getElement()));
	};

	shared_ptr<PlaintextSendableData> generateSendableData() override {
		
		return make_shared<GroupElementPlaintextSendableData>(element->generateSendableData());
	}

	// Nested class that holds the sendable data of the outer class
	class GroupElementPlaintextSendableData : public PlaintextSendableData {
	private:
		shared_ptr<GroupElementSendableData>  groupElementData;
	public:
		GroupElementPlaintextSendableData(shared_ptr<GroupElementSendableData> groupElementData) {
			this->groupElementData = groupElementData;
		};

		shared_ptr<GroupElementSendableData> getGroupElement() { return groupElementData; };

		string toString() override {
			return groupElementData->toString();
		};

		void initFromString(const string & row) override {
			groupElementData->initFromString(row);
		}

	};
};

/**
* This is a marker class. It allows the generation of an AsymmetricCiphertext at an abstract level.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class AsymmetricCiphertextSendableData : public NetworkSerialized {};

/**
* This is a marker class for all cipher-texts.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class AsymmetricCiphertext {
public:

	/**
	* This function is used when an asymmetric ciphertext needs to be sent via a {@link edu.biu.scapi.comm.Channel} or any other means of sending data (including serialization).
	* It retrieves all the data needed to reconstruct this ciphertext at a later time and/or in a different VM.
	* It puts all the data in an instance of the relevant class that implements the AsymmetricCiphertextSendableData interface.
	* @return the AsymmetricCiphertextSendableData object
	*/
	virtual shared_ptr<AsymmetricCiphertextSendableData> generateSendableData() = 0;
	virtual bool operator==(const AsymmetricCiphertext &other) const = 0;
};

/**
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class BigIntegerCiphertext : public AsymmetricCiphertext, public AsymmetricCiphertextSendableData{

private:
	biginteger cipher;

public:
	BigIntegerCiphertext(biginteger cipher) {
		this->cipher = cipher;
	}

	biginteger getCipher() { return cipher;	}

	/**
	* This function is used when an asymmetric ciphertext needs to be sent via a edu.biu.scapi.comm.Channel or any other means of sending data (including serialization).
	* It retrieves all the data needed to reconstruct this ciphertext at a later time and/or in a different VM. It puts all the data in an instance of the relevant class
	* that implements the AsymmetricCiphertextSendableData interface.<p>
	* In order to deserialize this into a BigIntegerCiphertext all you need to do is cast the serialized object with (BigIntegerCiphertext)
	*
	*/
	shared_ptr<AsymmetricCiphertextSendableData> generateSendableData() {
		//Since BigIntegerCiphertext is both an AsymmetricCiphertext and a AsymmetricCiphertextSendableData, on the one hand it has to implement
		//the generateSendableData() function, but on the other hand it is in itself an AsymmetricCiphertextSendableData, so we do not really
		//generate sendable data, but just return this object.
        //In order to avoid double deletion, we tell the pointer to use empty destructor.
		return shared_ptr<AsymmetricCiphertextSendableData>(this, [](void*){});
	}

	bool operator==(const AsymmetricCiphertext &other) const {
		auto temp = dynamic_cast<const BigIntegerCiphertext*>(&other);
		return cipher == temp->cipher;
	}

	string toString() override { return cipher.str();	};

	void initFromString(const string & row) override { cipher = biginteger(row); }
};

/**
* General interface for any symmetric ciphertext.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class SymmetricCiphertext : public NetworkSerialized {
public:
	/**
	* @return the byte array representation of the ciphertext.
	*/
	virtual vector<byte> getBytes() = 0;

	/**
	* @return the length of the byte array representation of the ciphertext.
	*/
	virtual int getLength() = 0;

	template<class Archive>
	void serialize(Archive & ar, const unsigned int version) {}
};

/**
* The decorator pattern has been used to implement different types of symmetric ciphertext.<p>
* This abstract class is the decorator part of the pattern. It allows wrapping the base symmetric ciphertext with extra functionality.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class SymCiphertextDecorator : public SymmetricCiphertext{
	friend class boost::serialization::access;
protected:
	//The symmetric ciphertext we want to decorate.
	shared_ptr<SymmetricCiphertext> cipher;

public:
	SymCiphertextDecorator(){}
	/**
	* This constructor gets the symmetric ciphertext that we need to decorate.
	* @param cipher
	*/
	SymCiphertextDecorator(shared_ptr<SymmetricCiphertext> cipher) { this->cipher = cipher; }

	/**
	*
	* @return the undecorated cipher.
	*/
	shared_ptr<SymmetricCiphertext> getCipher() { return cipher; }

	/*
	* Delegate to underlying (decorated) ciphertext. This behavior can be overridden by inheriting classes.
	*/
	vector<byte> getBytes() override { return cipher->getBytes(); }

	/*
	* Delegate to underlying (decorated) ciphertext. This behavior can be overridden by inheriting classes.
	*/
	int getLength() override { return cipher->getLength();	}

	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		ar & boost::serialization::base_object<SymmetricCiphertext>(*this);
		ar & cipher;
	}
};

/**
* This class represents the most basic symmetric ciphertext.
* It is a data holder for the ciphertext calculated by some symmetric encryption algorithm. <p>
* It only holds the actual "ciphered" bytes and not any additional information like for example in El Gamal encryption.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*/
class ByteArraySymCiphertext : public SymmetricCiphertext {
	friend class boost::serialization::access;
private:
	vector<byte> data;

public:
	ByteArraySymCiphertext(){}
	/**
	* The encrypted bytes need to be passed to construct this holder.
	* @param data
	*/
	ByteArraySymCiphertext(vector<byte> data) { this->data = data; }

	vector<byte> getBytes() override { return data; }

	int getLength() override { return data.size(); }

	string toString() override {
		const byte * uc = &(data[0]);
		return string(reinterpret_cast<char const*>(uc), data.size());
	};

	void initFromString(const string & s) override {
		data.assign(s.begin(), s.end());
	}

	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		ar & boost::serialization::base_object<SymmetricCiphertext>(*this);
		ar & data;
	}
};

/**
* This class is a container for cipher-texts that include actual cipher data and the IV used.
* This is a concrete decorator in the Decorator Pattern used for Symmetric Ciphertext.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class IVCiphertext : public SymCiphertextDecorator {
	friend class boost::serialization::access;
private:
	vector<byte> iv;

public:
	IVCiphertext(){}
	/**
	* Constructs a container for Ciphertexts that need an IV.
	* @param cipher symmetric ciphertext to which we need to add an IV.
	* @param iv the IV we need to add to the ciphertext.
	*/
	IVCiphertext(shared_ptr<SymmetricCiphertext> cipher, vector<byte> iv) : SymCiphertextDecorator(cipher) {
		this->iv = iv;
	}

	/**
	* @return the IV of this ciphertext-with-IV.
	*/
	vector<byte> getIv() { return iv; }

	string toString() override {
		const byte * uc = &(iv[0]);
		return cipher->toString() + ":" + string(reinterpret_cast<char const*>(uc), iv.size());
	};

	void initFromString(const string & s) override {
		auto vec = explode(s, ':');
		assert(vec.size() == 2);
		cipher->initFromString(vec[0]);
		iv.assign(vec[1].begin(), vec[1].end());
	}

	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		//boost::serialization::void_cast_register<SymCiphertextDecorator, IVCiphertext>();
		ar & boost::serialization::base_object<SymCiphertextDecorator>(*this);
		ar & iv;
	}
};

BOOST_SERIALIZATION_ASSUME_ABSTRACT(SymmetricCiphertext)
BOOST_SERIALIZATION_ASSUME_ABSTRACT(SymCiphertextDecorator)