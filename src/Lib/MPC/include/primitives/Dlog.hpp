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
#include "../cryptoInfra/SecurityLevel.hpp"
#include "../infra/MathAlgorithms.hpp"
#include "../../include/infra/ConfigFile.hpp"


/**
 * This exception is thrown in case A given Dlog group cannot be acceptted by the protocol.
 * For example, If a protocol needs a DDH Dlog group and it gets a non - DDH group.
 */
class InvalidDlogGroupException : public logic_error
{
public:
	InvalidDlogGroupException(const string & msg) : logic_error(msg) {};
};

/**
 * This is a marker class. It allows the generation of a GroupElement at an abstract level without knowing the actual type of Dlog Group.
 */
class GroupElementSendableData : public NetworkSerialized {
public:
	virtual ~GroupElementSendableData() = 0; // making this an abstract class		
};

inline GroupElementSendableData::~GroupElementSendableData() {}; // must provide implemeantion to allow destruction of base classes

/**
* This is the main aclass of the Group element hierarchy.
* We can refer to a group element as a general term OR we can relate to the fact that an element of an elliptic curve
* is a point and an element of a Zp group is a number between 0 and p-1.
*/
class GroupElement {

public:
	/**
	* Checks if this element is the identity of the group.
	* @return true if this element is the identity of the group; false otherwise.
	*/
	virtual bool isIdentity() = 0;

	/**
	* This function is used when a group element needs to be sent via a channel or any other means of sending data (including serialization).
	* It retrieves all the data needed to reconstruct this Group Element at a later time and/or in a different VM.
	* It puts all the data in an instance of the relevant class that implements the GroupElementSendableData interface.
	* @return the GroupElementSendableData object
	*/
	virtual shared_ptr<GroupElementSendableData> generateSendableData() = 0;
	virtual bool operator==(const GroupElement &other) const = 0;
	virtual bool operator!=(const GroupElement &other) const = 0;
};

/*
* The GroupParams family holds the necessary parameters for each possible concrete Dlog group. 
* Each DlogGroup has different parameters that constitute this group. GroupParams classes hold those parameters.
*/
class GroupParams
{
protected:
	biginteger q; // The group order

public:
	/*
	* Returns the group order, which is the number of elements in the group
	* @return the order of the group
	*/
	biginteger getQ() { return q; }
	
	// Making this class abstract.
	virtual ~GroupParams() = 0;
};

inline GroupParams::~GroupParams() { };

/**
* This is the abstract class for the discrete logarithm group. 
* Every class in the DlogGroup family derives this class.
* The discrete logarithm problem is as follows: given a generator g of a finite group G and 
* a random element h in G, find the (unique) integer x such that g^x = h.
* In cryptography, we are interested in groups for which the discrete logarithm problem (Dlog for short) is assumed to be hard.
* The two most common classes are the group Zp* for a large p, and some Elliptic curve groups.
*
* Another issue pertaining elliptic curves is the need to find a suitable mapping that will convert an arbitrary message (that is some binary string) to an element of the group and vice-versa.
* Only a subset of the messages can be effectively mapped to a group element in such a way that there is a one-to-one injection that converts the string to a group element and vice-versa.
* On the other hand, any group element can be mapped to some string
* In this case, the operation is not invertible. This functionality is implemented by the functions:
*  - encodeByteArrayToGroupElement
*  - decodeGroupElementToByteArray
*  - mapAnyGroupElementToByteArray
*
*  The first two work as a pair and decodeGroupElementToByteArray is the inverse of encodeByteArrayToGroupElement, whereas the last one works alone and does not have an inverse.
*/
class DlogGroup
{
protected:
	shared_ptr<GroupParams> groupParams;	// group parameters
	shared_ptr<GroupElement> generator;		// generator of the group
	shared_ptr<PrgFromOpenSSLAES> random_element_gen;

	int k; // k is the maximum length of a string to be converted to a Group Element of this group.
		   // If a string exceeds the k length it cannot be converted.

	/*
	* Computes the simultaneousMultiplyExponentiate using a naive algorithm
	*/
	std::shared_ptr<GroupElement> computeNaive(vector<std::shared_ptr<GroupElement>> & groupElements,
		vector<biginteger> & exponentiations);

	/*
	* Compute the simultaneousMultiplyExponentiate by LL algorithm.
	* The code is taken from the pseudo code of LL algorithm in http://dasan.sejong.ac.kr/~chlim/pub/multi_exp.ps.
	*/
	std::shared_ptr<GroupElement> computeLL(vector<std::shared_ptr<GroupElement>> & groupElements,
		vector<biginteger> & exponentiations);

private:
	/**
	* The class GroupElementExponentiations is a nested class of DlogGroupAbs.
	* It performs the actual work of pre-computation of the exponentiations for one base.
	* It is composed of two main elements. The group element for which the optimized computations
	* are built for, called the base and a vector of group elements that are the result of
	* exponentiations of order 1,2,4,8,
	*/
	class GroupElementsExponentiations {
	private:
		vector<shared_ptr<GroupElement>> exponentiations; //vector of group elements that are the result of exponentiations
		shared_ptr<GroupElement> base;  //group element for which the optimized computations are built for
		shared_ptr<DlogGroup> parent;
		
		/**
		* Calculates the necessary additional exponentiations and fills the exponentiations vector with them.
		* @param size - the required exponent
		*/
		void prepareExponentiations(const biginteger & size);

	public:
		/**
		* The constructor creates a map structure in memory.
		* Then calculates the exponentiations of order 1,2,4,8 for the given base and save them in the map.
		*/
		GroupElementsExponentiations(const shared_ptr<DlogGroup> & parent_,	const shared_ptr<GroupElement> & base_);

		/**
		* Checks if the exponentiations had already been calculated for the required size.
		* If so, returns them, else it calls the private function prepareExponentiations with the given size.
		* @param size - the required exponent
		* @return groupElement - the exponentiate result
		*/
		shared_ptr<GroupElement> getExponentiation(const biginteger & size);
	};

	// using pointer as key mean different element ==> different keys even if they are 'equal' in other sense
	unordered_map<shared_ptr<GroupElement>,	shared_ptr<GroupElementsExponentiations >> exponentiationsMap; //map for multExponentiationsWithSameBase calculations

	/*
	* Computes the loop the repeats in the algorithm.
	* for k=0 to h-1
	* 		e=0
	* 		for i=kw to kw+w-1
	*			if the bitIndex bit in ci is set:
	*			calculate e += 2^(i-kw)
	*		result = result *preComp[k][e]
	*
	*/
	shared_ptr<GroupElement> computeLoop(vector<biginteger> & exponentiations, int w, int h,
		vector<vector<shared_ptr<GroupElement>>> & preComp, shared_ptr<GroupElement> & result,
		int bitIndex);

	/*
	* Creates the preComputation table.
	*/
	vector<vector<shared_ptr<GroupElement>>> createLLPreCompTable(
		vector<shared_ptr<GroupElement>> & groupElements, int w, int h);

	/*
	* returns the w value according to the given t
	*/
	int getLLW(int t);

public:
	/**
	* Each concrete derived class returns a string with a meaningful name for this type of Dlog group.
	* For example: "elliptic curve over F2m" or "Zp*"
	* @return the name of the group type
	*/
	virtual string getGroupType() = 0;

	/**
	* The generator g of the group is an element of the group such that, when written multiplicatively, every element of the group is a power of g.
	* @return the generator of this Dlog group
	*/
	shared_ptr<GroupElement> getGenerator() { return generator; }
	
	/**
	* GroupParams is a structure that holds the actual data that makes this group a specific Dlog group.<p>
	* For example, for a Dlog group over Zp* what defines the group is p.
	*
	* @return the GroupParams of that Dlog group
	*/
	shared_ptr<GroupParams> getGroupParams() { return groupParams; }

	/**
	* If this group has been initialized then it returns the group's order. Otherwise throws exception.
	* @return the order of this Dlog group
	*/
	biginteger getOrder() { return groupParams->getQ(); };
	
	/**
	*
	* @return the identity of this Dlog group
	*/
	virtual shared_ptr<GroupElement> getIdentity() = 0;

	/**
	* Checks if the given element is a member of this Dlog group
	* @param element possible group element for which to check that it is a member of this group
	* @return true if the given element is a member of this group; false otherwise.
	* @throws invalid_argument
	*/
	virtual bool isMember(GroupElement* element) = 0;

	/**
	* Checks if the order is a prime number.
	* Primality checking can be an expensive operation and it should be performed only when absolutely necessary.
	* @return true if the order is a prime number. false, otherwise.
	*/
	virtual bool isPrimeOrder() { return isPrime(getOrder()); }
	
	/**
	* Checks if the order of this group is greater than 2^numBits
	* @param numBits
	* @return true if the order is greater than 2^numBits, false - otherwise.
	*/
	bool isOrderGreaterThan(int numBits) { return (getOrder() > boost::multiprecision::pow(biginteger(2), numBits)); }
	
	/**
	* Checks if the element set as the generator is indeed the generator of this group.
	* @return true if the generator is valid; false otherwise.
	*/
	virtual bool isGenerator() = 0;

	/**
	* Checks parameters of this group to see if they conform to the type this group is supposed to be.
	* @return true if valid; false otherwise.
	*/
	virtual bool validateGroup() = 0;

	/**
	* Calculates the inverse of the given GroupElement.
	* @param groupElement to invert
	* @return the inverse element of the given GroupElement
	* @throws invalid_argument
	**/
	virtual shared_ptr<GroupElement> getInverse(GroupElement* groupElement) = 0;

	/**
	* Raises the base GroupElement to the exponent. The result is another GroupElement.
	* @param exponent
	* @param base
	* @return the result of the exponentiation
	* @throws invalid_argument
	*/
	virtual shared_ptr<GroupElement> exponentiate(GroupElement* base, const biginteger & exponent) = 0;

	/**
	* Multiplies two GroupElements
	* @param groupElement1
	* @param groupElement2
	* @return the multiplication result
	* @throws invalid_argument
	*/
	virtual shared_ptr<GroupElement> multiplyGroupElements(GroupElement* groupElement1, 
		GroupElement* groupElement2) = 0;

	/**
	* Creates a random member of this Dlog group
	* @return the random element
	*/
	virtual shared_ptr<GroupElement> createRandomElement();

	/**
	* Creates a random generator of this Dlog group
	* @return the random generator
	*/
	shared_ptr<GroupElement> createRandomGenerator();

	/**
	* This function allows the generation of a group element by a protocol that holds a Dlog Group but does not know if it is a Zp Dlog Group or an Elliptic Curve Dlog Group.
	* It receives the possible values of a group element and whether to check membership of the group element to the group or not.
	* It may be not necessary to check membership if the source of values is a trusted source (it can be the group itself after some calculation). On the other hand,
	* to work with a generated group element that is not really an element in the group is wrong. It is up to the caller of the function to decide if to check membership or not.
	* If bCheckMembership is false always generate the element. Else, generate it only if the values are correct.
	* @param bCheckMembership
	* @param values
	* @return the generated GroupElement
	* @throws IllegalArgumentException
	*/
	virtual shared_ptr<GroupElement> generateElement(bool bCheckMembership, vector<biginteger> & values) = 0;

	/**
	* Reconstructs a GroupElement given the GroupElementSendableData data, which might have been received through a Channel open between the party holding this DlogGroup and
	* some other party.
	* @param bCheckMembership whether to check that the data provided can actually reconstruct an element of this DlogGroup. Since this action is expensive it should be used only if necessary.
	* @param data the GroupElementSendableData from which we wish to "reconstruct" an element of this DlogGroup
	* @return the reconstructed GroupElement
	*/
	virtual shared_ptr<GroupElement> reconstructElement(bool bCheckMembership, GroupElementSendableData* data) = 0;

	/**
	* Computes the product of several exponentiations with distinct bases
	* and distinct exponents.
	* Instead of computing each part separately, an optimization is used to
	* compute it simultaneously.
	* @param groupElements
	* @param exponentiations
	* @return the exponentiation result
	*/
	virtual shared_ptr<GroupElement> simultaneousMultipleExponentiations(
		vector<shared_ptr<GroupElement>> & groupElements, vector<biginteger> & exponentiations) = 0;

	/**
	* Computes the product of several exponentiations of the same base
	* and distinct exponents.
	* An optimization is used to compute it more quickly by keeping in memory
	* the result of h1, h2, h4,h8,... and using it in the calculation.<p>
	* Note that if we want a one-time exponentiation of h it is preferable to use the basic exponentiation function
	* since there is no point to keep anything in memory if we have no intention to use it.
	* @return the exponentiation result
	*/
	virtual shared_ptr<GroupElement> exponentiateWithPreComputedValues(
		const shared_ptr<GroupElement> & base, const biginteger & exponent);

	/**
	* This function cleans up any resources used by exponentiateWithPreComputedValues for the requested base.
	* It is recommended to call it whenever an application does not need to continue calculating exponentiations for this specific base.
	*
	*/
	void endExponentiateWithPreComputedValues(const shared_ptr<GroupElement> & base) {
		exponentiationsMap.erase(base);
	}
	
	/**
	* This function takes any string of length up to k bytes and encodes it to a Group Element.
	* k can be obtained by calling getMaxLengthOfByteArrayForEncoding() and it is calculated upon construction of this group; it depends on the length in bits of p.<p>
	* The encoding-decoding functionality is not a bijection, that is, it is a 1-1 function but is not onto.
	* Therefore, any string of length in bytes up to k can be encoded to a group element but not every group element can be decoded to a binary string in the group of binary strings of length up to 2^k.<p>
	* Thus, the right way to use this functionality is first to encode a byte array and then to decode it, and not the opposite.
	*
	* @param binaryString the byte array to encode
	* @return the encoded group Element <B> or null </B>if element could not be encoded
	*/
	virtual shared_ptr<GroupElement> encodeByteArrayToGroupElement(
		const vector<unsigned char> & binaryString) = 0;

	/**
	* This function decodes a group element to a byte array. This function is guaranteed to work properly ONLY if the group element was obtained as a result of
	* encoding a binary string of length in bytes up to k.<p>
	* This is because the encoding-decoding functionality is not a bijection, that is, it is a 1-1 function but is not onto.
	* Therefore, any string of length in bytes up to k can be encoded to a group element but not any group element can be decoded
	* to a binary sting in the group of binary strings of length up to 2^k.
	*
	* @param groupElement the element to decode
	* @return the decoded byte array
	*/
	virtual const vector<unsigned char> decodeGroupElementToByteArray(GroupElement* groupElement) = 0;


	/**
	* This function returns the value k which is the maximum length of a string to be encoded to a Group Element of this group.
	* Any string of length k has a numeric value that is less than (p-1)/2 - 1.
	* k is the maximum length a binary string is allowed to be in order to encode the said binary string to a group element and vice-versa.
	* If a string exceeds the k length it cannot be encoded.
	* @return k the maximum length of a string to be encoded to a Group Element of this group. k can be zero if there is no maximum.
	*/
	virtual int getMaxLengthOfByteArrayForEncoding() {
		//Return member variable k, which was calculated upon construction of this Dlog group, once the group got the p value. 
		return k;
	};
	
	/**
	* This function maps a group element of this dlog group to a byte array.<p>
	* This function does not have an inverse function, that is, it is not possible to re-construct the original group element from the resulting byte array.
	* @return a byte array representation of the given group element
	*/
	virtual const vector<byte> mapAnyGroupElementToByteArray(GroupElement* groupElement) = 0;
};

/**
* Marker class for Dlog groups that has a prime order sub-group.
*/
class primeOrderSubGroup : public virtual DlogGroup {};


/**********DlogZP hierarchy***********************/

/**
* Marker class. Every class that derives it is signed as Zp*
*/
class DlogZp : public DlogGroup {};

/**
* This class holds the parameters of a Dlog group over Zp*.
*/
class ZpGroupParams : public GroupParams{
private:
	biginteger p; //modulus
	biginteger xG; //generator value

public:
	/**
	* constructor that sets the order, generator and modulus
	* @param q - order of the group
	* @param xG - generator of the group
	* @param p - modulus of the group
	*/
	ZpGroupParams(const biginteger & q_, const biginteger & xG_, const biginteger & p_) {
		q = q_;
		xG = xG_;
		p = p_;
	}

	/**
	* Returns the prime modulus of the group
	*/
	biginteger getP() { return p; }

	/**
	* Returns the generator of the group
	*/
	biginteger getXg() { return xG; }
	
	string toString() { return "ZpGroupParams [p=" +  p.str() + ", g=" +  xG.str() + ", q=" +  q.str() + "]"; }
};

/**
* Marker class. Every class that derives it is signed as Zp* group were p is a safe prime.
*/
class DlogZpSafePrime : public DlogZp {};

/**
* This is a marker class. Every class that implements it is signed as Zp* element.
*/
class ZpElement : public GroupElement {
	/**
	* This function returns the actual "integer" value of this element; which is an element of a given Dlog over Zp*.
	* @return integer value of this Zp element.
	*/
public:
	virtual biginteger getElementValue()=0;
};

/**
* Concrete class for elements of a sub-group of prime order of Zp* where p is a safe prime.
*/
class ZpSafePrimeElement : public ZpElement {
	
protected:
	biginteger element = 0;

	/**
	* This constructor accepts x value and DlogGroup (represented by p).
	* If x is valid, sets it; else, throws exception
	*/
	ZpSafePrimeElement(const biginteger & x, const biginteger & p, bool bCheckMembership);
	
	/**
	* Constructor that gets DlogGroup and chooses random element with order q.
	* The algorithm is:
	* input: modulus p
	* choose a random element between 1 to p-1
	* calculate element^2 mod p
	*/
	ZpSafePrimeElement(const biginteger & p, PrgFromOpenSSLAES* prg);
	
	/*
	* Constructor that simply create element using the given value
	*/
	ZpSafePrimeElement(biginteger elementValue) { element = elementValue; };
public:
	biginteger getElementValue() override { return element; };
	bool isIdentity() override { return element == 1; }
	bool operator==(const GroupElement &other) const override;
	bool operator!=(const GroupElement &other) const override;
	virtual string toString() = 0;
	shared_ptr<GroupElementSendableData> generateSendableData() override;
};

class ZpElementSendableData : public GroupElementSendableData {
protected:
	biginteger x = 0;

public:
	ZpElementSendableData(const biginteger & x_) : GroupElementSendableData() {
		x = x_;
	};

	biginteger getX() { return x; }
	string toString() override { return  x.str(); }
	void initFromString(const string & row) override { x = biginteger(row); }
	
};

/***************Dlog Elliptic Curve hierarchy******************/

/**********************EC Params*******************************/

class ECGroupParams : public GroupParams {
protected:
	biginteger a; // coefficient a of the elliptic curve equation
	biginteger b; // coefficient b of the elliptic curve equation
	biginteger xG; // x coordinate of the generator point
	biginteger yG; // y coordinate of the generator point
	biginteger h; // cofactor of the group
	 
public:
	ECGroupParams(const biginteger & q, const biginteger & a, const biginteger & b, const biginteger & xG, const biginteger & yG, const biginteger & h) {
		this->q = q;
		this->a = a;
		this->b = b;
		this->xG = xG;
		this->yG = yG;
		this->h = h;
	}

	virtual string toString() = 0; //making this class abstrast

	/*
	* Returns coefficient a of the elliptic curves equation
	*/
	biginteger getA() {	return a; }

	/*
	* Returns coefficient b of the elliptic curves equation
	*/
	biginteger getB() {	return b; }

	/*
	* Returns the x coordinate of the generator point
	*/
	biginteger getXg() { return xG; }

	/*
	* Returns the y coordinate of the generator point
	*/
	biginteger getYg() { return yG;	}

	/*
	* Returns the cofactor of the group
	*/
	biginteger getCofactor() { return h; }
};

class ECFpGroupParams : public ECGroupParams {
private: 
	biginteger p; //modulus
public:
	ECFpGroupParams(const biginteger & q, const biginteger & xG, const biginteger & yG, 
		const biginteger & p, const biginteger & a, const biginteger & b, const biginteger & h) : 
		ECGroupParams(q, a, b, xG, yG, h)	{
		this->p = p;
	}

	string toString() override {	
		return "ECFpGroupParams [p=" +  p.str() + ", a=" +  a.str() + ", b=" + b.str() + ", xG="
			+ xG.str() + ", yG=" + yG.str() + ", h=" + h.str() + ", q=" + q.str() + "]";
	}

	biginteger getP() { return p; }

};

class ECF2mGroupParams :public ECGroupParams {
protected:
	int m; //specifying the finite field F2m
public:
	ECF2mGroupParams(const biginteger & q, const biginteger & xG, const biginteger & yG, int m, const biginteger & a,
	        const biginteger & b, const biginteger & h) :
		ECGroupParams(q, a, b, xG, yG, h) {
		this->m = m;
	}

	int getM() { return m; }
	virtual int getK1() = 0;
	virtual string toString() = 0; //making this class abstrast
};

class ECF2mTrinomialBasis : public ECF2mGroupParams {
private:
	int k; //the integer k where x^m + x^k + 1 represents the reduction polynomial f(z)
public:
	/*
	* Constructor that sets the parameters
	* @param q  group order
	* @param xG x coordinate of the generator point
	* @param yG y coordinate of the generator point
	* @param m the exponent m of F2m.
	* @param k the integer k where x^m + x^k + 1
	* represents the reduction polynomial f(z).
	* @param a the a coefficient of the elliptic curve equation
	* @param b the b coefficient of the elliptic curve equation
	* @param h the group cofactor
	*/
	ECF2mTrinomialBasis(const biginteger & q, const biginteger & xG, const biginteger & yG, int m, int k, const biginteger & a, const biginteger & b, const biginteger & h) :
		ECF2mGroupParams(q, xG, yG, m, a, b, h)	{
		this->k = k;
	}

	/*
	* Returns the integer k where x^m + x^k + 1
	* @return k
	*/
	int getK1() override { return k; }

	string toString() override {
		string s = "ECF2mTrinomialBasis [k=" + to_string(k);
		s += ", m=" + to_string(m);
		s+= ", a=" + a.str() + ", b="	+  b.str() + ", xG=" +  xG.str() + ", yG=" +  yG.str() + ", h=" +
		        h.str() + ", q=" +  q.str() + "]";
		return s;
	}
};

class ECF2mPentanomialBasis : public ECF2mGroupParams {
private:
	// x^m + x^k3 + x^k2 + x^k1 + 1 represents the reduction polynomial f(z)
	int k1;
	int k2;
	int k3;
public:
	/*
	* Sets the parameters
	* @param q the group order
	* @param xG x coordinate of the generator point
	* @param yG y coordinate of the generator point
	* @param m  the exponent m of F2m.
	* @param k1 the integer k1 where x^m + x^k3 + x^k2 + x^k1 + 1 represents the reduction polynomial f(z).
	* @param k2 the integer k2 where x^m + x^k3 + x^k2 + x^k1 + 1 represents the reduction polynomial f(z).
	* @param k3 the integer k3 where x^m + x^k3 + x^k2 + x^k1 + 1 represents the reduction polynomial f(z).
	* @param a the a coefficient of the elliptic curve equation
	* @param b the b coefficient of the elliptic curve equation
	* @param h the group cofactor
	*/
	ECF2mPentanomialBasis(const biginteger & q, const biginteger & xG, const biginteger & yG, int m, int k1, int k2, int k3, const biginteger & a, const biginteger & b, const biginteger & h)
		: ECF2mGroupParams(q, xG, yG, m, a, b, h) {
		this->k1 = k1;
		this->k2 = k2;
		this->k3 = k3;
	}

	/*
	* Returns the integer k1 where x^m + x^k3 + x^k2 + x^k1 + 1represents the reduction polynomial f(z).
	*/
	int getK1() override { return k1; }

	/*
	* Returns the integer k2 where x^m + x^k3 + x^k2 + x^k1 + 1represents the reduction polynomial f(z).
	*/
	int getK2() { return k2; }

	/*
	* Returns the integer k3 where x^m + x^k3 + x^k2 + x^k1 + 1represents the reduction polynomial f(z).
	*/
	int getK3() { return k3; }

	string toString() override; 
};

class ECF2mKoblitz : public ECF2mGroupParams {
private:
	biginteger n; 	//order of the main subgroup
	shared_ptr<ECF2mGroupParams> curve; //underlying curve
public:
	
	/*
	* Constructor that sets the underlying curve and the additional parameters
	* @param curve the underlying curve
	* @param n order of the sub group
	* @param h the cofactor
	*/
	ECF2mKoblitz(const shared_ptr<ECF2mGroupParams> & curve, const biginteger &  n, const biginteger & h) : ECF2mGroupParams(curve->getQ(), curve->getXg(), curve->getYg(), curve->getM(), curve->getA(), curve->getB(), curve->getCofactor()) {
		this->curve = curve;
		this->n = n;
		this->h = h;
	}

	/*
	* Returns the exponent of the underlying curve
	* @return m
	*/
	int getM() { return curve->getM(); }

	/*
	* Returns the integer k1 of the underlying curve where x^m + x^k3 + x^k2 + x^k1 + 1
	* represents the reduction polynomial f(z).
	*/
	int getK1() override { return curve->getK1(); }

	/**
	* Returns the integer <code>k2</code> of the underlying curve where x^m + x^k3 + x^k2 + x^k1 + 1
	* represents the reduction polynomial f(z).
	*/
	int getK2(); 

	/**
	* Returns the integer <code>k3</code> where x^m + x^k3 + x^k2 + x^k1 + 1
	* represents the reduction polynomial f(z).
	*/
	int getK3();

	/**
	* Returns the subgroup order of this group
	*/
	biginteger getSubGroupOrder() {	return n; }

	/**
	* Returns the underlying curve
	*/
	shared_ptr<ECF2mGroupParams> getCurve() { return curve; }

	string toString() override;
};

class ECElement : public GroupElement {
public:
	/*
	* This function returns the x coordinate of the (x,y) point which is an element of a given elliptic curve.
	* In case of infinity point, returns null.
	* @return x coordinate of (x,y) point
	*/
	virtual biginteger getX() = 0;

	/*
	* This function returns the y coordinate of the (x,y) point which is an element of a given elliptic curve.
	* In case of infinity point, returns null.
	* @return y coordinate of (x,y) point
	*/
	virtual biginteger getY() = 0;

	/**
	* Elliptic curve has a unique point called infinity.
	* In order to know if this object is an infinity point, this function should be called.
	* @return true if this point is the infinity, false, otherwise.
	*/
	virtual bool isInfinity() = 0;

	bool isIdentity() override { return isInfinity(); }
	
	bool operator==(const GroupElement &other) const override;
	bool operator!=(const GroupElement &other) const override;

	shared_ptr<GroupElementSendableData> generateSendableData() override;

};

class ECElementSendableData : public GroupElementSendableData {
private:
	biginteger x;
	biginteger y;
public:
	ECElementSendableData(const biginteger & x, const biginteger & y) {
		this->x = x;
		this->y = y;
	}

	biginteger getX() { return x; }
	biginteger getY() { return y; }
	string toString() override;

	void initFromString(const string & raw) override;
};

class ECF2mPoint : public ECElement {};

class ECFpPoint : ECElement {};


class DlogEllipticCurve : public DlogGroup {

protected:
	string curveName;
	string fileName;
	shared_ptr<ConfigFile> ecConfig; // properties object to hold the given config file's parameters
#ifdef _WIN32
	const string NISTEC_PROPERTIES_FILE = "../../../../include/configFiles/NISTEC.txt";
#else
	const string NISTEC_PROPERTIES_FILE = "../include/configFiles/NISTEC.txt";
#endif
	
	virtual void init(string fileName, string curveName, const shared_ptr<PrgFromOpenSSLAES> & random);

public:
	DlogEllipticCurve(string fileName, string curveName, const shared_ptr<PrgFromOpenSSLAES> & random) { init(fileName, curveName, random); }

	DlogEllipticCurve(string curveName, const shared_ptr<PrgFromOpenSSLAES> & random) { init(NISTEC_PROPERTIES_FILE, curveName, random); }
	
	virtual shared_ptr<ECElement> getInfinity() = 0;

	string getCurveName() { return curveName; }

	string getFileName() { return fileName; }

	/*
	* Checks parameters of this group to see if they conform to the type this group is supposed to be.
	* Parameters are uploaded from a configuration file upon construction of concrete instance of an Elliptic Curve Dlog group.
	* By default, SCAPI uploads a file with NIST recommended curves. In this case we assume the parameters are always correct.
	* It is also possible to upload a user-defined configuration file (with format specified in the "Elliptic Curves Parameters File Format" section of the FirstLevelSDK_SDD.docx file). In this case,
	* it is the user's responsibility to check the validity of the parameters.
	* In both ways, the parameters we set should be correct. Therefore, currently the function validateGroup does not perform any validity check and always returns true.
	* In the future we may add the validity checks.
	* @return true.
	*/
	bool validateGroup() override { return true; }

	/*
	* Checks if the element set as the generator is indeed the generator of this group.
	* The generator is set upon construction of this group. 
	* For Elliptic curves there are two ways to set the generator. One way is to load it from NIST file, so the generator is correct.
	* The second way is to get the generator values from the user in the init function. In that way, it is the user's responsibility to check the validity of the parameters.
	* In both ways, the generator we set must be correct. However, currently the function isGenerator does not operate the validity check and always returns true.
	* Maybe in the future we will add the validity checks.
	* @return true is the generator is valid; false otherwise.
	*
	*/
	bool isGenerator() override { return true; }

	/*
	* For Elliptic Curves, the identity is equivalent to the infinity.
	* @return the identity of this Dlog group
	*/
	shared_ptr<GroupElement> getIdentity() override { return getInfinity();	}
};

class DlogECFp : public DlogEllipticCurve {};

class DlogECF2m : public DlogEllipticCurve {};