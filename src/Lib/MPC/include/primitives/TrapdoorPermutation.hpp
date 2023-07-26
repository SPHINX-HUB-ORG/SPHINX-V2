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

#include "../cryptoInfra/Key.hpp"

/**
* Enum that represent the possible validity values of trapdoor element.
* There are three possible validity values:
* VALID (it is an element);
* NOT_VALID (it is not an element);
* DONT_KNOW (there is not enough information to check if it is an element or not)
*/
enum  TPElValidity { VALID, NOT_VALID, DONT_KNOW};

/**
* Abstract class for trapdoor permutation elements. Every concrete element class should derive this class.
 * In order to send this object over a channel, use the getElement() function to get the biginteger value of the element and send it directly.
 * In the other side, use the TrapdoorPermutation::generateTPElement(biginteger x) to create the TPElement object.
*/
class TPElement {
public:
	/**
	* Returns the trapdoor element value as biginteger.
	*/
	virtual biginteger getElement() = 0;
};

class RSAModulus {
public:
	biginteger p;
	biginteger q;
	biginteger n;
	RSAModulus(const biginteger & p,const  biginteger & q, const biginteger & n) {
		this->p = p;
		this->q = q;
		this->n = n;
	};

	/**
	* This function generates an RSA modulus N with "length" bits of length, such that N = p*q, and p and q
	* @param length the length in bits of the RSA modulus
	* @param certainty the certainty required regarding the primeness of p and q
	* @param random a source of randomness
	* @return an RSAModulus structure that holds N, p and q.
	*/
	RSAModulus(size_t length, int certainty, PrgFromOpenSSLAES* random);
};

/**
* General interface for Rabin Keys.
*/
class RabinKey : Key {
public:
	/**
	* @return biginteger - the modulus
	*/
	virtual biginteger getModulus()=0;
};

/**
* Concrete class of RabinKey.
*/
class ScRabinKey : public RabinKey {
protected:
	biginteger modulus = NULL;
public:
	/**
	* @return biginteger - the modulus
	*/
	biginteger getModulus() override { return modulus; };
	virtual ~ScRabinKey() = 0; // enforcing abstract class
};

/**
* Concrete class for RabinParameterSpec.
*/
class RabinKeyGenParameterSpec : AlgorithmParameterSpec {
public:
	int keySize;
	RabinKeyGenParameterSpec(int keySize) {
		if (keySize<16)
			throw invalid_argument("Rabin Key size should be greater than 15");
		this->keySize = keySize;
	};
	int getKeySize() { return keySize; };
};

/**
* Abstract class for Rabin private key.
*/
class RabinPrivateKey : public RabinKey, public PrivateKey {
public:
	/**
	* Returns prime1 (p), such that p*q=n.
	*/
	virtual biginteger getPrime1()=0;
	
	/**
	* Returns prime2 (q), such that p*q=n.
	*/
	virtual biginteger getPrime2()=0;
	/**
	* Returns the inverse of prime1 mod prime2 (u).
	*/
	virtual biginteger getInversePModQ()=0;
};

/**
* Abstract class for Rabin public key.
*/
class RabinPublicKey  : public RabinKey, public PublicKey {
public:
	/**
	* @return biginteger - QuadraticResidueModPrime1 (r)
	*/
	virtual biginteger getQuadraticResidueModPrime1()=0;
	/**
	* @return biginteger - QuadraticResidueModPrime2 (s)
	*/
	virtual biginteger getQuadraticResidueModPrime2()=0;
};

/**
* Concrete class of RabinPrivateKey.
*/
class ScRabinPrivateKey : public ScRabinKey, public RabinPrivateKey {
private:
	biginteger prime1 = NULL; 		//p, such that p*q=n
	biginteger prime2 = NULL; 		//q, such that p*q=n
	biginteger inversePModQ = NULL; //u

public:
	/**
	* Constructor that accepts the private key parameters and sets them.
	* @param mod modulus
	* @param p - prime1
	* @param q - prime2
	* @param u - inverse of prime1 mod prime2
	*/
	ScRabinPrivateKey(const biginteger & mod, const biginteger & p, const biginteger & q, const biginteger & u) {
		modulus = mod;
		prime1 = p;
		prime2 = q;
		inversePModQ = u;
	}
	string getAlgorithm() override { return "Rabin"; };
	vector<byte> getEncoded() override { return vector<byte>(0); };
	biginteger getPrime1() override { return prime1; };
	biginteger getPrime2() override { return prime2; };
	biginteger getInversePModQ() override { return inversePModQ; };
};

class ScRabinPrivateKeySpec : public KeySpec {
private:
	biginteger modulus = NULL;		//modulus
	biginteger prime1 = NULL; 		//p, such that p*q=n
	biginteger prime2 = NULL; 		//q, such that p*q=n
	biginteger inversePModQ = NULL; //u

public:
	/**
	* Constructor that accepts the private key parameters and sets them.
	* @param mod modulus
	* @param p - prime1
	* @param q - prime2
	* @param u - inverse of prime1 mod prime2
	*/
	ScRabinPrivateKeySpec(const biginteger & mod, const biginteger & p, const biginteger & q, const biginteger & u) {
		modulus = mod;
		prime1 = p;
		prime2 = q;
		inversePModQ = u;
	};
	/**
	* @return biginteger - the modulus
	*/
	biginteger getModulus() { return modulus; };
	biginteger getPrime1() { return prime1; };
	biginteger getPrime2() { return prime2; };
	biginteger getInversePModQ() { return inversePModQ; };
};

/**
* Concrete class of RabinPublicKey
*/
class ScRabinPublicKey : public ScRabinKey, public RabinPublicKey {
private:
	biginteger quadraticResidueModPrime1 = NULL; //r
	biginteger quadraticResidueModPrime2 = NULL; //s

	/**
	* Constructor that accepts the public key parameters and sets them.
	* @param mod modulus
	* @param r - quadratic residue mod prime1
	* @param s - quadratic residue mod prime2
	*/
	ScRabinPublicKey(const biginteger & mod, const biginteger & r, const biginteger & s) {
		modulus = mod;
		quadraticResidueModPrime1 = r;
		quadraticResidueModPrime2 = s;
	};

	string getAlgorithm() override { return "Rabin"; };
	vector<byte> getEncoded() override { return vector<byte>(); };
	biginteger getQuadraticResidueModPrime1() override { return quadraticResidueModPrime1; };
	biginteger getQuadraticResidueModPrime2() override { return quadraticResidueModPrime2; };
};

class ScRabinPublicKeySpec : public KeySpec {
private:
	biginteger modulus = NULL;
	biginteger quadraticResidueModPrime1 = NULL; //r
	biginteger quadraticResidueModPrime2 = NULL; //s

public:
	/**
	* Constructor that accepts the public key parameters and sets them.
	* @param mod modulus
	* @param r - quadratic residue mod prime1
	* @param s - quadratic residue mod prime2
	*/
	ScRabinPublicKeySpec(const biginteger & mod, const biginteger & r, const biginteger & s) {
		modulus = mod;
		quadraticResidueModPrime1 = r;
		quadraticResidueModPrime2 = s;
	}
	biginteger getModulus() { return modulus; };
	biginteger getQuadraticResidueModPrime1() { return quadraticResidueModPrime1; };
	biginteger getQuadraticResidueModPrime2() { return quadraticResidueModPrime2; };
};

/**
* Concrete class of TPElement for RSA element.
*/
class RSAElement : public TPElement {
private:
	biginteger element; // the element value

public:
	/**
	* Constructor that chooses a random element according to the given modulus.
	* @param modN the modulus
	*/
	RSAElement(const biginteger & modN, const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg());
	
	/**
	* Constructor that gets a modulus and a value. If the value is a valid RSA element according to the modulus, sets it to be the element.
	* @param modN - the modulus
	* @param x - the element value
	*/
	RSAElement(const biginteger & modN, const biginteger & x, bool check);
	
	/**
	* Returns the RSA element.
	* @return the element
	*/
	biginteger getElement() { return element; };

};

/**
* This class is the abstract class of trapdoor permutation. Every class in this family should derive this class.
* A trapdoor permutation is a bijection (1-1 and onto function) that is easy to compute for everyone,
* yet is hard to invert unless given special additional information, called the "trapdoor".
* The public key is essentially the function description and the private key is the trapdoor.
*/
class TrapdoorPermutation {
protected:
    shared_ptr<PrivateKey> privKey = nullptr;        //private key
    shared_ptr<PublicKey> pubKey = nullptr;          //public key
    biginteger modulus = NULL;		//the modulus of the permutation. It must be such that modulus = p*q and p = q = 3 mod 4
    bool _isKeySet = false;		    // indicates if this object is initialized or not. Set to false until init is called

public:
	/**
	* Sets this trapdoor permutation with public key and private key.
	*/
	virtual void setKey(const shared_ptr<PublicKey> & publicKey, const shared_ptr<PrivateKey> & privateKey = nullptr){
        privKey = privateKey;
        pubKey = publicKey;
        _isKeySet = true;
    }
	
	/**
	* Checks if this trapdoor permutation object has been previously initialized.
	* To initialize the object the setKey function has to be called with corresponding parameters after construction.
	*
	* @return true if the object was initialized; false otherwise.
	*/
	virtual bool isKeySet() { return _isKeySet; }
	
	/**
	* @return the public key
	*/
	virtual shared_ptr<PublicKey> getPubKey(){
        if (!isKeySet())
            throw IllegalStateException("public key isn't set");
        return pubKey;
    }
	
	/**
	* @return the algorithm name. for example - RSA, Rabin.
	*/
	virtual string getAlgorithmName()=0;
	
	/**
	* Generates public and private keys for this trapdoor permutation.
	* @return KeyPair holding the public and private keys
	* @throws InvalidParameterSpecException
	*/
	virtual KeyPair generateKey(int keySize)=0;
	
	/**
	* Computes the operation of this trapdoor permutation on the given TPElement.
	* @param tpEl - the input for the computation
	* @return - the result TPElement from the computation
	* @throws invalid_argument if the given element is invalid for this permutation
	*/
	virtual  shared_ptr<TPElement> compute(TPElement * tpEl)=0;
	/**
	* Inverts the operation of this trapdoor permutation on the given TPElement.
	* @param tpEl - the input to invert
	* @return - the result TPElement from the invert operation
	* @throws InvalidKeyException if there is no private key
	* @throws invalid_argument if the given element is invalid for this permutation
	*/
	virtual shared_ptr<TPElement> invert(TPElement * tpEl) = 0;
	
	/**
	* Computes the hard core predicate of the given tpElement. 
	* A hard-core predicate of a one-way function f is a predicate b (i.e., a function whose output is a single bit)
	* which is easy to compute given x but is hard to compute given f(x).
	* In formal terms, there is no probabilistic polynomial time algorithm that computes b(x) from f(x)
	* with probability significantly greater than one half over random choice of x.
	* @param tpEl the input to the hard core predicate
	* @return byte the hard core predicate. In java, the smallest types are boolean and byte.
	* We chose to return a byte since many times we need to concatenate the result of various predicates
	* and it will be easier with a byte than with a boolean.
	*/
	virtual byte hardCorePredicate(TPElement* tpEl);
	
	/**
	* Computes the hard core function of the given tpElement.
	* A hard-core function of a one-way function f is a function g
	* which is easy to compute given x but is hard to compute given f(x).
	* In formal terms, there is no probabilistic polynomial time algorithm that computes g(x) from f(x)
	* with probability significantly greater than one half over random choice of x.
	* @param tpEl the input to the hard core function
	* @return byte* the result of the hard core function. The byte array is allocated inside the method
	*/
	virtual vector<byte> hardCoreFunction(TPElement* tpEl);
	
	/**
	* Checks if the given element is valid for this trapdoor permutation
	* @param tpEl - the element to check
	* @return TPElValidity - enum number that indicate the validation of the element.
	* There are three possible validity values:
	* VALID (it is an element)
	* NOT_VALID (it is not an element)
	* DONT_KNOW (there is not enough information to check if it is an element or not)
	* @throws invalid_argument if the given element is invalid for this permutation
	*/
	virtual TPElValidity isElement(TPElement* tpEl) = 0;
	
	/**
	* creates a random TPElement that is valid for this trapdoor permutation
	* @return TPElement - the created random element
	*/
	virtual shared_ptr<TPElement> generateRandomTPElement() = 0;
	
	/**
	* Creates a TPElement from a specific value x. It checks that the x value is valid for this trapdoor permutation.
	* @return TPElement - If the x value is valid for this permutation return the created random element
	* @throws invalid_argument if the given value x is invalid for this permutation
	*/
	virtual shared_ptr<TPElement> generateTPElement(const biginteger & x) = 0;
	
	/**
	* Creates a TPElement from a specific value x. This function does not guarantee that the the returned "TPElement" is valid.<p>
	* It is the caller's responsibility to pass a legal x value.
	* @return TPElement - Set the x value and return the created random element
	*/
	virtual shared_ptr<TPElement> generateUncheckedTPElement(const biginteger & x) = 0;

	~TrapdoorPermutation() {};
};

/**
* Marker class. Each RSA concrete class should derive this class.
*/
class RSAPermutation : public virtual TrapdoorPermutation {
public:
	/**
	* RSA permutation is a trapdoor permutations written as exponentiation modulo a composite number N called the modulus.
	* This function returns this modulus.
	* @return the modulus of the permutation.
	*/
	virtual biginteger getModulus()=0;
};

/**
* Marker class. Each Rabin concrete class should derive this class.
*/
class RabinPermutation : public TrapdoorPermutation {
public:
	/**
	* Rabin permutation is a trapdoor permutations written as exponentiation modulo a composite number N called the modulus.
	* This function returns this modulus.
	* @return the modulus of the permutation.
	*/
	virtual biginteger getModulus()=0;
};






