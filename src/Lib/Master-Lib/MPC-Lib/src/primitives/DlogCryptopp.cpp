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


#ifdef ABARAK_NO_DEF_BUILD_ERR
#include "../../include/primitives/DlogCryptopp.hpp"


biginteger cryptoppint_to_biginteger(CryptoPP::Integer cint)
{
	string s = boost::lexical_cast<std::string>(cint);
	s = s.substr(0, s.size() - 1); // from some reason casting cryptoPP to string ends with '.'
	return biginteger(s);
}

CryptoPP::Integer biginteger_to_cryptoppint(biginteger bi)
{
	return CryptoPP::Integer(bi.str().c_str());
}


/*************************************************/
/**** CryptoPpDlogZpSafePrime ***/
/*************************************************/

CryptoPpDlogZpSafePrime::CryptoPpDlogZpSafePrime(ZpGroupParams * groupParams, mt19937 prg)
{
	mt19937 prime_gen = get_seeded_random(); // prg for prime checking
	this->random_element_gen = prg;
	biginteger p = groupParams->getP();
	biginteger q = groupParams->getQ();
	biginteger g = groupParams->getXg();

	// if p is not 2q+1 throw exception
	if (!(q * 2 + 1 == p)) {
		throw invalid_argument("p must be equal to 2q+1");
	}
	// if p is not a prime throw exception
	if (!isPrime(p)) {
		throw invalid_argument("p must be a prime");
	}
	// if q is not a prime throw exception
	if (!isPrime(q)) {
		throw invalid_argument("q must be a prime");
	}
	// set the inner parameters
	this->groupParams = groupParams;

	// create CryptoPP Dlog group with p, ,q , g.
	// the validity of g will be checked after the creation of the group because the check need the pointer to the group
	pointerToGroup = new CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime();
	pointerToGroup->Initialize(biginteger_to_cryptoppint(p), biginteger_to_cryptoppint(q), biginteger_to_cryptoppint(g));

	// if the generator is not valid, delete the allocated memory and throw exception 
	if (!pointerToGroup->ValidateElement(3, biginteger_to_cryptoppint(g), 0)){
		delete pointerToGroup;
		throw invalid_argument("generator value is not valid. q=" + (string)q + " g=" + (string) g);
	}
	// create the GroupElement - generator
	generator = new ZpSafePrimeElementCryptoPp(g, p, false);

	// now that we have p, we can calculate k which is the maximum length of a string to be converted to a Group Element of this group.
	k = calcK(p);
}

CryptoPpDlogZpSafePrime::CryptoPpDlogZpSafePrime(int numBits, mt19937 prg) {

	this->random_element_gen = prg;

	// create random Zp dlog group and initialise it with the size and generator
	CryptoPP::AutoSeededRandomPool rng; // Random Number Generator
	pointerToGroup = new CryptoPP::DL_GroupParameters_GFP_DefaultSafePrime();
	pointerToGroup->Initialize(rng, numBits);

	// get the generator value
	CryptoPP::Integer gen = pointerToGroup->GetSubgroupGenerator();
	//create the GroupElement - generator with the pointer that returned from the native function
	generator = new ZpSafePrimeElementCryptoPp(cryptoppint_to_biginteger(gen));

	biginteger p = cryptoppint_to_biginteger(pointerToGroup->GetModulus());
	biginteger q = cryptoppint_to_biginteger(pointerToGroup->GetSubgroupOrder());
	biginteger xG = ((ZpElement *)generator)->getElementValue();

	groupParams = new ZpGroupParams(q, xG, p);

	//Now that we have p, we can calculate k which is the maximum length in bytes of a string to be converted to a Group Element of this group. 
	k = calcK(p);
}

int CryptoPpDlogZpSafePrime::calcK(biginteger p) {
	int bitsInp = find_log2_floor(p) + 1;
	//any string of length k has a numeric value that is less than (p-1)/2 - 1
	int k = (bitsInp - 3) / 8;
	//The actual k that we allow is one byte less. This will give us an extra byte to pad the binary string passed to encode to a group element with a 01 byte
	//and at decoding we will remove that extra byte. This way, even if the original string translates to a negative BigInteger the encode and decode functions
	//always work with positive numbers. The encoding will be responsible for padding and the decoding will be responsible for removing the pad.
	k--;
	//For technical reasons of how we chose to do the padding for encoding and decoding (the least significant byte of the encoded string contains the size of the 
	//the original binary string sent for encoding, which is used to remove the padding when decoding) k has to be <= 255 bytes so that the size can be encoded in the padding.
	if (k > 255) {
		k = 255;
	}
	return k;
}

bool CryptoPpDlogZpSafePrime::isGenerator()
{
	//get the group generator
	CryptoPP::Integer g = pointerToGroup->GetSubgroupGenerator();
	/* call to a crypto++ function that checks the generator validity.
	* 3 is the checking level (full check), g is the generator and 0 is instead of DL_FixedBasedPrecomputation object
	*/
	return pointerToGroup->ValidateElement(3, g, 0);
}

bool CryptoPpDlogZpSafePrime::isMember(GroupElement * element) {

	ZpSafePrimeElementCryptoPp * zp_element = dynamic_cast<ZpSafePrimeElementCryptoPp *>(element);
	// check if element is ZpElementCryptoPp
	if (!zp_element) {
		throw invalid_argument("type doesn't match the group type");
	}

	/* if the element is the identity than it is valid.
	* The function validateElement of crypto++ return false if the element is 1 so we checked it outside.
	*/
	if (zp_element->isIdentity())
		return true;

	/* call to a crypto++ function that checks the element validity.
	* 3 is the checking level (full check), e is the element and 0 is instead of DL_FixedBasedPrecomputation object
	*/
	return pointerToGroup->ValidateElement(3, biginteger_to_cryptoppint(zp_element->getElementValue()), 0);
}

bool CryptoPpDlogZpSafePrime::validateGroup()
{
	CryptoPP::AutoSeededRandomPool rng;
	/* call to crypto++ function validate that checks if the group is valid.
	* it checks the validity of p, q, and the generator.
	* 3 is the checking level - full validate.
	*/
	return pointerToGroup->Validate(rng, 3);
}

GroupElement * CryptoPpDlogZpSafePrime::getInverse(GroupElement * groupElement)
{
	ZpSafePrimeElementCryptoPp * zp_element = dynamic_cast<ZpSafePrimeElementCryptoPp *>(groupElement);
	if(! zp_element)
		throw invalid_argument("element type doesn't match the group type");

	CryptoPP::Integer mod = pointerToGroup->GetModulus(); //get the field modulus
	CryptoPP::ModularArithmetic ma(mod); //create ModularArithmetic object with the modulus
    // get the inverse 
	CryptoPP::Integer result = ma.MultiplicativeInverse(biginteger_to_cryptoppint(zp_element->getElementValue()));
	ZpSafePrimeElementCryptoPp * inverseElement = new ZpSafePrimeElementCryptoPp(cryptoppint_to_biginteger(result));
	return inverseElement;
}

GroupElement * CryptoPpDlogZpSafePrime::exponentiate(GroupElement * base, biginteger exponent){
	ZpSafePrimeElementCryptoPp * zp_base = dynamic_cast<ZpSafePrimeElementCryptoPp *>(base);
	if (!zp_base)
		throw invalid_argument("element type doesn't match the group type");
	
	//exponentiate the element
	CryptoPP::Integer result = pointerToGroup->ExponentiateElement(biginteger_to_cryptoppint(zp_base->getElementValue()), biginteger_to_cryptoppint(exponent));
	//build a ZpElementCryptoPp element from the result value
	ZpSafePrimeElementCryptoPp * exponentiateElement = new ZpSafePrimeElementCryptoPp(cryptoppint_to_biginteger(result));
	return exponentiateElement;
}

GroupElement * CryptoPpDlogZpSafePrime::multiplyGroupElements(GroupElement * groupElement1,	GroupElement * groupElement2){
	ZpSafePrimeElementCryptoPp * zp1 = dynamic_cast<ZpSafePrimeElementCryptoPp *>(groupElement1);
	ZpSafePrimeElementCryptoPp * zp2 = dynamic_cast<ZpSafePrimeElementCryptoPp *>(groupElement2);
	if (!zp1 || !zp2)
		throw invalid_argument("element type doesn't match the group type");
		
	//multiply the element
	CryptoPP::Integer result = pointerToGroup->MultiplyElements(biginteger_to_cryptoppint(zp1->getElementValue()), biginteger_to_cryptoppint(zp2->getElementValue()));
	//build a ZpElementCryptoPp element from the result value
	ZpSafePrimeElementCryptoPp * mulElement = new ZpSafePrimeElementCryptoPp(cryptoppint_to_biginteger(result));
	return mulElement;
}

GroupElement * CryptoPpDlogZpSafePrime::simultaneousMultipleExponentiations(vector<GroupElement *> groupElements, vector<biginteger> exponentiations){

	for (int i = 0; i < groupElements.size(); i++) {
		ZpSafePrimeElementCryptoPp * zp_element = dynamic_cast<ZpSafePrimeElementCryptoPp *>(groupElements[i]);
		if (!zp_element) {
			throw invalid_argument("groupElement doesn't match the DlogGroup");
		}
	}

	//currently, in cryptoPpDlogZpSafePrime the native algorithm is faster than the optimized one due to many calls to the JNI.
	//Thus, we operate the native algorithm. In the future we may change this.
	// TODO - THIS IS NOT TRUE ANYMORE. NEED TO FIX THIS.
	return computeNaive(groupElements, exponentiations);
}

GroupElement * CryptoPpDlogZpSafePrime::generateElement(bool bCheckMembership, vector<biginteger> values)
{
	if (values.size() != 1) {
		throw new invalid_argument("To generate an ZpElement you should pass the x value of the point");
	}
	return new ZpSafePrimeElementCryptoPp(values[0], ((ZpGroupParams *)groupParams)->getP(), bCheckMembership);
}

CryptoPpDlogZpSafePrime::~CryptoPpDlogZpSafePrime()
{
	// the dynamic allocation of the Integer.
	delete pointerToGroup;
	// super.finalize(); - no need. happens automatically
}

 GroupElement * CryptoPpDlogZpSafePrime::encodeByteArrayToGroupElement(const vector<unsigned char> & binaryString) {
	//Any string of length up to k has numeric value that is less than (p-1)/2 - 1.
	//If longer than k then throw exception.
	 int bs_size = binaryString.size();
	if (bs_size > k) {
		throw length_error("The binary array to encode is too long.");
	}

	//Pad the binaryString with a x01 byte in the most significant byte to ensure that the 
	//encoding and decoding always work with positive numbers.
	list<unsigned char> newString(binaryString.begin(), binaryString.end());
	newString.push_front(1);

	byte *bstr = new byte[bs_size + 1];
	for (auto it = newString.begin(); it != newString.end(); ++it) {
		int index = std::distance(newString.begin(), it);
		bstr[index] = *it;
	}
	biginteger s = cryptoppint_to_biginteger(CryptoPP::Integer(bstr, bs_size + 1));

	//Denote the string of length k by s.
	//Set the group element to be y=(s+1)^2 (this ensures that the result is not 0 and is a square)
	biginteger y = boost::multiprecision::powm((s + 1), 2, ((ZpGroupParams *)groupParams)->getP());

	//There is no need to check membership since the "element" was generated so that it is always an element.
	ZpSafePrimeElementCryptoPp * element = new ZpSafePrimeElementCryptoPp(y, ((ZpGroupParams * )groupParams)->getP(), false);
	delete(bstr);
	return element;
}

 const vector<unsigned char> CryptoPpDlogZpSafePrime::decodeGroupElementToByteArray(GroupElement * groupElement) {
	 ZpSafePrimeElementCryptoPp * zp_element = dynamic_cast<ZpSafePrimeElementCryptoPp *>(groupElement);
	 if (!(zp_element))
		 throw invalid_argument("element type doesn't match the group type");

	 //Given a group element y, find the two inverses z,-z. Take z to be the value between 1 and (p-1)/2. Return s=z-1
	 biginteger y = zp_element->getElementValue();
	 biginteger p = ((ZpGroupParams * ) groupParams)->getP();

	 MathAlgorithms::SquareRootResults roots = MathAlgorithms::sqrtModP_3_4(y, p);

	 biginteger goodRoot;
	 biginteger halfP = (p - 1) / 2;
	 if (roots.getRoot1()>1 && roots.getRoot1() < halfP)
		 goodRoot = roots.getRoot1();
	 else
		 goodRoot = roots.getRoot2();
	 goodRoot -= 1;

	 CryptoPP::Integer cpi = biginteger_to_cryptoppint(goodRoot);
	 int len = ceil((cpi.BitCount() + 1) / 8.0); //ceil(find_log2_floor(goodRoot) / 8.0);
	 byte * output = new byte[len];
	 cpi.Encode(output, len);
	 vector<byte> res;
	 
	 // Remove the padding byte at the most significant position (that was added while encoding)
	 for (int i = 1; i < len; ++i)
		 res.push_back(output[i]);
	 return res;
 }

 const vector<unsigned char> CryptoPpDlogZpSafePrime::mapAnyGroupElementToByteArray(GroupElement * groupElement) {
	 ZpSafePrimeElementCryptoPp * zp_element = dynamic_cast<ZpSafePrimeElementCryptoPp *>(groupElement);
	 if (!(zp_element))
		 throw invalid_argument("element type doesn't match the group type");
	 string res = string(zp_element->getElementValue());
	 return vector<unsigned char>(res.begin(), res.end());
 }

 GroupElement * CryptoPpDlogZpSafePrime::reconstructElement(bool bCheckMembership, GroupElementSendableData * data) {
	 ZpElementSendableData * zp_data = dynamic_cast<ZpElementSendableData *>(data);
	 if (!(zp_data))
		 throw invalid_argument("data type doesn't match the group type");
	 return generateElement(bCheckMembership, vector<biginteger>({ zp_data->getX() }));
 }
#endif
