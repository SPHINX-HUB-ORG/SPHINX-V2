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


#include "../../include/primitives/Dlog.hpp"

/*************************************************/
/*ZpSafePrimeElement*/
/*************************************************/
ZpSafePrimeElement::ZpSafePrimeElement(const biginteger & x, const biginteger & p, bool bCheckMembership) {
	if (bCheckMembership) {
		biginteger q = (p - 1) / 2;
		//If the element is in the expected range, set it. else, throw exception
		if (x > 0 && x <= (p - 1))
		{
			if (boost::multiprecision::powm(x, q, p) == 1) // x^q mod p == 1
				element = x;
			else
				throw invalid_argument("Cannot create Zp element. Requested value " + x.str() +
				" is not in the range of this group.");
		}
		else
			throw invalid_argument("Cannot create Zp element. Requested value " + x.str() +
			" is not in the range of this group.");
	}
	else element = x;
		
}

ZpSafePrimeElement::ZpSafePrimeElement(const biginteger & p, PrgFromOpenSSLAES* prg)
{
	// Find a number in the range [1, ..., p-1]
	biginteger rand_in_range = getRandomInRange(1, p - 1, prg);
	// Calculate its power to get a number in the subgroup and set the power as the element. 
	element = boost::multiprecision::powm(rand_in_range, 2, p);
}

bool ZpSafePrimeElement::operator==(const GroupElement &other) const {
	if (typeid(*this) != typeid(other))
		return false;
	return this->element == ((ZpSafePrimeElement*)&other)->element;
}

bool ZpSafePrimeElement::operator!=(const GroupElement &other) const {
	return !(*this == other);
}

shared_ptr<GroupElementSendableData> ZpSafePrimeElement::generateSendableData() {
	return make_shared<ZpElementSendableData>(getElementValue());

}

/**************************************/ 
/**** DlogGroup Implementation ********/
/**************************************/

DlogGroup::GroupElementsExponentiations::GroupElementsExponentiations(
	const shared_ptr<DlogGroup> & parent_, const shared_ptr<GroupElement> & base_) {
	base = base_;
	parent = parent_;
	// build new vector of exponentiations
	exponentiations.push_back(base); // add the base - base^1

	biginteger two(2);
	for (int i = 1; i<4; i++) {
		auto multI = parent->exponentiate(exponentiations[i - 1].get(), two);
		exponentiations.push_back(multI);
	}
}

void DlogGroup::GroupElementsExponentiations::prepareExponentiations(const biginteger & size)
{
	//find log of the number - this is the index of the size-exponent in the exponentiation array 
	int index = find_log2_floor(size);

	/* calculates the necessary exponentiations and put them in the exponentiations vector */
	/* size of the vector stars with 4 in the constructor so we can always subtract */
	for (int i = exponentiations.size(); i <= index; i++) {
		auto multI = parent->exponentiate(exponentiations[i - 1].get(), biginteger(2));
		exponentiations.push_back(multI);
	}
}

shared_ptr<GroupElement> DlogGroup::GroupElementsExponentiations::getExponentiation(const biginteger & size) {
	/**
	* The exponents in the exponents vector are all power of 2.
	* In order to achieve the exponent size, we calculate its closest power 2 in the exponents vector
	* and continue the calculations from there.
	*/
	// find the the closest power 2 exponent
	size_t index = find_log2_floor(size);

	shared_ptr<GroupElement> exponent = NULL;
	/* if the requested index out of the vector bounds, the exponents have not been calculated yet, so calculates them.*/
	if (exponentiations.size() <= index)
		prepareExponentiations(size);

	exponent = exponentiations[index]; //get the closest exponent in the exponentiations vector
	
	/* if size is not power 2, calculates the additional multiplications */
	biginteger lastExp = boost::multiprecision::pow(biginteger(2), index);
	biginteger difference = size - lastExp;
	if (difference > 0) {
		auto diff = getExponentiation(size - lastExp);
		exponent = parent->multiplyGroupElements(diff.get(), exponent.get());
	}

	return exponent;
}

shared_ptr<GroupElement> DlogGroup::createRandomElement() {
	// This is a default implementation that is valid for all the Dlog Groups and relies on mathematical properties of the generators.
	// However, if a specific Dlog Group has a more efficient implementation then is it advised to override this function in that concrete
	// Dlog group. For example we do so in CryptoPpDlogZpSafePrime.
	biginteger randNum = getRandomInRange(1, groupParams->getQ() - 1, random_element_gen.get());

	// compute g^x to get a new element
	return exponentiate(generator.get(), randNum);
}

shared_ptr<GroupElement> DlogGroup::createRandomGenerator() {
	// in prime order groups every element except the identity is a generator.
	// get a random element in the group
	auto randGen = createRandomElement();
	// if the given element is the identity, get a new random element
	while (randGen->isIdentity() == true) {
		randGen = createRandomElement();
	}
	return randGen;
}

shared_ptr<GroupElement> DlogGroup::computeLoop(vector<biginteger> & exponentiations, int w,
	int h, vector<vector<shared_ptr<GroupElement>>> & preComp, shared_ptr<GroupElement> & result, int bitIndex){
	int e = 0;
	for (size_t k = 0; (int) k<h; k++) {
		for (size_t i = k*w; i<(k * w + w); i++) {
			if (i < exponentiations.size()) {
				//if the bit is set, change the e value
				if (boost::multiprecision::bit_test(exponentiations[i], bitIndex)){
				//if (exponentiations[i].testBit(bitIndex) == true) {
					int twoPow = (int)(pow(2, i - k*w));
					e += twoPow;
				}
			}
		}
		//multiply result with preComp[k][e]
		result = multiplyGroupElements(result.get(), preComp[k][e].get());
		e = 0;
	}
	return result;
}

vector<vector<shared_ptr<GroupElement>>> DlogGroup::createLLPreCompTable(
	vector<shared_ptr<GroupElement>> & groupElements, int w, int h){
	int twoPowW = (int)(pow(2, w));
	//create the pre-computation table of size h*(2^(w))
	vector<vector<shared_ptr<GroupElement>>> preComp; // GroupElement[][] preComp = new GroupElement[h][twoPowW];
	for (int i = 0; i < h; ++i) {
		preComp.push_back(vector<shared_ptr<GroupElement>>());
		preComp[preComp.size() - 1].resize(twoPowW, NULL);
	}


	shared_ptr<GroupElement> base = NULL;
	size_t baseIndex;

	//fill the table
	for (int k = 0; k<h; k++) {
		for (int e = 0; e<twoPowW; e++) {
			preComp[k][e] = getIdentity();

			for (int i = 0; i<w; i++) {
				baseIndex = k*w + i;
				if (baseIndex < groupElements.size()) {
					base = groupElements[baseIndex];
					//if bit i in e is set, change preComp[k][e]
					if ((e & (1 << i)) != 0) { //bit i is set
						preComp[k][e] = multiplyGroupElements(preComp[k][e].get(), base.get());
					}
				}
			}
		}
	}

	return preComp;

}

int DlogGroup::getLLW(int t) {
		int w;
		//choose w according to the value of t
		if (t <= 10) {
			w = 2;
		}
		else if (t <= 24) {
			w = 3;
		}
		else if (t <= 60) {
			w = 4;
		}
		else if (t <= 144) {
			w = 5;
		}
		else if (t <= 342) {
			w = 6;
		}
		else if (t <= 797) {
			w = 7;
		}
		else if (t <= 1828) {
			w = 8;
		}
		else {
			w = 9;
		}
		return w;
}

shared_ptr<GroupElement> DlogGroup::exponentiateWithPreComputedValues(
	const shared_ptr<GroupElement> & groupElement, const biginteger & exponent){
	//extracts from the map the GroupElementsExponentiations object corresponding to the accepted base
	auto it = exponentiationsMap.find(groupElement);
	
	// if there is no object that matches this base - create it and add it to the map
	if (it == exponentiationsMap.end()) {
		auto exponentiations = make_shared<GroupElementsExponentiations>(shared_ptr<DlogGroup>(this), groupElement);
		//TODO: free allocated memory
		exponentiationsMap[groupElement] = exponentiations;
	}
	
	// calculates the required exponent
	return exponentiationsMap.find(groupElement)->second->getExponentiation(exponent);
}

shared_ptr<GroupElement> DlogGroup::computeNaive(
	vector<shared_ptr<GroupElement>> & groupElements, vector<biginteger> & exponentiations)
{
	int n = groupElements.size(); //number of bases and exponents
	vector<shared_ptr<GroupElement>> exponentsResult(n); //holds the exponentiations result

	// raises each element to the corresponding power
	for (int i = 0; i < n; i++) {
		exponentsResult[i] = exponentiate(groupElements[i].get(), exponentiations[i]);
	}

	auto result = getIdentity(); //initialized to the identity element

	//multiplies every exponentiate
	for (int i = 0; i<n; i++) {
		result = multiplyGroupElements(exponentsResult[i].get(), result.get());
	}

	//return the final result
	return result;
}

shared_ptr<GroupElement> DlogGroup::computeLL(
	vector<shared_ptr<GroupElement>> & groupElements, vector<biginteger> & exponentiations)
{
	int n = groupElements.size(); //number of bases and exponents

    //get the biggest exponent
	biginteger bigExp = 0;
	for (size_t i = 0; i<exponentiations.size(); i++)
		if (bigExp < exponentiations[i])
			bigExp = exponentiations[i];

	int t = find_log2_floor(bigExp)+1; //num bits of the biggest exponent.
	int w = 0; //window size

	//choose w according to the value of t
	w = getLLW(t);

	//h = n/w
	int h;
	if ((n % w) == 0) {
		h = n / w;
	}
	else {
		h = ((int)(n / w)) + 1;
	}

	//create pre computation table
	auto preComp = createLLPreCompTable(groupElements, w, h);

	auto result = getIdentity(); //holds the computation result

	//computes the first loop of the algorithm. This loop returns in the next part of the algorithm with one single tiny change. 
	result = computeLoop(exponentiations, w, h, preComp, result, t - 1);

	//computes the third part of the algorithm
	for (int j = t - 2; j >= 0; j--) {
		//Y = Y^2
		result = exponentiate(result.get(), 2);

		//computes the inner loop
		result = computeLoop(exponentiations, w, h, preComp, result, j);
	}

	return result;
}
/*********************************************************************/
/*END of DlogGroup Implementation *********************************/
/*********************************************************************/

/**************************************/
/**** EC GroupParams Implementation ***/
/**************************************/

string ECF2mPentanomialBasis::toString() {
	string s = "ECF2mPentanomialBasis [k1=" + to_string(k1);
	s += ", k2=" + to_string(k2);
	s += ", k3=" + to_string(k3);
	s += ", m=" + to_string(m);
	s += ", a=" + a.str() + ", b=" + b.str() + ", xG=" + xG.str() +
	        ", yG=" + yG.str() + ", h=" + h.str() + ", q=" + q.str() + "]";
	return s;
}

int ECF2mKoblitz::getK2() {
	int k2 = 0;
	shared_ptr<ECF2mPentanomialBasis> pentaCurve = dynamic_pointer_cast<ECF2mPentanomialBasis>(curve);
	if (pentaCurve)
		k2 = pentaCurve->getK2();

	return k2;
}

int ECF2mKoblitz::getK3() {
	int k3 = 0;
	shared_ptr<ECF2mPentanomialBasis> pentaCurve = dynamic_pointer_cast<ECF2mPentanomialBasis>(curve);
	if (pentaCurve)
		k3 = pentaCurve->getK3();

	return k3;
}

string ECF2mKoblitz::toString() {
	string s = "ECF2mKoblitz [getM()=" + to_string(getM());
	s += ", getK1()=" + to_string(getK1());
	s += ", getK2()=" + to_string(getK2());
	s += ", getK3()=" + to_string(getK3());
	s += ", getQ()=" + getQ().str() + ", getXg()=" + getXg().str() + ", getYg()=" + getYg().str()
		+ ", getA()=" + getA().str() + ", getB()=" + getB().str()
		+ ", getSubGroupOrder()=" + getSubGroupOrder().str()
		+ ", getCurve()=[" + getCurve()->toString() + "], getCofactor()="
		+ getCofactor().str() + "]";
	return s;
}

/*********************************************************************/
/*END of GroupParams Implementation *********************************/
/*********************************************************************/

/**************************************/
/******* Dlog EC Implementation *******/
/**************************************/

bool ECElement::operator==(const GroupElement &other) const {
	if (typeid(*this) != typeid(other))
		return false;
	if (((ECElement*)this)->getX() != ((ECElement*)&other)->getX())
		return false;
	return ((ECElement*)this)->getY() == ((ECElement*)&other)->getY();
}

bool ECElement::operator!=(const GroupElement &other) const {
	return !(*this == other);
}

shared_ptr<GroupElementSendableData> ECElement::generateSendableData() {
	return make_shared<ECElementSendableData>(getX(), getY());
}

string ECElementSendableData::toString() {
	return x.str() + ":" + y.str();
}

void ECElementSendableData::initFromString(const string & raw) {
	auto str_vec = explode(raw, ':');
	assert(str_vec.size() == 2);
	x = biginteger(str_vec[0]);
	y = biginteger(str_vec[1]);
}

/**
* Constructor that initializes this DlogGroup with a curve that is not necessarily one of NIST recommended elliptic curves.
* @param fileName - name of the elliptic curves file. This file has to comply with
* @param curveName - name of curve to initialized
* @throws IOException
*/
void DlogEllipticCurve::init(string fileName, string curveName, const shared_ptr<PrgFromOpenSSLAES> & random) {
	
	ecConfig = make_shared<ConfigFile>(fileName); //get ConfigFile object containing the curves data
																//EC_FILE_PATH = fileName;
	//In case there is no such curve in the file, an exception will be thrown.
	ecConfig->Value(curveName, curveName);

	this->curveName = curveName;
	this->fileName = fileName;

	random_element_gen = random;
}