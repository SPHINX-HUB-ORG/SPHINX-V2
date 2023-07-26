Discrete Log Group (DLOG)
=========================

The **discrete logarithm problem** is as follows: given a generator :math:`g` of a finite group :math:`G` and a random element :math:`h \in G`, find the (unique) integer :math:`x` such that :math:`g^x = h`. In cryptography, we are interested in groups for which the discrete logarithm problem (Dlog for short) is assumed to be hard (or other discrete-log type assumptions like **CDH** and **DDH**). The two most common classes are a prime subgroup of the group :math:`Z_p^*` for a large :math:`p`, and some Elliptic curve groups.

We provide the implementation of the most important Dlog groups in cryptography (see diagram below):

* :math:`Z_p^*`
* Elliptic curve over the field :math:`GF[2^m]`
* Elliptic curve over the field :math:`Z_p`

Although Elliptic curves groups look very different, the discrete log problem over them can be described as follows. Given an elliptic curve :math:`E` over a finite field :math:`F`, a base point on that curve :math:`P` (i.e., a generator of the group defined from the curve), and a random point :math:`Q` on the curve, the problem is to find the integer :math:`n` such that :math:`nP=Q`.

We have currently incorporated the elliptic curves recommended by NIST_.

.. _NIST: http://www.nist.gov/

.. contents::

Class Hierarchy:
----------------

The root of the family is a general Dlog Group that presents functionality that all Dlog Groups should implement.

At the second level we encounter three interfaces:

1. PrimeOrderSubGroup: The order :math:`q` of the group must be a prime.
2. DlogZp: Dlog Group over the :math:`Z_p^*` field.
3. DlogEllipticCurve: Any elliptic curve.

At the third level we have:

1. DlogZpSafePrime: The order :math:`q` is not only a prime but also is such that prime :math:`p = 2*q + 1`.
2. DlogEcFp: Any elliptic curve over :math:`F_p`.
3. DlogEcF2m: Any elliptic curve over :math:`F_2[m]`.

All these are general interfaces. Specifically, we implement Dlog Groups that are of prime order; therefore all the concrete classes presented here implement this interface. Other implementations may choose to add Dlog Groups that are not of prime order, and they are at liberty of doing so. They just need not to declare that they implement the PrimeOrderSubGroup interface.

We also see in the diagram two other interfaces that are **used** by DlogGroup: 

1. GroupParams.
2. GroupElement.

The ``DlogGroup`` abstract class
--------------------------------

Group Parameters
~~~~~~~~~~~~~~~~

.. cpp:function:: shared_ptr<GroupElement> DlogGroup::getGenerator()

   The generator g of the group is an element of the group such that, 
   when written multiplicatively, every element of the group is a power of g.

   :return: the generator of this Dlog group

.. cpp:function:: shared_ptr<GroupElement> DlogGroup::createRandomGenerator()

   Creates a random generator of this Dlog group

   :return: the random generator

.. cpp:function:: biginteger DlogGroup::getOrder()

   :return: the order of this Dlog group

.. cpp:function:: shared_ptr<GroupParams> DlogGroup::getGroupParams()

   GroupParams is a structure that holds the actual data that makes this group a specific Dlog group.
   For example, for a Dlog group over Zp* what defines the group is p.

   :return: the GroupParams of that Dlog group

.. cpp:function:: string DlogGroup::getGroupType()

   Each concrete class implementing this interface returns a string with a meaningful 
   name for this type of Dlog group. For example: "elliptic curve over F2m" or "Zp*"

   :return: the name of the group type

.. cpp:function:: shared_ptr<GroupElement> DlogGroup::getIdentity()

   :return: the identity of this Dlog group

Exponentiation
~~~~~~~~~~~~~~

.. cpp:function:: shared_ptr<GroupElement> DlogGroup::exponentiate(GroupElement* base, const biginteger & exponent)

   Raises the base GroupElement to the exponent. The result is another GroupElement.

   :return: the result of the exponentiation

.. cpp:function:: shared_ptr<GroupElement> DlogGroup::exponentiateWithPreComputedValues(const shared_ptr<GroupElement> & base, const biginteger & exponent)

   Computes the product of several exponentiations of the same base and distinct exponents. 
   An optimization is used to compute it more quickly by keeping in memory the result of h1, h2, h4,h8,... and using it in the calculation.

   Note that if we want a one-time exponentiation of h it is preferable to use the basic exponentiation function 
   since there is no point to keep anything in memory if we have no intention to use it.

   :return: the exponentiation result

.. cpp:function:: void DlogGroup::endExponentiateWithPreComputedValues(const shared_ptr<GroupElement> & base)

   This function cleans up any resources used by exponentiateWithPreComputedValues for the requested base. It is recommended to call it whenever an application does not need to continue calculating exponentiations for this specific base.

.. cpp:function:: shared_ptr<GroupElement> DlogGroup::simultaneousMultipleExponentiations(vector<shared_ptr<GroupElement>> & groupElements, vector<biginteger> & exponentiations)

   Computes the product of several exponentiations with distinct bases and distinct exponents. Instead of computing each part separately, an optimization is used to compute it simultaneously.

   :param groupElements: vector of base elements to exponentiate
   :param exponentiations: vector of exponents
   :return: the exponentiation result

Multiplication and Inverse
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. cpp:function:: shared_ptr<GroupElement> DlogGroup::getInverse(GroupElement* groupElement)

   Calculates the inverse of the given GroupElement.

   :param groupElement: to invert
   :return: the inverse element of the given GroupElement

.. cpp:function:: shared_ptr<GroupElement> DlogGroup::multiplyGroupElements(GroupElement* groupElement1, GroupElement* groupElement2)

   Multiplies two GroupElements

   :return: the multiplication result

Group Element Generation
~~~~~~~~~~~~~~~~~~~~~~~~

.. cpp:function:: shared_ptr<GroupElement> DlogGroup::createRandomElement()

   Creates a random member of this Dlog group

   :return: the random element

.. cpp:function:: shared_ptr<GroupElement> DlogGroup::generateElement(bool bCheckMembership, vector<biginteger> & values)

   This function allows the generation of a group element by a protocol that holds a Dlog Group but does not know 
   if it is a Zp Dlog Group or an Elliptic Curve Dlog Group. It receives the possible values of a group element 
   and whether to check membership of the group element to the group or not. 
   
   It may be not necessary to check membership if the source of values is a trusted source (it can be the group itself after some calculation). 
   On the other hand, to work with a generated group element that is not really an element in the group is wrong. 
   It is up to the caller of the function to decide if to check membership or not. 
   If bCheckMembership is false always generate the element. Else, generate it only if the values are correct.

   :param bCheckMembership:
   :param values:
   :return: the generated GroupElement

Validation
~~~~~~~~~~

.. cpp:function:: bool DlogGroup::isGenerator()

   Checks if the element set as the generator is indeed the generator of this group.

   :return: ``true`` if the generator is valid, ``false`` otherwise.

.. cpp:function:: bool DlogGroup::isMember(GroupElement* element)

   Checks if the given element is a member of this Dlog group

   :param element: possible group element for which to check that it is a member of this group
   :return: ``true`` if the given element is a member of this group, ``false`` otherwise.

.. cpp:function:: bool DlogGroup::validateGroup()

   Checks parameters of this group to see if they conform to the type this group is supposed to be.

   :return: ``true`` if valid, ``false`` otherwise.

Group Classification
~~~~~~~~~~~~~~~~~~~~

.. cpp:function:: bool DlogGroup::isOrderGreaterThan(int numBits)

   Checks if the order of this group is greater than 2^numBits

   :return: ``true`` if the order is greater than 2^numBits, ``false`` otherwise.

.. cpp:function:: bool DlogGroup::isPrimeOrder()

   Checks if the order is a prime number

   :return: true if the order is a prime number, false otherwise.

Group Element Serialization
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. cpp:function:: shared_ptr<GroupElement> DlogGroup::reconstructElement(bool bCheckMembership, GroupElementSendableData* data) 

   Reconstructs a GroupElement given the GroupElementSendableData data, which might have been received through a Channel open between the party holding this DlogGroup and some other party.

   :param bCheckMembership: whether to check that the data provided can actually reconstruct an element of this DlogGroup. Since this action is expensive it should be used only if necessary.
   :param data: the GroupElementSendableData from which we wish to "reconstruct" an element of this DlogGroup
   :return: the reconstructed GroupElement

Byte Array Encoding
~~~~~~~~~~~~~~~~~~~

.. cpp:function:: shared_ptr<GroupElement> DlogGroup::encodeByteArrayToGroupElement(const vector<unsigned char> & binaryString)   

   This function takes any string of length up to k bytes and encodes it to a Group Element. k can be obtained by calling getMaxLengthOfByteArrayForEncoding() and it is calculated upon construction of this group; it depends on the length in bits of p.

   The encoding-decoding functionality is not a bijection, that is, it is a 1-1 function but **is not onto**. Therefore, any string of length in bytes up to k can be encoded to a group element but not every group element can be decoded to a binary string in the group of binary strings of length up to 2^k.

   Thus, the right way to use this functionality is first to encode a byte array and then to decode it, and not the opposite.

   :param binaryString: the byte array to encode
   :return: the encoded group Element **or null** if the string could not be encoded

.. cpp:function:: const vector<unsigned char> DlogGroup::decodeGroupElementToByteArray(GroupElement* groupElement)

   This function decodes a group element to a byte array. This function is guaranteed to work properly **ONLY** if the group element was obtained as a result of encoding a binary string of length in bytes up to k.

   This is because the encoding-decoding functionality is not a bijection, that is, it is a 1-1 function but **is not onto**. Therefore, any string of length in bytes up to k can be encoded to a group element but not any group element can be decoded to a binary sting in the group of binary strings of length up to 2^k.

   :param groupElement: the element to decode
   :return: the decoded byte array

.. cpp:function:: int DlogGroup::getMaxLengthOfByteArrayForEncoding()

   This function returns the value *k* which is the maximum length of a string to be encoded to a Group Element of this group.
   Any string of length *k* has a numeric value that is less than (p-1)/2. 
   *k* is the maximum length a binary string is allowed to be in order to encode the said binary string to a group element and vice-versa.
   If a string exceeds the *k* length it cannot be encoded.

   :return: k the maximum length of a string to be encoded to a Group Element of this group. k can be zero if there is no maximum.

.. cpp:function:: const vector<byte> DlogGroup::mapAnyGroupElementToByteArray(GroupElement* groupElement)

   This function maps a group element of this dlog group to a byte array.
   This function does not have an inverse function, that is, it is not possible to re-construct the original group element from the resulting byte array.

   :return: a byte array representation of the given group element


The ``GroupElement`` abstract class
-----------------------------------

.. cpp:function:: shared_ptr<GroupElementSendableData> GroupElement::generateSendableData()

   This function is used when a group element needs to be sent via a channel or any other means of sending data. 
   It retrieves all the data needed to reconstruct this Group Element at a later time and/or in a different VM. 
   It puts all the data in an instance of the relevant class that implements the GroupElementSendableData interface.

   :return: the GroupElementSendableData object

.. cpp:function:: bool GroupElement::isIdentity()

   checks if this element is the identity of the group.

   :return: ``true`` if this element is the identity of the group, ``false`` otherwise.

The ``GroupParams`` class
-------------------------

.. cpp:function:: biginteger GroupParams::getQ() 

   :return: the group order q

Basic Usage
-----------

.. code-block:: cpp

    // initiate a discrete log group (in this case the OpenSSL implementation of the elliptic curve group K-233)
    DlogGroup* dlog = new OpenSSLDlogECF2m("include/configFiles/NISTEC.txt", "K-233");
    
    // get the group generator and order 
    shared_ptr<GroupElement> g = dlog->getGenerator();
    biginteger q = dlog->getOrder();
    auto random = get_seeded_prg();
    
    // create a random exponent r
    biginteger r = getRandomInRange(0, q - 1, random.get());
    // exponentiate g in r to receive a new group element
    shared_ptr<GroupElement> g1 = dlog->exponentiate(g.get(), r);
    // create a random group element
    
    shared_ptr<GroupElement> h = dlog->createRandomElement();
    // multiply elements
    shared_ptr<GroupElement> gMult = dlog->multiplyGroupElements(g1.get(), h.get());

.. todo
   Zp Group
   --------

   dsfdsf

   Elliptic Curve Group
   --------------------

   wqewqeqwe

Supported Dlog Types
--------------------

In this section we present the Discrete log groups provided by libscapi.

The OpenSSL implementation:

=======================   ===============================================
Class Name        	    Class Location
=======================   ===============================================
OpenSSLDlogZpSafePrime      libscapi/include/primitives/DlogOpenSSL.hpp
OpenSSLDlogECFp		    libscapi/include/primitives/DlogOpenSSL.hpp
OpenSSLDlogECF2m	    libscapi/include/primitives/DlogOpenSSL.hpp
=======================   ===============================================
