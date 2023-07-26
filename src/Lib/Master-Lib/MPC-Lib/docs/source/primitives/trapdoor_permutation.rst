Trapdoor Permutation
====================

A trapdoor permutation is a bijection (1-1 and onto function) that is easy to compute for everyone, yet is hard to invert unless given special additional information, called the "trapdoor". The public key is essentially the function description and the private key is the trapdoor. 

.. contents::

The ``TPElement`` abstract class
--------------------------------

The ``TPElement`` class represents a trapdoor permutation element.

.. cpp:function:: biginteger TPElement::getElement()

    Returns the trapdoor element value as bigInteger.
    
    :return: the value of the element

The ``TrapdoorPermutation`` abstract class
------------------------------------------

This class is the general class of trapdoor permutation.

Core Functionality
~~~~~~~~~~~~~~~~~~

.. cpp:function:: shared_ptr<TPElement> TrapdoorPermutation::compute(TPElement * tpEl)
 
    Computes the operation of this trapdoor permutation on the given TPElement.

    :param tpEl: the input for the computation
    :return: the result TPElement from the computation

.. cpp:function:: shared_ptr<TPElement> TrapdoorPermutation::invert(TPElement * tpEl)

    Inverts the operation of this trapdoor permutation on the given TPElement.

    :param tpEl: the input to invert
    :return: the result TPElement from the invert operation

.. cpp:function:: byte TrapdoorPermutation::hardCorePredicate(TPElement* tpEl)

    Computes the hard core predicate of the given tpElement.
    
    A hard-core predicate of a one-way function :math:`f` is a predicate :math:`b` (i.e., a function whose output is a single bit) 
    which is easy to compute given :math:`x` but is hard to compute given :math:`f(x)`.
    In formal terms, there is no probabilistic polynomial time algorithm that computes :math:`b(x)` from :math:`f(x)` 
    with probability significantly greater than one half over random choice of :math:`x`.

    :param tpEl: the input to the hard core predicate
    :return: (byte) the hard core predicate.

.. cpp:function:: vector<byte> TrapdoorPermutation::hardCoreFunction(TPElement* tpEl)

    Computes the hard core function of the given tpElement.

    A hard-core function of a one-way function :math:`f` is a function :math:`g` 
    which is easy to compute given :math:`x` but is hard to compute given :math:`f(x)`.
    In formal terms, there is no probabilistic polynomial time algorithm that computes :math:`g(x)` from :math:`f(x)` 
    with probability significantly greater than one half over random choice of :math:`x`.

    :param tpEl: the input to the hard core function
    :return: byte[] the result of the hard core function


Generating TPElements
~~~~~~~~~~~~~~~~~~~~~

.. cpp:function:: shared_ptr<TPElement> TrapdoorPermutation::generateRandomTPElement()

    creates a random TPElement that is valid for this trapdoor permutation

    :return: the created random element 

.. cpp:function::shared_ptr<TPElement> TrapdoorPermutation::generateTPElement(const biginteger & x)

    Creates a TPElement from a specific value :math:`x`. 
    It checks that the :math:`x` value is valid for this trapdoor permutation.

    :return: If the :math:`x` value is valid for this permutation return the created random element

.. cpp:function:: shared_ptr<TPElement> TrapdoorPermutation::generateUncheckedTPElement(const biginteger & x)
 
    Creates a TPElement from a specific value :math:`x`. 
    This function does not guarantee that the the returned ``TPElement`` object is valid.
    It is the caller's responsibility to pass a legal :math:`x` value.

    :return: Set the :math:`x` value and return the created random element


Checking Element Validity
~~~~~~~~~~~~~~~~~~~~~~~~~

.. cpp:function:: TPElValidity TrapdoorPermutation::isElement(TPElement* tpEl)

    Checks if the given element is valid for this trapdoor permutation

    :param tpEl: the element to check
    :return: (`TPElValidity`_) enum number that indicate the validation of the element
    :throws: IllegalArgumentException if the given element is invalid for this permutation

.. _TPElValidity:

.. cpp:enum:: TPElValidity

    Enum that represent the possible validity values of trapdoor element.
    There are three possible validity values:

    :param VALID: it is an element
    :param NOT_VALID: it is not an element
    :param DONT_KNOW: there is not enough information to check if it is an element or not

Encryption Keys Functionality
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. cpp:function:: void setKey(const shared_ptr<PublicKey> & publicKey, const shared_ptr<PrivateKey> & privateKey)

    Sets this trapdoor permutation with public key and private key.

    :param publicKey:  the public key
    :param privateKey: the private key that without it the permutation cannot be inverted efficiently. 
		       If the private key is not given, the object can compute but canot invert. 

.. cpp:function:: bool isKeySet()
    
    Checks if this trapdoor permutation object has been previously initialized.
    To initialize the object the ``setKey()`` function has to be called with corresponding parameters after construction.
    
    :return: ``true`` if the object was initialized, ``false`` otherwise.

 .. cpp:function:: shared_ptr<PublicKey> getPubKey()

    :return: returns the public key

BasicUsage
----------

We demonstrate a basic usage scenario with a sender party that wish to hide a secret using the trapdoor permutation,
and a receiver who is not able to invert the permutation on the secret.

Here is the code of the sender:

.. code-block:: cpp

    //Create public key, private key and secret
    ...
    
    //instantiate the rsa permutation using the openssl library:
    OpenSSLRSAPermutation trapdoorPermutation;
    //set the keys for this trapdoor permutation
    trapdoorPermutation.setKey(publicKey, privateKey);
    
    // represent the secret (originally was of BigInteger type) using TPElement
    TPElement secretElement = trapdoorPermutation.generateTPElement(secret);
    //hide the secret using the trapdoor permutation
    TPElement maskedSecret = trapdoorPermutation.compute(secretElement);
    
    // this line will succeed, because the private key is known to the sender
    TPElement invertedElement = trapdoorPermutation.invert(maskedSecret);
    
    // send the public key and the secret to the other side	
    ...

Here is the code of the receiver:

.. code-block:: cpp

    // receive public key and secretMsg
    ...
    
    //instantiate the rsa permutation using the openssl library:
    OpenSSLRSAPermutation trapdoorPermutation;
    //set the keys for this trapdoor permutation
    trapdoorPermutation.setKey(publicKey);
    
    // reconstruct a TPElement from a biginteger
    TPElement maskedSecret = trapdoorPermutation.generateTPElement(secretMsg);
    
    // this line will fail, because the private key is not known to the receiver
    TPElement secretElement = trapdoorPermutation.invert(maskedSecret);

Supported Trapdoor Permutations
-------------------------------

In this section we present the trapddor permutations provided by libscapi.
    
OpenSSL implementation of RSA trapdoor permutation:

=======================   ===============================================================
Key            		    Class Location
=======================   ===============================================================
OpenSSLRSAPermutation       libscapi/include/primitives/TrapdoorPermutationOpenSSL.hpp
=======================   ===============================================================
