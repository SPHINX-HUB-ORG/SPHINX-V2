Pseudorandom Function (PRF)
===========================

In cryptography, a **pseudorandom function family**, abbreviated **PRF**, is a collection of efficiently-computable functions which emulate a random function in the following way: no efficient algorithm can distinguish (with significant advantage) between a function chosen randomly from the PRF family and a random oracle (a function whose outputs are fixed completely at random).

.. contents::

The ``PseudorandomFunction`` abstract class
-------------------------------------------

The main function of this class is ``computeBlock()``. We supply several versions for compute, with and without length. Since both PRP's and PRF's may have varying input/output length, for such algorithms the length should be supplied. We provide the version without the lengths and not just the versions with length of input and output, although it suffices, to avoid confusion and misuse from a basic user that only knows how to use block ciphers. A user that uses the block cipher TripleDES, may be confused by the “compute with length” functions since TripleDES has a pre-defined length and it cannot be changed.

Block Manipulation
~~~~~~~~~~~~~~~~~~

.. cpp:function:: void PseudorandomFunction::computeBlock(const vector<byte> & inBytes, int inOff, vector<byte> &outBytes, int outOff)

    Computes the function using the secret key.
    The user supplies the input vector and the offset from which to take the data from. 
    The user also supplies the output vector as well as the offset. 
    The computeBlock function will put the output in the output vector starting at the offset.
    This function is suitable for block ciphers where the input/output length is known in advance.
    
    :param inBytes: input bytes to compute
    :param inOff: input offset in the inBytes array
    :param outBytes: output bytes. The resulted bytes of compute
    :param outOff: output offset in the outBytes array to put the result from

.. cpp:function:: void PseudorandomFunction::computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte> &outBytes, int outOff, int outLen)
	
    Computes the function using the secret key.
    This function is provided in the abstract class especially for the sub-family PrfVaryingIOLength, 
    which may have variable input and output length.
    If the implemented algorithm is a block cipher then the size of the input as well as the output is known in advance and 
    the use may call the other computeBlock function where length is not require.
    
    :param inBytes: input bytes to compute
    :param inOff: input offset in the inBytes vector
    :param inLen: the length of the input vector
    :param outBytes: output bytes. The resulted bytes of compute
    :param outOff: output offset in the outBytes vector to put the result from
    :param outLen: the length of the output vector

.. cpp:function:: void PseudorandomFunction::computeBlock(const vector<byte> & inBytes, int inOffset, int inLen, vector<byte> &outBytes, int outOffset)
    
    Computes the function using the secret key.
 
    This function is provided in this PseudorandomFunction abstract class for the sake of classes for which the input length can be different for each computation. Hmac and Prf/Prp with variable input length are examples of such classes.
 
    :param inBytes: input bytes to compute
    :param inOffset: input offset in the inBytes vector
    :param inLen: the length of the input vector
    :param outBytes: output bytes. The resulted bytes of compute.
    :param outOffset: output offset in the outBytes vector to put the result from

.. cpp:function:: int PseudorandomFunction::getBlockSize()

   :return: the input block size in bytes

Setting the Secret Key
~~~~~~~~~~~~~~~~~~~~~~

.. cpp:function:: SecretKey PseudorandomFunction::generateKey(AlgorithmParameterSpec & keyParams)

   Generates a secret key to initialize this prf object.

   :param keyParams: algorithmParameterSpec contains the required parameters for the key generation
   :return: the generated secret key

.. cpp:function:: SecretKey PseudorandomFunction::generateKey(int keySize)

   Generates a secret key to initialize this prf object.

   :param keySize: is the required secret key size in bits
   :return: the generated secret key

.. cpp:function:: bool PseudorandomFunction::isKeySet()

   An object trying to use an instance of prf needs to check if it has already been initialized.

   :return: true if the object was initialized by calling the function setKey.

.. cpp:function:: void PseudorandomFunction::setKey(SecretKey & secretKey)

   Sets the secret key for this prf. The key can be changed at any time.

   :param secretKey: secret key

Basic Usage
-----------

.. code-block:: cpp

    //Create secretKey and in, in2, out vectors
    ...
    
    // create a PRF of type TripleDES using openssl library
    PseudorandomFunction* prf = new OpenSSLTripleDES();
    
    //set the key
    prf->setKey(secretKey);
    
    //compute the function with input in and output out.
    prf->computeBlock(in, 0, out, 0);


Pseudorandom Function with Varying Input-Output Lengths
-------------------------------------------------------

A pseudorandom function with varying input/output lengths does not have pre-defined input and output lengths. The input and output length may be different for each compute function call. The length of the input as well as the output is determined upon user request. The class ``IteratedPrfVarying`` implements this functionality using an inner PRF that must implement the ``PrfVaryingInputLength`` abstract class. An example for such PRF is ``Hmac``.

How to use the Varying Input-Output Length PRF
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: cpp

    //Create secret key and in, out byte vectors
    ...

    //create the Prf varying.
    PseudorandomFunction* prf = new IteratedPrfVarying(make_shared<OpenSSLHMAC>());
    
    //set the key
    prf->setKey(secretKey);
    
    //compute the function with input in of size 10 and output out of size 20.
    prf->computeBlock(in, 0, 10, out, 0, 20);

Supported Prf Types
--------------------

In this section we present the prf functions provided by libscapi.

==============================    ======================================
Class Name          		   Class Location
==============================    ======================================
IteratedPrfVarying         	    libscapi/include/primitives/Prf.hpp
LubyRackoffPrpFromPrfVarying        libscapi/include/primitives/Prf.hpp
==============================    ======================================

The OpenSSL implementation:

================   ============================================
Class Name           Class Location
================   ============================================
OpenSSLHMAC         libscapi/include/primitives/PrfOpenSSL.hpp
================   ============================================
