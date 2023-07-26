Cryptographic Hash
==================

A **cryptographic hash** function is a deterministic procedure that takes an arbitrary block of data and returns a fixed-size bit string, the (cryptographic) hash value. There are two main levels of security that we will consider here: 

*  **target collision resistance:** meaning that given :math:`x` it is hard to find :math:`y` such that :math:`H(y)=H(x)`.

*  **collision resistance:** meaning that it is hard to find any :math:`x` and :math:`y` such that :math:`H(x)=H(y)`.

.. note:: We do not include **preimage resistance** since cryptographically this is just a one-way function.

.. contents::

The ``CryptographicHash`` abstract class
----------------------------------------

The user may request to pass partial data to the hash and only after some iterations to obtain the hash of all the data. This is done by calling the function ``update()``. After the user is done updating the data it can call the ``hashFinal()`` to obtain the hash output.

.. cpp:function:: void update(const vector<byte> &in, int inOffset, int inLen)

   Adds the vector to the existing msg to hash.

   :param in: input vector
   :param inOffset: the offset within the vector
   :param inLen: the length. The number of bytes to take after the offset

.. cpp:function:: void hashFinal(vector<byte> &out, int outOffset)

   Completes the hash computation.

   :param out: the output in vector
   :param outOffset: the offset which to put the result bytes from

Usage
-----

Below is an example of using Cryptographic hash: 

.. code-block:: cpp

    //create an input array in and an output array out 
    ...
    
    //create  an OpenSSL sha224 function.
    CryptographicHash* hash = new OpenSSLSHA224();

    //call the update function in the Hash interface.
    hash->update(in, 0, in.length);

    //get the result of hashing the updated input.
    hash->hashFinal(out, 0);



Supported Hash Types
--------------------

In this section we present the hash functions provided by libscapi.

The OpenSSL implementation:

================   =============================================
Class Name           Class Location
================   =============================================
OpenSSLSHA1         libscapi/include/primitives/hashOpenSSL.hpp
OpenSSLSHA224       libscapi/include/primitives/hashOpenSSL.hpp
OpenSSLSHA256       libscapi/include/primitives/hashOpenSSL.hpp
OpenSSLSHA384       libscapi/include/primitives/hashOpenSSL.hpp
OpenSSLSHA512       libscapi/include/primitives/hashOpenSSL.hpp
================   =============================================

The Blake2 implementation:

================   ============================================
Class Name           Class Location
================   ============================================
Blake2SHA1         libscapi/include/primitives/hashBlake2.hpp
Blake2SHA224       libscapi/include/primitives/hashBlake2.hpp
Blake2SHA256       libscapi/include/primitives/hashBlake2.hpp
Blake2SHA384       libscapi/include/primitives/hashBlake2.hpp
Blake2SHA512       libscapi/include/primitives/hashBlake2.hpp
================   ============================================

