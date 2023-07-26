Pseudorandom Generator (PRG)
============================

A **pseudorandom generator (PRG)** is a deterministic algorithm that takes a “short” uniformly distributed string, known as *the seed*, and outputs a longer string that cannot be efficiently distinguished from a uniformly distributed string of that length.

The ``PseudorandomGenerator`` abstract class
--------------------------------------------

The main function of this class is ``getPrgBytes()``. It streams the prg bytes and return the reauired amount of pseudo random bytes:

.. cpp:function:: void PseudorandomGenerator::getPRGBytes(vector<byte> & outBytes, int outOffset, int outlen)

    Streams the prg bytes.
    
    :param outBytes: output bytes. The result of streaming the bytes.
    :param outOffset: output offset
    :param outlen: the required output length

Setting the Secret Key
~~~~~~~~~~~~~~~~~~~~~~

.. cpp:function:: SecretKey PseudorandomGenerator::generateKey(AlgorithmParameterSpec & keyParams)

   Generates a secret key to initialize this prg object.

   :param keyParams: algorithmParameterSpec contains the required parameters for the key generation
   :return: the generated secret key

.. cpp:function:: SecretKey PseudorandomGenerator::generateKey(int keySize)

   Generates a secret key to initialize this prg object.

   :param keySize: is the required secret key size in bits
   :return: the generated secret key

.. cpp:function:: bool PseudorandomGenerator::isKeySet()

   An object trying to use an instance of prg needs to check if it has already been initialized.

   :return: true if the object was initialized by calling the function setKey.

.. cpp:function:: void PseudorandomGenerator::setKey(SecretKey & secretKey)

   Sets the secret key for this prg. The key can be changed at any time.

   :param secretKey: secret key

Basic Usage
-----------

.. code-block:: cpp

    //Create secret key and out byte vector
    ...
    
    //Create a prg 
    PseudorandomGenerator* prg = new PrgFromOpenSSLAES(); 
    SecretKey secretKey = prg->generateKey(256); //256 is the key size in bits. 
    
    //set the key
    prg->setKey(secretKey);
    
    //get PRG bytes. The caller is responsible for allocating the out array.
    //The result will be put in the out array.
    prg->getPRGBytes(out.length, out);

Supported Prg Types
--------------------

In this section we present the prg functions provided by libscapi.

====================   ======================================
Class Name          	 Class Location
====================   ======================================
ScPrgFromPrf         	 libscapi/include/primitives/Prg.hpp
PrgFromOpenSSLAES        libscapi/include/primitives/Prf.hpp
====================   ======================================

The OpenSSL implementation:

================   =======================================
Class Name           Class Location
================   =======================================
OpenSSLRC4           libscapi/include/primitives/Prg.hpp
================   =======================================
