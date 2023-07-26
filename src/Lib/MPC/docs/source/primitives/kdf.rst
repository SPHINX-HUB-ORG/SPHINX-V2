Key Derivation Function (KDF)
=============================

A key derivation function (or KDF) is used to derive (close to) uniformly distributed string/s from a secret value with high entropy (but no other guarantee regarding its distribution).

.. contents::

The ``Key Derivation Function`` abstract class:
-----------------------------------------------

.. cpp:function:: SecretKey KeyDerivationFunction::deriveKey(const vector<byte> & entropySource, int inOff, int inLen, int outLen, const vector<byte>& iv = vector<byte>())

   Generates a new secret key from the given seed and iv (if given).

   :param entropySource: the secret key that is the seed for the key generation
   :param inOff: the offset within the entropySource to take the bytes from
   :param inLen: the length of the seed
   :param outLen: the required output key length
   :param iv: info for the key generation
   :return: SecretKey the derivated key.

Basic Usage
-----------

.. code-block:: cpp

    KeyDerivationFunction* kdf = new HKDF(make_shared<OpenSSLHMAC>());
    vector<byte> source(3, 1);
    int targetLen = 128;
    vector<byte> kdfed = kdf->deriveKey(source, 0, source.size(), targetLen).getEncoded();


Supported KDF Types
--------------------

In this section we present the key derivation functions provided by libscapi.

===============   ======================================
Class Name          Class Location
===============   ======================================
HKDF		    libscapi/include/primitives/Kdf.hpp
===============   ======================================
