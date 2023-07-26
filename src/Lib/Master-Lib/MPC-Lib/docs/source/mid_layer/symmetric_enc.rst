Symmetric Encryption
====================

There are three main categories of symmetric encryption:

1. An encryption based on modes of operation using a pseudo-random permutation and a randomized IV. The randomized IV is crucial for security. **CBCEnc** and **CTREnc** belong to this category.

2. An authenticated encryption where the message gets first encrypted and then mac-ed. **EncryptThenMac** belongs to this category.

3. Homomorphic encryption. 

Libscapi currently implemented the CTR encryption only. In the future we may add more implementations.

The symmetric encryption class implements three main functionalities that correspond to the cryptographer’s language in which an encryption scheme is composed of three algorithms:

1. Generation of the key.

2. Encryption of the plaintext.

3. Decryption of the ciphertext.

.. contents::

The SymmetricEnc abstract class
-------------------------------

.. cpp:class:: SymmetricEnc : public Eav, public Indistinguishable

   This is the main class for the Symmetric Encryption family.
   Any symmetric encryption scheme belongs by default at least to the Eavsdropper Security Level and to the Indistinguishable Security Level.

Encryption and Decryption
~~~~~~~~~~~~~~~~~~~~~~~~~

.. cpp:function:: shared_ptr<SymmetricCiphertext> SymmetricEnc::encrypt(Plaintext* plaintext)

   Encrypts a plaintext. It lets the system choose the random IV.

   :return: an IVCiphertext, which contains the IV used and the encrypted data.

.. cpp:function:: shared_ptr<SymmetricCiphertext> SymmetricEnc::encrypt(Plaintext* plaintext, vector<byte> & iv)

   This function encrypts a plaintext. It lets the user choose the random IV.

   :param iv: random bytes to use in the encryption pf the message.
   :return: an IVCiphertext, which contains the IV used and the encrypted data.

.. cpp:function:: shared_ptr<Plaintext> SymmetricEnc::decrypt(SymmetricCiphertext* ciphertext)

   This function performs the decryption of a ciphertext returning the corresponding decrypted plaintext.

   :param ciphertext: The Ciphertext to decrypt.
   :return: the decrypted plaintext.

Key Generation
~~~~~~~~~~~~~~

.. cpp:function:: SecretKey SymmetricEnc::generateKey(AlgorithmParameterSpec& keyParams)

   Generates a secret key to initialize this symmetric encryption.

   :param keyParams: algorithmParameterSpec contains parameters for the key generation of this symmetric encryption.
   :return: the generated secret key.

.. cpp:function:: SecretKey SymmetricEnc::generateKey(int keySize)

   Generates a secret key to initialize this symmetric encryption.

   :param keySize: is the required secret key size in bits.
   :return: the generated secret key.

Key Handling
~~~~~~~~~~~~

.. cpp:function:: bool SymmetricEnc::isKeySet()

   An object trying to use an instance of symmetric encryption needs to check if it has already been initialized.

   :return: true if the object was initialized by calling the function setKey.

.. cpp:function:: void SymmetricEnc::setKey(SecretKey & secretKey)

   Sets the secret key for this symmetric encryption. The key can be changed at any time.

   :param secretKey: secret key.

The CTREnc abstract class
-------------------------

This is a marker class, for the CTR method:

.. image:: ../_static/CTR.png
   :alt: CTR mode

.. cpp:class:: CTREnc : public virtual SymmetricEnc, public Cpa

Basic Usage
-----------

Sender usage:

.. code-block:: cpp

    OpenSSLCTREncRandomIV encryptor("AES");

    //Generate a SecretKey using the created object and set it.
    SecretKey key = encryptor.generateKey(128);
    encryptor.setKey(key);

    //Get a plaintext to encrypt, and encrypt the plaintext.
    ...
    SymmetricCiphertext cipher = encryptor.encrypt(plaintext);

    //Send the cipher to the decryptor.
    ...

Receiver usage:

.. code-block:: cpp

    //Create the same SymmetricEnc object as the sender’s encryption object, and set the key.
    //Get the ciphertext and decrypt it to get the plaintext.
    Plaintext plaintext = decryptor.decrypt(cipher);

Supported Encryption Types
--------------------------

In this section we present the symmetric encryptions provided by libscapi.

The OpenSSL implementation:

======================       =====================================================
Class Name                     Class Location
======================       =====================================================
OpenSSLCTREncRandomIV          libscapi/include/mid_layer/OpenSSLSymmetricEnc.hpp
======================       =====================================================

