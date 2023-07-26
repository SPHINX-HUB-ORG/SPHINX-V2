Asymmetric Encryption
=====================

Asymmetric encryption refers to a cryptographic system requiring two separate keys, one to encrypt the plaintext, and one to decrypt the ciphertext. Neither key will do both functions. One of these keys is public and the other is kept private. If the encryption key is the one published then the system enables private communication from the public to the decryption key's owner.

.. contents::

Asymmetric encryption can be used by a protocol or a user in two different ways:

1. The protocol works on an abstract level and does not know the concrete algorithm of the asymmetric encryption. This way the protocol cannot create a specific Plaintext to the encrypt function because it does not know which concrete Plaintext the encrypt function should get. 
Similarly, the protocol does not know how to treat the Plaintext returned from the decrypt function. 
In these cases the protocol has a byte array that needs to be encrypted.

2. The protocol knows the concrete algorithm of the asymmetric encryption. This way the protocol knows which Plaintext implementation the encrypt function gets and the decrypt function returns. Therefore, the protocol can be specific and cast the plaintext to the concrete implementation. For example, the protocol knows that it has a DamgardJurikEnc object, so the encrypt function gets a BigIntegerPlaintext and the decrypt function returns a BigIntegerPlaintext. The protocol can create such a plaintext in order to call the encrypt function or cast the returned plaintext from the decrypt function to get the BigInteger value that was encrypted.

The AsymmetricEnc abstract class
---------------------------------

.. cpp:class:: AsymmetricEnc : public Cpa, Indistinguishable 

   General class for asymmetric encryption. Each class of this family must derive this class.

Encryption and Decryption
~~~~~~~~~~~~~~~~~~~~~~~~~

.. cpp:function:: shared_ptr<AsymmetricCiphertext> AsymmetricEnc::encrypt(const shared_ptr<Plaintext> & plainText)

   Encrypts the given plaintext using this asymmetric encryption scheme.

   :param plainText: message to encrypt
   :return: Ciphertext the encrypted plaintext

.. cpp:function:: shared_ptr<AsymmetricCiphertext> AsymmetricEnc::encrypt(const shared_ptr<Plaintext> & plainText, const biginteger & r)

   Decrypts the given ciphertext using this asymmetric encryption scheme.

   :param cipher: ciphertext to decrypt
   :return: Plaintext the decrypted cipher


Plaintext Manipulation
~~~~~~~~~~~~~~~~~~~~~~

.. cpp:function:: shared_ptr<Plaintext> AsymmetricEnc::generatePlaintext(vector<byte> & text)

   Generates a Plaintext suitable for this encryption scheme from the given message.

   A Plaintext object is needed in order to use the encrypt function. Each encryption scheme might generate a different type of Plaintext according to what it needs for encryption. The encryption function receives as argument an object of type Plaintext in order to allow a protocol holding the encryption scheme to be oblivious to the exact type of data that needs to be passed for encryption.

   :param text: byte array to convert to a Plaintext object.

.. cpp:function:: vector<byte> AsymmetricEnc::generateBytesFromPlaintext(Plaintext* plaintext)

   Generates a byte array from the given plaintext. This function should be used when the user does not know the specific type of the Asymmetric encryption he has, and therefore he is working on byte array.

   :param plaintext: to generates byte array from.
   :return: the byte array generated from the given plaintext.

.. cpp:function:: int AsymmetricEnc::getMaxLengthOfByteArrayForPlaintext()

   Returns the maximum size of the byte array that can be passed to generatePlaintext function. This is the maximum size of a byte array that can be converted to a Plaintext object suitable to this encryption scheme.

   :return: the maximum size of the byte array that can be passed to generatePlaintext function.

.. cpp:function:: bool AsymmetricEnc::hasMaxByteArrayLengthForPlaintext()

   There are some encryption schemes that have a limit of the byte array that can be passed to the generatePlaintext. This function indicates whether or not there is a limit. Its helps the user know if he needs to pass an array with specific length or not.

   :return: true if this encryption scheme has a maximum byte array length to generate a plaintext from; false, otherwise.

Key Generation
~~~~~~~~~~~~~~

.. cpp:function:: pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>> AsymmetricEnc::generateKey(AlgorithmParameterSpec * keyParams)

   Generates public and private keys for this asymmetric encryption.

   :param keyParams: hold the required parameters to generate the encryption scheme's keys
   :return: KeyPair holding the public and private keys relevant to the encryption scheme

.. cpp:function:: pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>> AsymmetricEnc::generateKey()

   Generates public and private keys for this asymmetric encryption.

   :return: KeyPair holding the public and private keys

Key Handling
~~~~~~~~~~~~

.. cpp:function:: shared_ptr<PublicKey> AsymmetricEnc::getPublicKey()

   Returns the PublicKey of this encryption scheme.

   This function should not be use to check if the key has been set. To check if the key has been set use isKeySet function.

   :return: the PublicKey

.. cpp:function:: bool AsymmetricEnc::isKeySet()

   Checks if this AsymmetricEnc object has been previously initialized with corresponding keys.

   :return: ``true`` if either the Public Key has been set or the key pair (Public Key, Private Key) has been set; ``false`` otherwise.

.. cpp:function:: void AsymmetricEnc::setKey(const shared_ptr<PublicKey> & publicKey, const shared_ptr<PrivateKey> & privateKey)

   Sets this asymmetric encryption with public key and private key.

.. cpp:function:: void AsymmetricEnc::setKey(const shared_ptr<PublicKey> & publicKey)

   Sets this asymmetric encryption with a public key

   In this case the encryption object can be used only for encryption.

Reconstruction (from communication channel)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. cpp:function:: shared_ptr<AsymmetricCiphertext> AsymmetricEnc::reconstructCiphertext(AsymmetricCiphertextSendableData* data)

   Reconstructs a suitable AsymmetricCiphertext from data that was probably obtained via a Channel or any other means of sending data (including serialization).

   We emphasize that this is NOT in any way an encryption function, it just receives ENCRYPTED DATA and places it in a ciphertext object.

   :param data: contains all the necessary information to construct a suitable ciphertext.
   :return: the AsymmetricCiphertext that corresponds to the implementing encryption scheme, for ex: CramerShoupCiphertext

.. cpp:function:: shared_ptr<PrivateKey> AsymmetricEnc::reconstructPrivateKey(KeySendableData* data)

   Reconstructs a suitable PrivateKey from data that was probably obtained via a Channel or any other means of sending data (including serialization).

   We emphasize that this function does NOT in any way generate a key, it just receives data and recreates a PrivateKey object.

   :param data: a KeySendableData object needed to recreate the original key. The actual type of KeySendableData has to be suitable to the actual encryption scheme used, otherwise it throws an IllegalArgumentException
   :return: a new PrivateKey with the data obtained as argument

.. cpp:function:: shared_ptr<PublicKey> AsymmetricEnc::reconstructPublicKey(KeySendableData* data)

   Reconstructs a suitable PublicKey from data that was probably obtained via a Channel or any other means of sending data (including serialization).

   We emphasize that this function does NOT in any way generate a key, it just receives data and recreates a PublicKey object.

   :param data: a KeySendableData object needed to recreate the original key. The actual type of KeySendableData has to be suitable to the actual encryption scheme used, otherwise it throws an IllegalArgumentException
   :return: a new PublicKey with the data obtained as argument

Using the Generic Interface
---------------------------

Sender Usage:

.. code-block:: cpp

    //Get an abstract Asymmetric encryption object from somewhere. 
    //Generate a key pair using the encryptor.
    auto pair = encryptor.generateKey();

    //Publish your public key.
    Publish(pair.first);

    //Set private key and party2's public key: 
    encryptor.setKey(party2PublicKey, pair.second);
    
    //Generate a plaintext suitable for this encryption object using the encryption object.
    Plaintext plaintext = encryptor.generatePlaintext(msg);

    //Encrypt the plaintext
    AsymmetricCiphertext cipher = encryptor.encrypt(plaintext);

    //Send cipher and keys to the receiver.
    ...

Receiver Usage:

.. code-block:: cpp

    //Get the same asymmetric encryption object as the sender’s object. //Generate a keyPair using the encryption object.
    auto pair = encryptor.generateKey();

    //Publish your public key.
    Publish(pair.getPublic());

    //Set private key and party1's public key: 
    encryptor.setKey(party1PublicKey, pair.second);
    
    //Get the ciphertext and decrypt it to get the plaintext.
    ...

    Plaintext plaintext = encryptor.decrypt(cipher);
    //Get the plaintext bytes using the encryption object and use it as needed. 
    auto text = encryptor.generatesBytesFromPlaintext(plaintext);
    ...

El Gamal Encryption Scheme
--------------------------

The El Gamal encryption scheme’s security is based on the hardness of the decisional Diffie-Hellman (DDH) problem. ElGamal encryption can be defined over any cyclic group :math:`G`. Its security depends upon the difficulty of a certain problem in :math:`G` related to computing discrete logarithms. We implement El Gamal over a Dlog Group :math:`(G, q, g)` where :math:`q` is the order of group :math:`G` and :math:`g` is the generator.

ElGamal encryption scheme can encrypt a group element and a byte array. The general case that accepts a message that should be encrypted usually uses the encryption on a byte array, but in other cases there are protocols that do multiple calculations and might want to keep working on a close group. For those cases we provide encryption on a group element.

In order to allow these two encryption types, we provide two ElGamal concrete classes. One implements the encrypt function on a group element and is called `ElGamalOnGroupElementEnc`, and the other one implements the encrypt function on a byte array and is called `ElGamalOnByteArrayEnc`.

.. note:: Note that ElGamal on a groupElement is an asymmetric multiplicative homomorphic encryption, while ElGamal on a ByteArray is not.

ElGamalEnc abstract class
~~~~~~~~~~~~~~~~~~~~~~~~~

.. cpp:class:: ElGamalEnc : public AsymmetricEnc

   General class for El Gamal encryption scheme. Every concrete implementation of ElGamal should derive this class. By definition, this encryption scheme is CPA-secure and Indistinguishable.


ElGamalOnByteArrayEnc class
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. cpp:class:: ElGamalOnByteArrayEnc : public ElGamalEnc

   This class performs the El Gamal encryption scheme that perform the encryption on a ByteArray. The general encryption of a message usually uses this type of encryption. By definition, this encryption scheme is CPA-secure and Indistinguishable.

Constructors
^^^^^^^^^^^^

.. cpp:function:: ElGamalOnByteArrayEnc::ElGamalOnByteArrayEnc()

   Default constructor. Uses the default implementations of DlogGroup and KDF.

.. cpp:function:: ElGamalOnByteArrayEnc::ElGamalOnByteArrayEnc(const shared_ptr<DlogGroup> & dlogGroup, const shared_ptr<KeyDerivationFunction> & kdf, const shared_ptr<PrgFromOpenSSLAES> & random)

   Constructor that gets a DlogGroup and source of randomness.

   :param dlogGroup: must be DDH secure.
   :param kdf: a key derivation function.
   :param random: source of randomness

Complete Encryption
^^^^^^^^^^^^^^^^^^^

.. cpp:function:: shared_ptr<AsymmetricCiphertext> ElGamalOnByteArrayEnc::completeEncryption(const shared_ptr<GroupElement> & c1, GroupElement* hy, Plaintext* plaintext)

   This is a protected function. It completes the encryption operation.

   :param plaintext: contains message to encrypt. MUST be of type ByteArrayPlaintext.
   :return: Ciphertext of type ElGamalOnByteArrayCiphertext containing the encrypted message.

ElGamalOnGroupElementEnc class
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. cpp:class:: ElGamalOnGroupElementEnc : public ElGamalEnc, public AsymMultiplicativeHomomorphicEnc

   This class performs the El Gamal encryption scheme that perform the encryption on a GroupElement.

   In some cases there are protocols that do multiple calculations and might want to keep working on a close group. For those cases we provide encryption on a group element. By definition, this encryption scheme is CPA-secure and Indistinguishable.

Constructors
^^^^^^^^^^^^

.. cpp:function:: ElGamalOnGroupElementEnc::ElGamalOnGroupElementEnc()

   Default constructor. Uses the default implementations of DlogGroup and random.

.. cpp:function:: ElGamalOnGroupElementEnc::ElGamalOnGroupElementEnc(const shared_ptr<DlogGroup> & dlogGroup, const shared_ptr<PrgFromOpenSSLAES> & random)

   Constructor that gets a DlogGroup and source of randomness.

   :param dlogGroup: must be DDH secure.
   :param random: source of randomness.

Complete Encryption
^^^^^^^^^^^^^^^^^^^

.. cpp:function:: shared_ptr<AsymmetricCiphertext> ElGamalOnGroupElementEnc::completeEncryption(const shared_ptr<GroupElement> & c1, GroupElement* hy, Plaintext* plaintext)

   This is a protected function. It completes the encryption operation.

   :param plaintext: contains message to encrypt. MUST be of type GroupElementPlaintext.
   :return: Ciphertext of type ElGamalOnGroupElementCiphertext containing the encrypted message.

Multiply Ciphertexts (Homomorphic Encryption operation)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. cpp:function:: shared_ptr<AsymmetricCiphertext> ElGamalOnGroupElementEnc::multiply(AsymmetricCiphertext* cipher1, AsymmetricCiphertext* cipher2)

   Calculates the ciphertext resulting of multiplying two given ciphertexts. Both ciphertexts have to have been generated with the same public key and DlogGroup as the underlying objects of this ElGamal object.

   :return: Ciphertext of the multiplication of the plaintexts p1 and p2 where alg.encrypt(p1)=cipher1 and alg.encrypt(p2)=cipher2

.. cpp:function:: shared_ptr<AsymmetricCiphertext> ElGamalOnGroupElementEnc::multiply(AsymmetricCiphertext* cipher1, AsymmetricCiphertext* cipher2, biginteger & r)

   Calculates the ciphertext resulting of multiplying two given ciphertexts using the given random value r. Both ciphertexts have to have been generated with the same public key and DlogGroup as the underlying objects of this ElGamal object.

   :return: Ciphertext of the multiplication of the plaintexts p1 and p2 where alg.encrypt(p1)=cipher1 and alg.encrypt(p2)=cipher2

Basic Usage
~~~~~~~~~~~

Sender usage:

.. code-block:: cpp

    shared_ptr<DlogGroup> dlog = make_shared<OpenSSLDlogECF2m>();
    //Create an ElGamalOnGroupElement encryption object.
    ElGamalOnGroupElementEnc elGamal(dlog);
    
    //Generate a keyPair using the ElGamal object.
    auto pair = elGamal.generateKey();
    
    //Publish your public key.
    Publish(pair.first);
    
    //Set private key and party2's public key: 
    elGamal.setKey(party2PublicKey, pair.second);
    
    //Create a GroupElementPlaintext to encrypt and encrypt the plaintext.
    GroupElementPlaintext plaintext(dlog->createRandomElement()); 
    AsymmetricCiphertext cipher = elGamal.encrypt(plaintext); 
    
    //Sends cipher to the receiver.
    
Receiver usage:

.. code-block:: cpp

    //Create an ElGamal object with the same DlogGroup definition as party1. 
    //Generate a keyPair using the ElGamal object.
    auto pair = elGamal.generateKey();
    
    //Publish your public key.
    Publish(pair.first);
    
    //Set private key and party1's public key: 
    elGamal.setKey(party1PublicKey, pair.second);
    
    //Get the ciphertext and decrypt it to get the plaintext. 
    ...
    shared_ptr<Plaintext> plaintext = elGamal.decrypt(cipher);
    
    //Get the plaintext element and use it as needed.
    GroupElement element = ((GroupElementPlaintext*)plaintext.get()).getElement(); 
    ...

Cramer Shoup DDH Encryption Scheme
----------------------------------

The Cramer Shoup encryption scheme’s security is based on the hardness of the decisional Diffie-Hellman (DDH) problem, 
like El Gamal encryption scheme. Cramer Shoup encryption can be defined over any cyclic group :math:`G`. 
Its security depends upon the difficulty of a certain problem in :math:`G` related to computing discrete logarithms. 

We implement Cramer Shoup over a Dlog Group :math:`(G, q, g)` where :math:`q` is the order of group :math:`G` and :math:`g` is the generator.

In contrast to El Gamal, which is extremely malleable, Cramer–Shoup adds other elements to ensure non-malleability even against a resourceful attacker. This non-malleability is achieved through the use of a hash function and additional computations, resulting in a ciphertext which is twice as large as in El Gamal.

Similary to ElGamal, Cramer Shoup encryption scheme can encrypt a group element and a byte array. libscapi only provides the group element version.

The CramerShoupOnGroupElementEnc class
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. cpp:class:: CramerShoupOnGroupElementEnc :public AsymmetricEnc, Cca2

   Implementation of CramerShoup encryption scheme over group elements.

.. cpp:function:: ::CramerShoupOnGroupElementEnc::CramerShoupOnGroupElementEnc(const shared_ptr<DlogGroup> & dlogGroup, const shared_ptr<CryptographicHash> & hash, const shared_ptr<PrgFromOpenSSLAES> & random)

   Constructor that lets the user choose the underlying dlog, hash and random.

   :param dlogGroup: underlying DlogGroup to use, it has to have DDH security level
   :param hash: underlying hash to use, has to have CollisionResistant security level
   :param random: source of randomness.

Basic Usage
~~~~~~~~~~~

Sender usage:

.. code-block:: cpp

    //Create an underlying DlogGroup.
    shared_ptr<DlogGroup> dlog = make_shared<OpenSSLDlogECF2m>();
    
    //Create a CramerShoupOnByteArray encryption object.
    CramerShoupOnGroupElementEnc encryptor (dlog);
    
    //Generate a keyPair using the CramerShoup object.
    auto pair = encryptor.generateKey();
    
    //Publish your public key.
    Publish(pair.first);
    
    //Set private key and party2's public key: 
    encryptor.setKey(party2PublicKey, pair.second);
    
    //Get a vector message to encrypt. Check if the length of the given msg is valid.
    if (encryptor.hasMaxByteArrayLengthForPlaintext()){
        if (msg.size() > encryptor.getMaxLengthOfByteArrayForPlaintext()) {
    	    throw invalid_argument(“message too long”);
        }
    }
    
    //Generate a plaintext suitable to this CramerShoup object.
    auto plaintext = encryptor.generatePlaintext(msg);
    
    //Encrypt the plaintext
    auto cipher = encrypor.encrypt(plaintext);
    
    //Send cipher and keys to the receiver.

Receiver usage:

.. code-block:: cpp

    //Create a CramerShoup object with the same DlogGroup definition as party1. 
    //Generate a keyPair using the CramerShoup object.
    auto pair = encryptor.generateKey();
    
    //Publish your public key.
    Publish(pair.first);
    
    //Set private key and party1's public key: 
    encryptor.setKey(party1PublicKey, pair.second);
    
    //Get the ciphertext and decrypt it to get the plaintext. ...
    auto plaintext = encryptor.decrypt(cipher);
    
    //Get the plaintext element and use it as needed.
    GroupElement element = ((GroupElementPlaintext*)plaintext.get()).getElement(); 


Damgard Jurik Encryption Scheme
-------------------------------

Damgard Jurik is an asymmetric encryption scheme that is based on the Paillier encryption scheme. This encryption scheme is CPA-secure and Indistinguishable.

DamgardJurikEnc class 
~~~~~~~~~~~~~~~~~~~~~~

.. cpp:class:: DamgardJurikEnc : public AsymAdditiveHomomorphicEnc

   Damgard Jurik is an asymmetric encryption scheme based on the Paillier encryption scheme. By definition, this encryption scheme is CPA-secure and Indistinguishable.

.. cpp:function:: DamgardJurikEnc::DamgardJurikEnc(const shared_ptr<PrgFromOpenSSLAES> & random)

   Constructor that lets the user choose the source of randomness.

.. cpp:function:: shared_ptr<AsymmetricCiphertext> DamgardJurikEnc::reRandomize(AsymmetricCiphertext* cipher)
   
   This function takes an encryption of some plaintext (let's call it originalPlaintext) and returns a cipher that "looks" different but it is also an encryption of originalPlaintext.

Basic Usage
~~~~~~~~~~~

The code example below is used when the sender and receiver know the specific type of asymmetric encryption object.

Sender code:

.. code-block:: cpp

    //Create a DamgardJurik encryption object.
    DamgardJurikEnc encryptor;
    
    //Generate a keyPair using the DamgardJurik object.
    DJKeyGenParameterSpec spec(128, 40)
    auto pair = encryptor.generateKey(spec);
    
    //Publish your public key.
    Publish(pair.first);
    
    //Set private key and party2's public key: 
    encryptor.setKey(party2PublicKey, pair.second);
    
    //Get the biginteger value to encrypt, create a BigIntegerPlaintext with it and encrypt the plaintext.
    ...
    BigIntegerPlainText plaintext(num); 
    auto cipher = encryptor.encrypt(plaintext);
    
    //Send cipher and keys to the receiver.

Receiver code:

.. code-block:: cpp

    //Create a DamgardJurik object with the same definition as party1. 
    //Generate a keyPair using the DamgardJurik object.
    auto pair = encryptor.generateKey();
    
    //Publish your public key.
    Publish(pair.first);
    
    //Set private key and party1's public key: 
    encryptor.setKey(party1PublicKey, pair.second);
    
    //Get the ciphertext and decrypt it to get the plaintext. ...
    auto plaintext = elGamal.decrypt(cipher);
    
    //Get the plaintext element and use it as needed.
    biginteger element = ((BigIntegerPlainText)plaintext.get()).getX();

