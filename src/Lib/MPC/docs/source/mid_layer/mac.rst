Message Authentication Codes
============================

In cryptography, a Message Authentication Code (MAC) is a short piece of information used to authenticate a message and to provide integrity and authenticity assurances on the message. Integrity assurances detect accidental and intentional message changes, while authenticity assurances affirm the message's origin. libscapi currently provides only one implementation of message authentication codes: `HMAC`_.

.. contents::

The Mac abstract class
-----------------------

This is the general class for Mac. Every class in this family must derive this class.

.. cpp:class:: Mac

Basic Mac and Verify Functionality
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. cpp:function:: vector<byte> Mac::mac(const vector<byte> &msg, int offset, int msgLen)

   Computes the mac operation on the given msg and return the calculated tag.

   :param msg: the message to operate the mac on.
   :param offset: the offset within the message vector to take the bytes from.
   :param msgLen: the length of the message in bytes.
   :return: vector<byte> the return tag from the mac operation.

.. cpp:function:: bool Mac::verify(const vector<byte> &msg, int offset, int msgLength, vector<byte>& tag)

   Verifies that the given tag is valid for the given message.

   :param msg: the message to compute the mac on to verify the tag.
   :param offset: the offset within the message array to take the bytes from.
   :param msgLength: the length of the message in bytes.
   :param tag: the tag to verify.
   :return: true if the tag is the result of computing mac on the message. false, otherwise.

Calulcating the Mac when not all the message is known up front
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. cpp:function:: void Mac::update(vector<byte> & msg, int offset, int msgLen)

   Adds the byte array to the existing message to mac.

   :param msg: the message to add.
   :param offset: the offset within the message array to take the bytes from.
   :param msgLen: the length of the message in bytes.

.. cpp:function:: void Mac::doFinal(vector<byte> & msg, int offset, int msgLength, vector<byte> & tag_res)

   Completes the mac computation and puts the result tag in the tag array.

   :param msg: the end of the message to mac.
   :param offset: the offset within the message array to take the bytes from.
   :param msgLength: the length of the message in bytes.
   :return: the result tag from the mac operation.

Key Handling
~~~~~~~~~~~~

.. cpp:function:: SecretKey Mac::generateKey(int keySize)

   Generates a secret key to initialize this mac object.

   :param keySize: is the required secret key size in bits.
   :return: the generated secret key.

.. cpp:function:: SecretKey Mac::generateKey(AlgorithmParameterSpec & keyParams)

   Generates a secret key to initialize this mac object.

   :param keyParams: algorithmParameterSpec contains parameters for the key generation of this mac algorithm.
   :return: the generated secret key.

.. cpp:function:: bool Mac::isKeySet()

   An object trying to use an instance of mac needs to check if it has already been initialized.

   :return: true if the object was initialized by calling the function setKey.

.. cpp:function:: void Mac::setMacKey(SecretKey & secretKey)

   Sets the secret key for this mac. The key can be changed at any time.

   :param secretKey: secret key

Mac Properties
~~~~~~~~~~~~~~

.. cpp:function:: int Mac::getMacSize()

   Returns the input block size in bytes.

   :return: the input block size.

.. _`HMAC`:

HMAC
----

We presented the same HMAC algorithm in the first layer of libscapi. However, there it was only presented as a PRF. In order to make HMAC become also a MAC and not just a PRF, all we have to do is to derive the Mac class. This means that now our HMAC needs to know how to mac and verify. HMAC is a mac that does not require knowing the length of the message in advance.

The Hmac class
~~~~~~~~~~~~~~~

Hmac is a Marker interface. Every class that implements it is signed as Hmac. Hmac has varying input length and thus implements the interface PrfVaryingInputLength. Currenty the ``BcHMAC`` class implements the ``Hmac`` interface.

.. cpp:class:: Hmac : public virtual PrfVaryingInputLength, public virtual UniqueTagMac, public virtual UnlimitedTime

Basic Usage
~~~~~~~~~~~

Sender usage:

.. code-block:: cpp

    //Create an hmac object.
    OpenSSLHMAC hmac("SHA-1");
    
    //Generate a SecretKey
    Hmac.generateKey(128);
    
    //Set the secretKey.
    hmac.setKey(secretKey);
    
    //Get the message to mac and calculate the mac tag.
    auto tag = hmac.mac(msg, offset, length); 
    
    //Send the msg and tag to the receiver.
    ...

Receiver usage:

.. code-block:: cpp

    //Get secretKey, msg and tag byte arrays.
    ...
    //Create the same hmac object as the sender’s hmac object and set the key. 
    ...
    // receive the message and the tag
    ...
    // Verify the tag with the given msg.
    If (hmac.verify(tag, msg, offset, length)) { //Tag is valid.
        //Continue working...
    } else return ERROR; //Tag is not valid.
