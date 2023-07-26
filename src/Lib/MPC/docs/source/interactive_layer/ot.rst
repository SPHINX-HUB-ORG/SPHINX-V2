Oblivious Transfer Protocols
============================

In Oblivious Transfer, a party called **the sender** has :math:`n` messages, and a party called **the receiver** has an index :math:`i`. 
The receiver wishes to receive the :math:`i^{th}` message of the sender, without the sender learning :math:`i`, 
while the sender wants to ensure that the receiver receives only one of the :math:`n` messages.

.. contents::

Class Hierarchy
---------------

The general structure of OT protocols contains three components:

* Sender and receiver abstract classes
* Sender and receiver concrete classes

abstract classes
~~~~~~~~~~~~~~~~

Both Sender and Receiver abstract classes declare the ``transfer()`` function, which executes the OT protocol. The ``transfer()`` function of the sender runs the protocol from the sender's point of view, while the transfer function of the receiver runs the protocol from the receiver's point of view. 
There are two types of abstract classes. One is for the regular OT case and the other for the batch OT case .

In the regular OT case, both transfer functions accept two parameters:

* A channel that is used to send and receive messages during the protocol execution.
* An input object that holds the required parameter to the sender/receiver execution.

In the batch OT case, the transfer functions accept just the input object, since all concrete implementations use their own communication rether than libscapi's channel.

The input types are ``OTSInput`` and ``OTRInput`` for the regular case, and ``OTBatchSInput`` and ``OTBatchRInput`` for the batch case. These are abstract classes for the sender's and receiver's input, respectively. Each concrete implementation may have some different parameters and should implement a dedicated input class that holds them.
The transfer functions of the sender and the receiver differ in their return value. In the regular case, the sender's transfer function returns void, and the receiver's transfer function returns ``OTROutput``. In the batch case, the sender's transfer function returns ``OTBatchSOutput``, and the receiver's transfer function returns ``OTBatchROutput``. All types of output are abstract classes and work as marker classes. Each concrete OT receiver should implement a dedicated output class that holds the necessary output objects.

The OTSender abstract class 
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. cpp:class:: OTSender

.. cpp:function:: void OTSender::transfer(CommParty* channel, OTSInput* input)

   The transfer stage of OT protocol which can be called several times in parallel.
   The OT implementation support usage of many calls to transfer, with single preprocess execution.
   This way, one can execute multiple OTs by creating the OT sender once and call the transfer function for each input couple.
   In order to enable parallel calls, each transfer call should use a different channel to send and receive messages. This way the parallel executions of the function will not block each other.

   :param channel: each call should get a different one.
   :param input: The parameters given in the input must match the DlogGroup member of this class, which given in the constructor.

The OTReciever abstract class
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. cpp:class:: OTReceiver

.. cpp:function:: shared_ptr<OTROutput> OTReceiver::transfer(CommParty* channel, OTRInput* input)

   The transfer stage of OT protocol which can be called several times in parallel.
   The OT implementation support usage of many calls to transfer, with single preprocess execution.
   This way, one can execute multiple OT by creating the OT receiver once and call the transfer function for each input couple.
   In order to enable parallel calls, each transfer call should use a different channel to send and receive messages. This way the parallel executions of the function will not block each other.

   :param channel: each call should get a different one.
   :param input: The parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
   :return: OTROutput, the output of the protocol.

The OTBatchSender abstract class 
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. cpp:class:: OTBatchSender

.. cpp:function:: shared_ptr<OTBatchSOutput> OTBatchSender::transfer(OTBatchSInput * input)

   The transfer stage of OT protocol which does mulptiple OTs in parallel.

   :param input: The parameters used in the 

The OTBatchReceiver abstract class
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. cpp:class:: OTBatchReceiver

.. cpp:function:: shared_ptr<OTBatchROutput> OTBatchReceiver::transfer(OTBatchRInput * input)

   The transfer stage of OT protocol which does mulptiple OTs in parallel.
   
   :param input: The parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
   :return: OTROutput, the output of the protocol.


The Input/Output Interfaces
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Every OT sender and receiver need inputs during the protocol execution, but every concrete protocol needs different inputs.
The following classes are marker classes for regular and batch OT sender/receiver inputs, where there is an implementing class for each OT protocol.

.. cpp:class:: OTSInput

.. cpp:class:: OTRInput

.. cpp:class:: OTBatchSInput

.. cpp:class:: OTBatchRInput

  
Similar, every regular OT receiver and every batch sender and receiver outputs a result in the end of the protocol execution, but every concrete protocol output different data.
The following classes are marker classes for OT output, where there is an implementing class for each OT protocol.
 
.. cpp:class:: OTROutput

.. cpp:class:: OTBatchSOutput

.. cpp:class:: OTBatchROutput

   
Concrete implementations
~~~~~~~~~~~~~~~~~~~~~~~~

As we have already said, each concrete OT implementation should implement dedicated sender and receiver classes. These classes implement the functionalities that are unique for the specific implementation. Most OT protocols can work on two different types of inputs: byte arrays and DlogGroup elements. Each input type should be treated differently, thus we decided to have concrete sender/receiver classes for each input option.

Concrete *regular* OT implemented so far are:

* Semi Honest
* Privacy Only
* One Sided Simulation
* Full Simulation
* Full Simulation – ROM
* UC


Concrete *batch* OT implemented so far are:

* Batch Semi Honest Extension. This is a wrapper of Michael Zohner's implementation.

* Batch Malicious Extension. There are two wrappers: One wraps the Michael Zohner's implementation and the other wraps the Bristol's implementation.

Basic Usage
-----------

In order to execute the OT protocol, both sender and receiver should be created as separate programs (Usually not on the same machine). 
The main function in the sender and the receiver is the transfer function, that gets the communication channel between them and input.

Steps in sender creation:

* Given a ``Channel`` object channel do:
* Create an ``OTSender`` (for example, ``OTSemiHonestDDHOnGroupElementSender``).
* Create input for the sender. Usually, the input for the receiver contains x0 and x1.
* Call the transfer function of the sender with channel and the created input.

.. code-block:: cpp

    //Creates the OT sender object.
    OTSemiHonestDDHOnGroupElementSender sender;
    
    //Creates input for the sender. 
    auto x0 = dlog.createRandomElement();
    auto x1 = dlog.createRandomElement();
    OTSOnGroupElementInput input(x0, x1);
    
    //call the transfer part of the OT protocol
    sender.transfer(&channel, &input);
    

Steps in receiver creation:

* Given a ``Channel`` object channel do:
* Create an ``OTReceiver`` (for example, ``OTSemiHonestDDHOnGroupElementReceiver``).
* Create input for the receiver. Usually, the input for the receiver contains only sigma parameter.
* Call the transfer function of the receiver with channel and the created input.

.. code-block:: cpp

    //Creates the OT receiver object.
    OTSemiHonestDDHOnGroupElementReceiver receiver;
    
    //Creates input for the receiver.
    byte sigma = 1; 
    OTRBasicInput input(sigma);
    
    OTROutput output = receiver.transfer(&channel, &input);
    //use output…
