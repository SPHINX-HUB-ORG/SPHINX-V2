Sigma Protocols
===============

**Sigma Protocols** are a basic building block for Zero-knowledge proofs, Zero-Knowledge Proofs Of Knowledge and more. A sigma protocol is a 3-round proof, comprised of:

1. A first message from the prover to the verifier
2. A random challenge from the verifier
3. A second message from the prover.

Sigma Protocol can be executed as a standalone protocol or as a building block for another protocol, like Zero Knowledge proofs.
As a standalone protocol, Sigma protocol should execute the protocol as is, including the communication between the prover and the verifier.
As a building block for other protocols, Sigma protocol should only compute the prover's first and second messages and the verifier's challenge and verification. This is, in other words, the protocol functions without communication between the parties.

To enable both options, there is a separation between the communication part and the actual protocol computations.
The general structure of Sigma Protocol contains the following components:

* Prover, Verifier and Simulator generic classes.
* ProverComputation and VerifierComputation abstract classes.
* ProverComputation and VerifierComputation concrete classes (Specific to each protocol).

.. contents::

The Prover class
----------------

The ``SigmaProtocolProver`` class has two modes of operation:

1. Explicit mode - call processFirstMessage() to process the first message and afterwards call processSecondMessage() to process the second message.

2. Implicit mode - Call prove() function that calls the above two functions. This way is more easy to use since the user should not be aware of the order in which the functions must be called.

.. cpp:class:: SigmaProtocolProver

   General class for Sigma Protocol prover. 
   This class manages the communication functionality of all the sigma protocol provers.
   It sends the first message, receives the challenge from the prover and sends the second message.
   It uses SigmaProverComputation instance of a concrete sigma protocol to compute the actual messages.

   Sigma protocols are a basic building block for zero-knowledge, zero-knowledge proofs of knowledge and more.

   A sigma protocol is a 3-round proof, comprised of a first message from the prover to the verifier, a random challenge from the verifier and a second message from the prover.
   See Hazay-Lindell (chapter 6) for more information.

.. cpp:function: void SigmaProtocolProver::processFirstMsg(const shared_ptr<SigmaProverInput> & input)

   Processes the first step of the sigma protocol.
   It computes the first message and sends it to the verifier.

.. cpp:function:: void SigmaProtocolProver::processSecondMsg()

   Processes the second step of the sigma protocol.
   It receives the challenge from the verifier, computes the second message and then sends it to the verifier.

   **This is a blocking function!**

.. cpp:function:: void SigmaProtocolProver::prove(const shared_ptr<SigmaProverInput> & input)

   Runs the proof of this protocol.

   This function executes the proof at once by calling the above functions one by one.
   This function can be called when a user does not want to save time by doing operations in parallel.

The Verifier class
-------------------

The ``SigmaProtocolVerifier`` also has two modes of operation:

1. Explicit mode – call sampleChallenge() to sample the challenge, then sendChallenge() to receive the prover's first message and then call processVerify() to receive the prover's second message and verify the proof.

2. Implicit mode - Call verify() function that calls the above three functions. Same as the prove function of the prover, this way is much simpler, since the user should not know the order of the functions.

.. cpp:class:: SigmaProtocolVerifier

   General class for Sigma Protocol verifier. 
   This class manages the communication functionality of all the sigma protocol verifiers, such as send the challenge to the prover and receive the prover messages. 
   It uses SigmaVerifierComputation instance of a concrete sigma protocol to compute the actual calculations.

.. cpp:function:: vector<byte> SigmaProtocolVerifier::getChallenge()

   Returns the sampled challenge.

   :return: the challenge.

.. cpp:function:: bool SigmaProtocolVerifier::processVerify(SigmaCommonInput* input)

   Waits to the prover's second message and then verifies the proof.
   **This is a blocking function!**

   :return: true if the proof has been verified; false, otherwise.

.. cpp:function:: void SigmaProtocolVerifier::sampleChallenge()

   Samples the challenge for this protocol.

.. cpp:function:: void SigmaProtocolVerifier::sendChallenge()

   Waits for the prover's first message and then sends the chosen challenge to the prover.
   **This is a blocking function!**

.. cpp:function:: void SigmaProtocolVerifier::setChallenge(const vector<byte> & challenge)

   Sets the given challenge.

.. cpp:function:: bool SigmaProtocolVerifier::verify(SigmaCommonInput* input)

   Runs the verification of this protocol.

   This function executes the verification protocol at once by calling the following functions one by one.
   This function can be called when a user does not want to save time by doing operations in parallel.

   :return: true if the proof has been verified; false, otherwise.

The Simulator class
--------------------

The ``SigmaSimulator`` has two simulate() functions. Both functions simulate the sigma protocol. The difference between them is the source of the challenge; one function receives the challenge as an input argument, while the other samples a random challenge. Both simulate functions return ``SigmaSimulatorOutput`` object that holds the simulated a, e, z.

.. cpp:class:: SigmaSimulator

   General class for Sigma Protocol Simulator. The simulator is a probabilistic polynomial-time function, that on input x and challenge e outputs a transcript of the form (a, e, z) with the same probability distribution as transcripts between the honest prover and verifier on common input x.

.. cpp:function:: int SigmaSimulator::getSoundnessParam()

   Returns the soundness parameter for this Sigma simulator.

   :return: t soundness parameter

.. cpp:function:: shared_ptr<SigmaSimulatorOutput> SigmaSimulator::simulate(SigmaCommonInput* input, const vector<byte> & challenge)

   Computes the simulator computation.

   :return: the output of the computation - (a, e, z).

.. cpp:function:: shared_ptr<SigmaSimulatorOutput> SigmaSimulator::simulate(SigmaCommonInput* input)

   Chooses random challenge and computes the simulator computation.

   :return: the output of the computation - (a, e, z).

Computation classes
-------------------

The classes that operate the **actual** protocol phases derive the ``SigmaProverComputation`` and ``SigmaVerifierComputation`` abstract classes. SigmaProverComputation computes the prover's messages and SigmaVerifierComputation computes the verifier's challenge and verification. Each operation is done in a dedicated function.

In case that Sigma Protocol is used as a building block, the protocol which uses it will hold an instance of SigmaProverComputation or SigmaVerifierComputation and will call the required function. Each concrete sigma protocol should implement the computation classes.

SigmaProverComputation
~~~~~~~~~~~~~~~~~~~~~~

.. cpp:class:: SigmaProverComputation

   This abstract class manages the mathematical calculations of the prover side in the sigma protocol.
   It samples random values and computes the messages.

.. cpp:function:: shared_ptr<SigmaProtocolMsg> SigmaProverComputation::computeFirstMsg(const shared_ptr<SigmaProverInput> & input)

   Computes the first message of the sigma protocol.

.. cpp:function:: shared_ptr<SigmaProtocolMsg> SigmaProverComputation::computeSecondMsg(const vector<byte> & challenge)

   Computes the second message of the sigma protocol.

SigmaVerifierComputation
~~~~~~~~~~~~~~~~~~~~~~~~

.. cpp:class:: SigmaVerifierComputation

   This abstract class manages the mathematical calculations of the verifier side in the sigma protocol.
   It samples random challenge and verifies the proof.

.. cpp:function:: void SigmaVerifierComputation::sampleChallenge()

   Samples the challenge for this protocol.

.. cpp:function:: void SigmaVerifierComputation::setChallenge(const vector<byte> & challenge)

   Sets the given challenge.

.. cpp:function:: vector<byte> SigmaVerifierComputation::getChallenge()

   Returns the sampled challenge.

   :return: the challenge.

.. cpp:function:: bool SigmaVerifierComputation::verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z)

   Verifies the proof.

   :return: true if the proof has been verified; false, otherwise.

Supported Protocols
-------------------

Concrete Sigma protocols implemented so far are:

* Dlog
* DH
* Extended DH
* Pedersen commitment knowledge
* Pedersen committed value
* El Gamal commitment knowledge
* El Gamal committed value
* El Gamal private key
* El Gamal encrypted value
* Cramer-Shoup encrypted value
* Damgard-Jurik encrypted zero
* Damgard-Jurik encrypted value
* Damgard-Jurik product
* AND (of multiple statements)
* OR of two statements
* OR of multiple statements

Example of Usage
----------------

Steps in prover creation:

* Given a ``Channel`` object channel and input for the concrete Sigma protocol prover (In the example below, x and h) do:

  * Create a ``SigmaProverComputation`` (for example, ``SigmaDlogProverComputation``).
  * Create a ``SigmaProtocolProver`` with channel and the proverComputation.
  * Create input object for the prover. 
  * Call the ``prove()`` function of the prover with the input.

Prover code example:

.. code-block:: cpp

    //Creates the dlog group, use the koblitz curve.
    auto dlog = make_shared<OpenSSLDlogECF2m>("K-233");
    
    //Creates sigma prover computation.
    shared_ptr<SigmaProverComputation> proverComputation = make_shared<SigmaDlogProverComputation>(dlog, t, get_seeded_prg());

    //Create Sigma Prover with the given SigmaProverComputation.
    SigmaProver prover(channel, proverComputation); 
    
    //Creates input for the prover.
    shared_ptr<SigmaProverInput> input = make_shared<SigmaDlogProverInput>(h, w);
    
    //Calls the prove function of the prover.
    prover.prove(input);

Steps in verifier creation:

* Given a ``Channel`` object channel and input for the concrete Sigma protocol verifier (In the example below, h) do:

  * Create a ``SigmaVerifierComputation`` (for example, ``SigmaDlogVerifierComputation``).
  * Create a ``SigmaProtocolVerifier`` with channel and verifierComputation.
  * Create input object for the verifier. 
  * Call the ``verify()`` function of the verifier with the input.

Verifier code example:

.. code-block:: cpp

    //Creates the dlog group, use the koblitz curve.
    auto dlog = make_shared<OpenSSLDlogECF2m>("K-233");
    
    //Creates sigma verifier computation.
    shared_ptr<SigmaVerifierComputation> verifierComputation = make_shared<SigmaDlogVerifierComputation>(dlog, t, get_seeded_prg());
    
    //Creates Sigma verifier with the given SigmaVerifierComputation.
    SigmaVerifier verifier(channel, verifierComputation);
    
    // Creates input for the verifier.
    shared_ptr<SigmaCommonInput> input = make_shared<SigmaDlogCommonInput>(h);
    
    //Calls the verify function of the verifier.
    verifier.verify(input);
