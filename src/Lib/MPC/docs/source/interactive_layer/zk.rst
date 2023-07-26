Zero Knowledge Proofs and Zero Knowledge Proofs of Knowledge
============================================================

A **zero-knowledge proof** or a zero-knowledge protocol is a method by which one party (the prover) can prove to another party (the verifier) that a given statement is true, without conveying any additional information apart from the fact that the statement is indeed true. A **zero-knowledge proof of knowledge (ZKPOK)** is a sub case of zero knowledge proofs, in which the prover proves to the verifier that he knows how to prove a statement, without actually proving it.

.. contents::

Zero Knowledge abstract classes
-------------------------------

ZKProver
~~~~~~~~

The ``ZKProver`` abstract class declares the ``prove()`` function that accepts an input and runs the ZK proof. The input type is ``ZKProverInput``, which is a marker class. Every concrete protocol should have a dedicated input class that extends it.

.. cpp:class:: ZKProver

   A zero-knowledge proof or zero-knowledge protocol is a method by which one party (the prover) can prove to another party (the verifier) that a given statement is true, 
   without conveying any additional information apart from the fact that the statement is indeed true.

   This is a general class that simulates the prover side of the Zero Knowledge proof. Every class that derive this class is signed as Zero Knowledge prover.

.. cpp:function:: void ZKProver::prove(const shared_ptr<ZKProverInput> & input)

   Runs the prover side of the Zero Knowledge proof.

   :param input: holds necessary values to the proof calculations.

ZKVerifier
~~~~~~~~~~

The ``ZKVerifier`` abstract class declares the ``verify()`` function that accepts an input and runs the ZK proof verification. The input type is ``ZKCommonInput``, which is a marker class of inputs that are common for the prover and the verifier. Every concrete protocol should have a dedicated input class that extends it.

.. cpp:class:: ZKVerifier

   A zero-knowledge proof or zero-knowledge protocol is a method by which one party (the prover) can prove to another party (the verifier) that a given statement is true, 
   without conveying any additional information apart from the fact that the statement is indeed true.

   This is a general class that simulates the verifier side of the Zero Knowledge proof. Every class that derive this class is signed as Zero Knowledge verifier.

.. cpp:function:: bool ZKVerifier::verify(ZKCommonInput* input, const shared_ptr<SigmaProtocolMsg> & emptyA, const shared_ptr<SigmaProtocolMsg> & emptyZ)

   Runs the verifier side of the Zero Knowledge proof.

   :param input: holds necessary values to the varification calculations.
   :return: true if the proof was verified; false, otherwise.

ZKProverInput
~~~~~~~~~~~~~

.. cpp:class:: ZKProverInput

   Marker class. Each concrete ZK prover's input class should derive this class.

ZKCommonInput
~~~~~~~~~~~~~

.. cpp:class:: ZKCommonInput

   This is a marker class for Zero Knowledge input, where there is an implementing class for each concrete Zero Knowledge protocol.

Zero Knowledge Proof of Knowledge classes
-----------------------------------------

``ZKPOKProver`` and ``ZKPOKVerifier`` are marker classes that extend the ``ZKProver`` and ``ZKVerifier`` classes. ZKPOK concrete protocol should extend these marker classes instead of the general ZK classes.

.. cpp:class:: ZKPOKProver : public ZKProver

   This is a general class that simulates the prover side of the Zero Knowledge proof of knowledge.
   Every class that derive it is signed as ZKPOK prover.

.. cpp:class:: ZKPOKVerifier : public virtual ZKVerifier

   This is a general class that simulates the verifier side of the Zero Knowledge proof of knowledge.
   Every class that derive it is signed as ZKPOK verifier.

Implemented Protocols
---------------------

Concrete Zero Knowledge protocols implemented so far are:

* Zero Knowledge from any sigma protocol
* Zero Knowledge Proof of Knowledge from any sigma protocol (currently implemented using Pedersen Commitment scheme)
* Zero Knowledge Proof of Knowledge from any sigma protocol Fiat Shamir (Random Oracle Model)

Example of Usage
----------------

Steps in prover creation:

* Given a Channel object channel and input for the underlying SigmaProverComputation (in the following case, h and x) do:

  * Create a SigmaProverComputation (for example, SigmaDlogProverComputation).
  * Create a ZKProver with channel and the proverComputation (ForExample, ZKFromSigmaProver).
  * Create input object for the prover.
  * Call the prove function of the prover with the input.

Prover code example:

.. code-block:: cpp

   //create the ZK prover
   auto dlog = make_shared<OpenSSLDlogECF2m>("K-233");
   ZKFromSigmaProver prover(channel, make_shared<SigmaDlogProverComputation>(dlog, 40, get_seeded_prg()));
    
   //create the input for the prover
   shared_ptr<SigmaDlogProverInput> input = make_shared<SigmaDlogProverInput>(h, x);
        
   //Call prove function
   prover.prove(input);
    
Steps in verifier creation:

* Given a Channel object channel and input for the underlying SigmaVerifierComputation (In the example below, h) do:

  * Create a SigmaVerifierComputation (for example, SigmaDlogVerifierComputation).
  * Create a ZKVerifier with channel and verifierComputation (For example, ZKFromSigmaVerifier).
  * Create input object for the verifier. 
  * Call the verify function of the verifier with the input.

Verifier code example:

.. code-block:: cpp
  
    //create the ZK prover
   auto dlog = make_shared<OpenSSLDlogECF2m>("K-233");
    ZKFromSigmaVerifier verifier(channel, make_shared<SigmaDlogVerifierComputation>(dlog, 40, get_seeded_prg()), get_seeded_prg());

    //create the input for the verifier
    shared_ptr<SigmaDlogCommonInput> input = make_shared<SigmaDlogCommonInput>(h);
    
    //Call verify function
    cout << verifier.verify(input) << endl;
        

