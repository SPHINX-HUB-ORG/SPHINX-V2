// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef PROTOCOL_HPP__
#define PROTOCOL_HPP__

#pragma once

#include "languages/Bair/BairInstance.hpp"
#include "languages/Bair/BairWitness.hpp"
#include "languages/Acsp/AcspInstance.hpp"
#include "languages/Acsp/AcspWitness.hpp"
#include <algebraLib/FieldElement.hpp>
#include <vector>
#include <map>
#include <memory>
#include <iostream>
#include <string>

#include "../Verify.hpp"
#include "../Block.hpp"
#include "../Chain.hpp"
#include "../Sign.hpp"


namespace libstark {
namespace Protocols {

    // Transcript data related types
    class TranscriptMessage {
    public:
        virtual ~TranscriptMessage() {};
    };

    typedef std::unique_ptr<TranscriptMessage> msg_ptr_t;

    // Protocol parties definitions
    class PartieInterface {
    public:
        // Receive a message and return True if protocol finished
        virtual void receiveMessage(const TranscriptMessage& msg) = 0;

        // Send a message based on current internal state
        virtual msg_ptr_t sendMessage() = 0;

        virtual ~PartieInterface() {};
    };


    // Verifier class
    class verifierInterface : public PartieInterface {
    public:
        virtual ~verifierInterface() {};
        virtual bool doneInteracting() const = 0;
        virtual bool verify() const = 0;

        virtual size_t expectedCommitedProofBytes() const = 0;
        virtual size_t expectedSentProofBytes() const = 0;
        virtual size_t expectedQueriedDataBytes() const = 0;

        // Add the SPHINX verification methods
        virtual bool verifySPHINXBlock(const SPHINXBlock& block, const std::string& signature, const SPHINXPubKey& publickey) = 0;
        virtual bool verifySPHINXChain(const SPHINXChain& chain) = 0;

        virtual void fillResultsAndCommitmentRandomly() = 0;
    };


    // Prover class
    class ProverInterface : public PartieInterface {
    public:
        // Declare the necessary methods for the Prover

        virtual bool doneInteracting() const = 0;
        virtual bool verify() const = 0;

        virtual size_t expectedCommitedProofBytes() const = 0;
        virtual size_t expectedSentProofBytes() const = 0;
        virtual size_t expectedQueriedDataBytes() const = 0;

        // Add the SPHINX verification methods
        virtual bool verifySPHINXBlock(const SPHINXBlock& block, const std::string& signature, const SPHINXPubKey& publickey) = 0;
        virtual bool verifySPHINXChain(const SPHINXChain& chain) = 0;

        virtual void fillResultsAndCommitmentRandomly() = 0;
    };


    // The `ProverInterface` and `verifierInterface` do not include the "private key" because they are designed as abstraction interfaces for cryptographic protocols. These interfaces hide the specific implementation details, including any private keys, and provide a clean and secure way to interact with the protocol.

    // Including the private key in these interfaces would break the abstraction and expose sensitive information to the external code using these interfaces. Cryptographic protocols typically keep the private key hidden and only use it internally within their implementations.

    // In this specific case, the `SPHINXVerify` namespace contains functions that require a private key, such as `sign_data`. The implementations of the `verifierInterface` and `ProverInterface` interfaces handle the interaction with the `SPHINXVerify` functions internally, without exposing the private key to the outside world.

    // For example, in the methods `verifySPHINXBlock` and `verifySPHINXChain` of both `verifierInterface` and `ProverInterface`, the private key is used internally to call the appropriate `SPHINXVerify` functions for verification.

    // By keeping the private key hidden within the implementations of these interfaces, the security of the cryptographic protocol is maintained, and the users of these interfaces can securely interact with the verification and proving processes without having direct access to sensitive information.


    typedef std::map<size_t, std::vector<Algebra::FieldElement*>> queriesToInp_t;
    class IOPP_verifierInterface : public verifierInterface {
    public:
        virtual ~IOPP_verifierInterface() {};
        virtual const queriesToInp_t& queriesToInput() const = 0;
    };

    // Protocol execution algorithm
    bool executeProtocol(PartieInterface& prover, verifierInterface& verifier, const bool onlyVerifierData = false);

    bool executeProtocol(const BairInstance& instance, const BairWitness& witness, const unsigned short securityParameter, bool testBair = false, bool testAcsp = false, bool testPCP = false);
    void simulateProtocol(const BairInstance& instance, const unsigned short securityParameter);

    // Printouts
    namespace prn {
        void printBairInstanceSpec(const BairInstance& instance);
        void printAcspInstanceSpec(const AcspInstance& instance);
        void printAcspWitnessSpec(const AcspWitness& witness);
        void printAcspPairSpec(const AcspInstance& instance, const AcspWitness& witness);
    }

    // Sphinx Verify
    namespace SPHINXVerify {
        bool verifierImplementation::verifySPHINXBlock(const SPHINXBlock& block, const std::string& signature, const SPHINXPubKey& publickey) {
        // Call the SPHINXVerify::verifySPHINXBlock function
        bool blockVerified = SPHINXVerify::verifySPHINXBlock(block, signature, SPHINXPubKey);
        return blockVerified;
    }

    bool verifierImplementation::verifySPHINXChain(const SPHINXChain& chain) {
        // Call the SPHINXVerify::verifySPHINXChain function
        bool chainVerified = SPHINXVerify::verifySPHINXChain(chain);
        return chainVerified;
    }

    bool proverImplementation::verifySPHINXBlock(const SPHINXBlock& block, const std::string& signature, const SPHINXPubKey& publickey) {
        // Call the SPHINXVerify::verifySPHINXBlock function
        bool blockVerified = SPHINXVerify::verifySPHINXBlock(block, signature, SPHINXPubKey);
        return blockVerified;
    }

    bool proverImplementation::verifySPHINXChain(const SPHINXChain& chain) {
        // Call the SPHINXVerify::verifySPHINXChain function
        bool chainVerified = SPHINXVerify::verifySPHINXChain(chain);
        return chainVerified;
    }
} // namespace Sphinxverify
} // namespace Protocols
} // namespace libstark

#endif // ifndef PROTOCOL_HPP__
