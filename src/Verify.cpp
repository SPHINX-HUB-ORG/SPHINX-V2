// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The provided code defines a namespace SPHINXVerify that contains several functions for verifying the integrity and authenticity of SPHINX
// blocks and chains, as well as generating and verifying zero-knowledge proofs.

// sign_data: 
    // This function takes data as input (a vector of bytes) and a private key (a pointer to a byte array).
    // It uses the Crypto::sign function (assuming it is available from an inner namespace) to sign the 
    // data using the provided private key. After the data is signed, it calls 
    // SPHINXVerify::verify_sphinx_protocol to perform the verification of the SPHINX protocol. If the 
    // protocol verification succeeds (isVerified is true), the function returns the generated signature
    // as a string. If the verification fails, the function returns an empty string or handles the error
    // appropriately.

// verify_data: 
    // This function takes data (a vector of bytes), a signature (a string representing the signature), 
    // and a verifier public key (a vector of bytes) as input. It first uses the Crypto::verify function
    // to verify the signature of the data using the provided verifier public key. If the signature is 
    // valid (valid is true), the function proceeds with the verification of the SPHINX protocol by 
    // calling verify_sphinx_protocol. If both the signature and protocol verification are successful, 
    // the function returns true, indicating that the data is valid. Otherwise, it returns false.

// verify_sphinx_protocol: 
    // This function implements the verification process for the SPHINX protocol. It creates objects for
    // the SPHINXProver and SPHINXVerifier classes (assuming these classes are defined elsewhere). 
    // The protocol starts with the verifier sending an initial message using verifier.sendMessage(). 
    // The prover receives this message and responds with a message using prover.sendMessage(). 
    // This interaction continues until the verifier indicates that the protocol is done 
    // (verifier.doneInteracting() returns true). The final result of the verification is obtained by 
    // calling verifier.verify(), which returns true if the protocol is successfully completed.

// verifySPHINXBlock: 
    // This function takes a SPHINXBlock, a signature (a string), and a SPHINX_PublicKey as input. 
    // It first verifies the SPHINX protocol by calling verify_sphinx_protocol. If the protocol 
    // verification fails, the function returns false, indicating that the block is not valid. 
    // Otherwise, it proceeds to verify the integrity of the block by checking its signature using 
    // the provided public key. It uses the Crypto::verify function to verify the block's signature 
    // against the public key. If the signature is valid, the function returns true, indicating that 
    // the block is valid. Otherwise, it returns false.

// verifySPHINXChain: 
    // This function takes a SPHINXChain as input, which is a collection of SPHINXBlocks forming a chain.
    // It first verifies the SPHINX protocol by calling verify_sphinx_protocol. If the protocol 
    // verification fails, the function returns false. If the chain is empty (has zero length), 
    // the function considers it valid and returns true. Otherwise, it proceeds to verify the 
    // integrity of each block in the chain. It uses the verifySPHINXBlock function to verify the 
    // signature of each block. Additionally, it checks that the blocks are properly linked together 
    // by comparing the previous hash of each block with the hash of the previous block. 
    // If all blocks are verified and properly linked, the function returns true, indicating that the 
    // chain is valid. Otherwise, it returns false.

// This code utilizes the libstark protocol library and cryptographic techniques to verify SPHINX blocks and chains, verify signature and
// data as well as generate and verify zero-knowledge proofs.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



#include <iostream>
#include <string>
#include <vector>

#include "Lib/Libstark/src/protocols/protocol.hpp"
#include "Consensus/Contract.hpp"
#include "Sign.hpp"
#include "Chain.hpp"
#include "Block.hpp"
#include "Node.hpp"
#include "Verify.hpp"


namespace SPHINXVerify {
    // Function to sign data using the private key
    std::string sign_data(const std::vector<uint8_t>& data, const uint8_t* SPHINXPrivKey) {
        // Call the signing function from the Crypto namespace to sign the data
        std::string signature = Crypto::sign(data, SPHINXPrivKey);

        // After data is signed, verify it using the SPHINXKey::verify_sphinx_protocol function
        bool isVerified = verify_sphinx_protocol();

        if (isVerified) {
            // Return the generated signature
            return signature;
        } else {
            // If verification fails, return an empty string or handle the error accordingly
            return "";
        }
    }

    // Function to verify data (including signature verification)
    bool verify_data(const std::vector<uint8_t>& data, const std::string& signature, const std::vector<uint8_t>& verifier_SPHINXPubKey) {
        bool valid = Crypto::verify(data, signature, verifier_SPHINXPubKey);

        if (valid) {
            // If the signature is valid, continue with verification using the SPHINX protocol
            bool protocolValid = verify_sphinx_protocol();
            return protocolValid;
        }

        return false;
    }

    bool verify_sphinx_protocol() {
        // Create a SPHINXProver and SPHINXVerifier objects
        SPHINXProver prover;
        SPHINXVerifier verifier;

        // Call the sendMessage function from the verifier object to get the initial message
        libstark::Protocols::msg_ptr_t initialMessage = verifier.sendMessage();

        // Create a TranscriptMessage pointer and assign the initial message
        std::unique_ptr<libstark::Protocols::TranscriptMessage> msg = std::move(initialMessage);

        // Continue the interaction until the verifier is done
        while (!verifier.doneInteracting()) {
            // Send the message to the prover
            prover.receiveMessage(*msg);

            // Call the sendMessage function from the prover to get the response message
            libstark::Protocols::msg_ptr_t responseMessage = prover.sendMessage();

            // Move the response message to the TranscriptMessage pointer
            msg = std::move(responseMessage);

            // Send the message to the verifier
            verifier.receiveMessage(*msg);
        }

        // Verify the final result
        bool valid = verifier.verify();

        return valid;
    }

    // Function to verify the integrity of a block
    bool verifyBlock(const SPHINXBlock& block) {
        // Recalculate the hash of the block's header, including the Merkle root
        std::string calculatedHeaderHash = calculateBlockHeaderHash(block.getPreviousHash(), block.getMerkleRoot(), block.getTimestamp(), block.getNonce());

        // Compare the calculated hash with the Merkle root stored in the block's header
        if (calculatedHeaderHash == block.getHeaderHash()) {
            // If they match, the block's integrity is intact

            // Call the SPHINX protocol verification
            bool protocolValid = verify_sphinx_protocol();
            if (!protocolValid) {
                return false;
            }

            return true;
        } else {
            // Otherwise, the block has been tampered with
            return false;
        }
    }

    // Function to verify the integrity of the entire chain
    bool verifyChain(const SPHINXChain& chain) {
        size_t chainLength = chain.getChainLength();

        if (chainLength == 0) {
            // An empty chain is considered valid

            // Call the SPHINX protocol verification
            bool protocolValid = verify_sphinx_protocol();
            if (!protocolValid) {
                return false;
            }

            return true;
        }

        // Verify the integrity of each block in the chain
        for (size_t i = 0; i < chainLength; ++i) {
            const SPHINXBlock& currentBlock = chain.getBlockAt(i);

            // Verify the integrity of the current block
            bool blockVerified = verifyBlock(currentBlock);
            if (!blockVerified) {
                // Invalid block detected
                return false;
            }

            if (i > 0) {
                const SPHINXBlock& previousBlock = chain.getBlockAt(i - 1);
                if (currentBlock.getPreviousHash() != previousBlock.getHash()) {
                    // The blocks are not properly linked together
                    return false;
                }
            }
        }

        // All blocks have been verified, and the chain is valid
        return true;
    }

    // Function to verify the integrity of a block and its signature
    bool verifySPHINXBlock(const SPHINXBlock& block, const std::string& signature, const SPHINXPubKey& publickey) {
        // Verify the integrity of the block first (including SPHINX protocol verification)
        bool blockIntegrityVerified = verifyBlock(block);
        if (!blockIntegrityVerified) {
            return false;
        }

        // Verify the signature of the block using the provided signature and public key
        bool verified = Crypto::verify(block.getBlockHash(), signature, publickey);
        return verified;
    }

    // Function to verify the integrity of the entire chain, including block signatures
    bool verifySPHINXChain(const SPHINXChain& chain) {
        // Verify the integrity of the chain first (including SPHINX protocol verification)
        bool chainIntegrityVerified = verifyChain(chain);
        if (!chainIntegrityVerified) {
            return false;
        }

        size_t chainLength = chain.getChainLength();

        if (chainLength == 0) {
            // An empty chain is considered valid
            return true;
        }

        // Verify the integrity of each block in the chain, including their signatures
        for (size_t i = 0; i < chainLength; ++i) {
            const SPHINXBlock& currentBlock = chain.getBlockAt(i);

            // Verify the signature of the current block
            bool blockVerified = verifySPHINXBlock(currentBlock, currentBlock.getSignature(), currentBlock.getPublicKey());
            if (!blockVerified) {
                // Invalid block detected
                return false;
            }

            if (i > 0) {
                const SPHINXBlock& previousBlock = chain.getBlockAt(i - 1);
                if (currentBlock.getPreviousHash() != previousBlock.getHash()) {
                    // The blocks are not properly linked together
                    return false;
                }
            }
        }

        // All blocks have been verified, and the chain is valid
        return true;
    }
} // namespace SPHINXVerify
