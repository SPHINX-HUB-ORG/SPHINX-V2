// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.



#ifndef SCRIPT_H
#define SCRIPT_H

#include <string>
#include <vector>
#include <stack>

enum class Opcode {
    OP_CURVE25519_KEYPAIR,
    OP_KYBER768_KEYPAIR,
    OP_HYBRID_ENCRYPT,
    OP_HYBRID_DECRYPT,
    OP_SWIFFTX_HASH,
    OP_BLAKE3_HASH,
    OP_SPHINCS_PLUS_SIGN,
    OP_SPHINCS_PLUS_VERIFY
    // Add more opcodes as needed
};

class ScriptInterpreter {
public:
    bool executeScript(const std::vector<Opcode>& script);

private:
    std::stack<bool> stack;
    AddressValidator addressValidator;
    EncryptionSystem encryptionSystem;

    // Implement opcode execution functions here

    void opCurve25519Keypair();
    void opKyber768Keypair();
    void opHybridEncrypt();
    void opHybridDecrypt();
    void opSwifftxHash();
    void opBlake3Hash();
    void opSphincsPlusSign();
    void opSphincsPlusVerify();
};

#endif
