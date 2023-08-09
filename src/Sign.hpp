// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.



#ifndef SPHINX_SIGN_HPP
#define SPHINX_SIGN_HPP

#pragma once

#include <string>
#include <vector>
#include <iostream>
#include <map>
#include <memory>

#include <vector>
#include <string>
#include <iostream>
#include "json.hpp"
#include "Sphincs.hpp"

using json = nlohmann::json;

constexpr int SPHINCS_N = 256;
constexpr int SPHINCS_H = 128;
constexpr int SPHINCS_D = 64;
constexpr int SPHINCS_A = 32;
constexpr int SPHINCS_K = 16;
constexpr int SPHINCS_W = 8;
constexpr int SPHINCS_V = 4;

using SPHINXPubKey = std::vector<unsigned char>;
using SPHINXPrivKey = std::vector<unsigned char>;

namespace SPHINXSign {

    std::string extractTransactionData(const std::string& signedTransaction);

    std::string signTransactionData(const std::string& transactionData, const SPHINXPrivKey& privateKey);

    SPHINXPubKey extractPublicKey(const std::string& signedTransaction);

    void addSignedTransactionToMerkleTree(const std::string& signedTransaction, const uint8_t* SPHINXPrivKey);

    bool verify_data(const std::vector<uint8_t>& data, const std::string& signature, const SPHINXPubKey& publicKey);

    bool verifySPHINXBlock(const Block& block, const std::string& signature, const SPHINXPubKey& publicKey);

    bool verifySPHINXChain(const Chain& chain);

} // namespace SPHINXSign

#endif // SPHINX_SIGN_HPP
