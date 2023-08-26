// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef VERIFY_HPP
#define VERIFY_HPP

#include <iostream>
#include <string>
#include <vector>
#include "Block.hpp"
#include "Chain.hpp"

namespace SPHINXVerify {

    std::string sign_data(const std::vector<uint8_t>& data, const uint8_t* SPHINXPrivKey);

    bool verify_data(const std::vector<uint8_t>& data, const std::string& signature, const std::vector<uint8_t>& verifier_SPHINXPubKey);

    bool verify_sphinx_protocol();

    bool verifyBlock(const SPHINXBlock& block);

    bool verifyChain(const SPHINXChain& chain);

    bool verifySPHINXBlock(const SPHINXBlock& block, const std::string& signature, const SPHINXPubKey& publickey);

    bool verifySPHINXChain(const SPHINXChain& chain);

} // namespace SPHINXVerify

#endif // SPHINX_VERIFY_HPP
