// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef CHAINMANAGER_HPP
#define CHAINMANAGER_HPP

#include <string>
#include <unordered_map>
#include "chain.hpp"

class SPHINXChainManager {
public:
    SPHINXChainManager() = default;  // Default constructor

    // Create a new chain with the given name and main parameters
    void createChain(const std::string& chainName, const MainParams& mainParams) {
        SPHINXChain::Chain chain(mainParams);
        chains_[chainName] = chain;
    }

    // Get a reference to an existing chain by name
    SPHINXChain::Chain& getChain(const std::string& chainName) {
        auto it = chains_.find(chainName);
        if (it != chains_.end()) {
            return it->second;
        }
        throw std::runtime_error("Chain not found: " + chainName);
    }

    // Check if a chain with the given name exists
    bool chainExists(const std::string& chainName) const {
        return chains_.count(chainName) > 0;
    }

    // Delete a chain with the given name
    void deleteChain(const std::string& chainName) {
        auto it = chains_.find(chainName);
        if (it != chains_.end()) {
            chains_.erase(it);
        } else {
            throw std::runtime_error("Chain not found: " + chainName);
        }
    }

private:
    std::unordered_map<std::string, SPHINXChain::Chain> chains_;
};

#endif // CHAINMANAGER_HPP
