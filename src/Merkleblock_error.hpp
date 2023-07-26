// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef MERKLEBLOCK_ERROR_HPP
#define MERKLEBLOCK_ERROR_HPP

#include <stdexcept>
#include <string>
#include "MerkleBlock.hpp"

class MerkleBlockException : public std::exception {
public:
    explicit MerkleBlockException(const std::string& message) : errorMessage(message) {}

    const char* what() const noexcept override {
        return errorMessage.c_str();
    }

private:
    std::string errorMessage;
};

#endif // MERKLEBLOCK_ERROR_HPP
