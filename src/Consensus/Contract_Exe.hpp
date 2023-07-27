// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.



#ifndef SPHINX_CONTRACTEXE_HPP
#define SPHINX_CONTRACTEXE_HPP

#pragma once

#include <iostream>
#include <string>
#include <vector>
#include "Contract.hpp"

class SPHINX_ContractExe {
public:
    SPHINX_ContractExe();

    void enforceContractRules(const std::string& contractCode);

    void otherMemberFunction();

private:
    // Private member variables and functions (if any)
};

#endif // SPHINX_CONTRACTEXE_HPP

