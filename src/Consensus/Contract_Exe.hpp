/*
 *  Copyright (c) (2023) SPHINX_ORG
 *  Authors:
 *    - (C kusuma) <thekoesoemo@gmail.com>
 *      GitHub: (https://github.com/cahyaksm)
 *  Contributors:
 *    - (Contributor 1) <email1@example.com>
 *      Github: (https://github.com/yourgit)
 *    - (Contributor 2) <email2@example.com>
 *      Github: (https://github.com/yourgit)
 */



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

