// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINX_HTTP_SERVER_HPP
#define SPHINX_HTTP_SERVER_HPP

#include <string>

namespace SPHINX {
    void startHttpServer();
    std::string processHttpRequest(const std::string& request);
} // namespace SPHINX

#endif // SPHINX_HTTP_SERVER_HPP
