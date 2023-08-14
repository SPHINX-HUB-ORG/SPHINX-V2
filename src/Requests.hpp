// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.

#ifndef SPHINX_HTTP_HPP
#define SPHINX_HTTP_HPP

#include <string>
#include <vector>
#include "json.hpp"
#include "Server_http.hpp"

namespace SPHINXHttp {
    // Function declarations
    json sendTransaction(const Transaction &transaction)
    nlohmann::json getSPHINXChainFromNodes(const std::vector<int>& listOfNodes);
    void sendNewSPHINXChain(const std::vector<int>& listOfNodes, const std::string& json);
    void addSelfToNetwork(const std::vector<int>& listOfNodes, int port);
    nlohmann::json handleJsonRpcRequest(const nlohmann::json& request);
    nlohmann::json handleGetBlockHeight(const nlohmann::json& params);
    nlohmann::json handleGetTransactionDetails(const nlohmann::json& params);
    nlohmann::json handleSendTransaction(const nlohmann::json& params);
} // namespace SPHINXHttp

#endif // SPHINX_HTTP_HPP
