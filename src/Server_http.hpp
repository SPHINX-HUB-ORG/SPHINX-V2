// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINX_SERVER_JSONRPCSERVER_HPP
#define SPHINX_SERVER_JSONRPCSERVER_HPP

#include <json/json.h>
#include <jsonrpccpp/server.h>
#include <jsonrpccpp/server/connectors/httpserver.h>
#include "SPHINXHttp.hpp"  // Include the necessary header for SPHINXHttp

namespace SPHINXServer {

    class JsonRpcServer : public jsonrpc::AbstractServer<jsonrpc::HttpServer> {
    public:
        JsonRpcServer(jsonrpc::HttpServer &server);

        void handleJsonRpcRequest(const Json::Value &request, Json::Value &response);

        void exampleMethod(const Json::Value &request, Json::Value &response);

        void handleHttpRequest(const std::string &httpRequest) override;

        void startJsonRpcServer();

    private:
        jsonrpc::HttpServer &httpServer;
    };

} // namespace SPHINXServer

#endif // SPHINX_SERVER_JSONRPCSERVER_HPP

