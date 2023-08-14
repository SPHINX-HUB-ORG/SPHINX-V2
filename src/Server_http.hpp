// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINX_SERVER_HTTP_HPP
#define SPHINX_SERVER_HTTP_HPP

#pragma once

#include <iostream>
#include <string>
#include <iostream>

namespace SPHINXServer {

    class JsonRpcServer : public jsonrpc::AbstractServer<jsonrpc::HttpServer> {
    public:
        JsonRpcServer(jsonrpc::HttpServer &server);
        virtual void exampleMethod(const Json::Value &request, Json::Value &response);

        // Add a new function to handle incoming HTTP requests
        void handleHttpRequest(const std::string &httpRequest);

        void startJsonRpcServer();

    private:
        jsonrpc::HttpServer httpServer;
    };

} // namespace SPHINX

#endif // SPHINX_SERVER_HTTP_HPP

