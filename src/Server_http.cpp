// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <iostream>
#include <string>
#include <iostream>
#include <string>

#include "Server_http.hpp"
#include "json/src/jsonrpccpp/server/abstractserver.h"
#include "json/src/jsonrpccpp/common/exception.h"
#include "json/src/jsonrpccpp/server.h"

namespace SPHINXServer {

    JsonRpcServer::JsonRpcServer(jsonrpc::HttpServer &server)
        : jsonrpc::AbstractServer<jsonrpc::HttpServer>(server), httpServer(server) {}

    void JsonRpcServer::exampleMethod(const Json::Value &request, Json::Value &response) {
        // Process the JSON-RPC request and set the response
        response = Json::Value("Success");
    }

    void JsonRpcServer::startJsonRpcServer() {
        try {
            httpServer.SetHandler(this->handler);
            httpServer.StartListening();

            while (true) {
                httpServer.HandleRequests();
            }
        } catch (jsonrpc::JsonRpcException &e) {
            std::cerr << "JSON-RPC Exception: " << e.what() << std::endl;
        }
    }

} // namespace SPHINX

