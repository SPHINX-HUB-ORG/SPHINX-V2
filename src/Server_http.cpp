// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <iostream>
#include <string>
#include <iostream>
#include <string>
#include "Server_http.hpp"

#include <iostream>
#include <string>
#include "json/src/jsonrpccpp/server/abstractserver.h"
#include "json/src/jsonrpccpp/common/exception.h"
#include "json/src/jsonrpccpp/server.h"

namespace SPHINXServerHttp {

    class JsonRpcServer : public jsonrpc::AbstractServer<jsonrpc::HttpServer> {
    public:
        JsonRpcServer(jsonrpc::HttpServer &server) : jsonrpc::AbstractServer<jsonrpc::HttpServer>(server) {}

        // Define your JSON-RPC methods here
        virtual void exampleMethod(const Json::Value &request, Json::Value &response) {
            // Process the JSON-RPC request and set the response
            response = Json::Value("Success");
        }
    };

    void startJsonRpcServer() {
        try {
            jsonrpc::HttpServer httpServer(8080); // Change the port as needed
            JsonRpcServer server(httpServer);
            server.StartListening();

            while (true) {
                httpServer.HandleRequests();
            }
        } catch (jsonrpc::JsonRpcException &e) {
            std::cerr << "JSON-RPC Exception: " << e.what() << std::endl;
        }
    }
} // namespace SPHINX