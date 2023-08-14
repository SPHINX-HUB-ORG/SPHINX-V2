// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <iostream>
#include <string>
#include <iostream>

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

    void JsonRpcServer::handleHttpRequest(const std::string &httpRequest) {
        // Handle the incoming HTTP request here
        // You can process the request, perform JSON-RPC method execution, and send back the response
        // You can use httpRequest to extract the bridge address and perform the necessary operations
        
        // Construct an appropriate JSON-RPC response
        Json::Value jsonResponse;
        jsonResponse["jsonrpc"] = "2.0";
        jsonResponse["result"] = "Bridge created successfully!";
        jsonResponse["id"] = 1;
        
        // Send the JSON-RPC response
        std::string httpResponse = jsonrpc::StringifyJSON(jsonResponse);
        
        // Send the HTTP response back to the client
        // ...

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