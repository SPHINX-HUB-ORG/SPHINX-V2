// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <iostream>
#include <string>
#include <iostream>

#include "Server_http.hpp"
#include "Requests.hpp"
#include "json/src/jsonrpccpp/server/abstractserver.h"
#include "json/src/jsonrpccpp/common/exception.h"
#include "json/src/jsonrpccpp/server.h"

namespace SPHINXServer {

    class JsonRpcServer : public jsonrpc::AbstractServer<jsonrpc::HttpServer> {
    public:
        JsonRpcServer(jsonrpc::HttpServer &server)
            : jsonrpc::AbstractServer<jsonrpc::HttpServer>(server), httpServer(server) {}

        // Define a method to handle JSON-RPC requests
        void handleJsonRpcRequest(const Json::Value &request, Json::Value &response) {
            // Process the JSON-RPC request and set the response
            response = SPHINXHttp::handleJsonRpcRequest(request);
        }

        void exampleMethod(const Json::Value &request, Json::Value &response) {
            // Process the JSON-RPC request and set the response
            response = Json::Value("Success");
        }

        void handleHttpRequest(const std::string &httpRequest) override {
            // Handle the incoming HTTP request here
            // We can process the request, perform JSON-RPC method execution, and send back the response
            // We can use httpRequest to extract the bridge address and perform the necessary operations

            // For this example, let's assume we received a JSON-RPC request
            // and we need to execute the 'exampleMethod' from this class.
            Json::CharReaderBuilder reader;
            Json::Value requestJson;
            Json::Value responseJson;

            std::istringstream is(httpRequest);
            std::string errors;
            if (Json::parseFromStream(reader, is, &requestJson, &errors)) {
                // Assuming you have already parsed the JSON-RPC request
                if (requestJson.isObject() && requestJson.isMember("method")) {
                    std::string methodName = requestJson["method"].asString();
                    if (methodName == "handleJsonRpcRequest") {
                        handleJsonRpcRequest(requestJson["params"], responseJson);
                    } else {
                        responseJson["error"] = "Unknown method";
                    }
                } else {
                    responseJson["error"] = "Invalid request";
                }

                // Construct an appropriate JSON-RPC response
                Json::Value jsonResponse;
                jsonResponse["jsonrpc"] = "2.0";
                jsonResponse["result"] = responseJson;
                jsonResponse["id"] = 1;

                // Send the JSON-RPC response
                std::string httpResponse = jsonrpc::StringifyJSON(jsonResponse);

                // Send the HTTP response back to the client
                // In this example, we'll use a basic socket approach
                try {
                    const std::string response = "HTTP/1.1 200 OK\r\n"
                                                "Content-Length: " + std::to_string(httpResponse.size()) + "\r\n"
                                                "Content-Type: application/json\r\n"
                                                "\r\n" +
                                                httpResponse;

                    httpServer.SendResponse(response);
                } catch (std::exception &e) {
                    std::cerr << "HTTP Response Sending Error: " << e.what() << std::endl;
                }
            }
        }

        void startJsonRpcServer() {
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

    private:
        jsonrpc::HttpServer &httpServer;
    };

} // namespace SPHINXServer
