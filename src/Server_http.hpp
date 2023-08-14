// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINX_SERVER_HTTP_HPP
#define SPHINX_SERVER_HTTP_HPP

#include <string>
#include "json/src/jsonrpccpp/server/connectors/httpserver.h"
#include "json/src/jsonrpccpp/common/exception.h"
#include "json/src/jsonrpccpp/server.h"

namespace SPHINXServer {

    class JsonRpcServer : public jsonrpc::AbstractServer<jsonrpc::HttpServer> {
    public:
        JsonRpcServer(jsonrpc::HttpServer &server);
        virtual void exampleMethod(const Json::Value &request, Json::Value &response);

        void startJsonRpcServer();

    private:
        jsonrpc::HttpServer httpServer;
    };

} // namespace SPHINX

#endif // SPHINX_SERVER_HTTP_HPP

