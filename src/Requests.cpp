// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

#include "Node.hpp"
#include "Chain.hpp"
#include "SphinxJS/jsonrpcpp/include/json.hpp"
#include "SphinxJS/Sphinx.js"
#include "Requests.hpp"


namespace SPHINXHttp {

    using json = nlohmann::json;
    using HttpClient = SPHINX::Client<SPHINX::HTTP>;

    json sendTransaction(const Transaction &transaction) {
        json response = {
            {"jsonrpc", "2.0"},
            {"result", "Transaction sent successfully"},
            {"id", nullptr}
        };
        return response;
    }

    // Function to get the latest chain from the network and find the longest one
    json getSPHINXChainFromNodes(const vector<int>& listOfNodes) {
        cout << "Pinging nodes for chains...." << endl;
        vector<string> vect;
        for (const int port : listOfNodes) {
            cout << "--- pinging node " << port << endl;
            HttpClient client("localhost:" + to_string(port));
            try {
                auto req = client.request("GET", "/latestchain");
                vect.push_back(req->content.string());
            } catch (const SPHINXHttp::system_error& e) {
                cerr << "Client request error: " << e.what() << endl;
            }
        }

        // Find the biggest chain
        json biggest_SPHINXChain = json::parse(vect[0]);
        int max = 0;
        for (int i = 0; i < vect.size(); i++) {
            auto json_data = json::parse(vect[i]);
            if (max < json_data["length"].get<int>()) {
                max = json_data["length"].get<int>();
                biggest_SPHINXChain = json_data;
            }
        }
        return biggest_SPHINXChain;
    }

    // Function to send the new chain to the network
    void sendNewSPHINXChain(const vector<int>& listOfNodes, const string& json) {
        cout << "Sending new chain to the network...." << endl;
        for (const int port : listOfNodes) {
            cout << "--- sending to node " << port << endl;
            HttpClient client("localhost:" + to_string(port));
            try {
                auto req = client.request("POST", "/newchain", json);
                cout << "Node " << port << " Response: " << req->content.string() << endl;
            } catch (const SPHINXHttp::system_error& e) {
                cerr << "Client request error: " << e.what() << endl;
            }
        }
    }

    // Function to add self to the network
    void addSelfToNetwork(const vector<int>& listOfNodes, int port) {
        cout << "Sending port to all nodes" << endl;
        json j;
        j["port"] = port;
        for (const int nodePort : listOfNodes) {
            cout << "--- sending port to node " << nodePort << endl;
            HttpClient client("localhost:" + to_string(nodePort));
            try {
                auto req = client.request("POST", "/addnode", j.dump(3));
                cout << "Node " << nodePort << " Response: " << req->content.string() << endl;
            } catch (const SPHINXHttp::system_error& e) {
                cerr << "Client request error: " << e.what() << endl;
            }
        }
    }

    // Function to handle JSON-RPC requests
    json handleJsonRpcRequest(const json& request) {
        // Ensure the request is a valid JSON-RPC request
        if (!request.is_object() || !request.contains("jsonrpc") || !request.contains("method") || !request.contains("id")) {
            // Invalid JSON-RPC request
            json response = {
                {"jsonrpc", "2.0"},
                {"error", {"code", -32600}, "message", "Invalid request"},
                {"id", nullptr}
            };
            return response;
        }

        // Extract method name and parameters from the request
        std::string method = request["method"];
        json params = request.contains("params") ? request["params"] : json::object();

        // Route the request to the corresponding JSON-RPC method
        if (method == "getBlockHeight") {
            return handleGetBlockHeight(params);
        } else if (method == "getTransactionDetails") {
            return handleGetTransactionDetails(params);
        } else if (method == "sendTransaction") {
            return handleSendTransaction(params);
        } else {
            // Method not found
            json response = {
                {"jsonrpc", "2.0"},
                {"error", {"code", -32601}, "message", "Method not found"},
                {"id", request["id"]}
            };
            return response;
        }
    }

    // Function to handle "getBlockHeight" JSON-RPC method
    json handleGetBlockHeight(const json& params) {
        // Assuming you have a function to get the current block height from the blockchain
        uint32_t blockHeight = getBlockHeightFromBlockchain();
        json response = {
            {"jsonrpc", "2.0"},
            {"result", blockHeight},
            {"id", params.contains("id") ? params["id"] : nullptr}
        };
        return response;
    }

    // Function to handle "getTransactionDetails" JSON-RPC method
    json handleGetTransactionDetails(const json& params) {
        // Assuming you have a function to retrieve transaction details from the blockchain
        std::string transactionId = params["transactionId"];
        TransactionDetails transactionDetails = getTransactionDetailsFromBlockchain(transactionId);

        // Construct JSON response with transaction details
        json response = {
            {"jsonrpc", "2.0"},
            {"result", transactionDetails},
            {"id", params.contains("id") ? params["id"] : nullptr}
        };
        return response;
    }

    // Function to handle "sendTransaction" JSON-RPC method
    json handleSendTransaction(const json& params) {
        // Assuming you have a function to validate and process the transaction
        std::string transactionData = params["transactionData"];
        bool isValid = validateTransaction(transactionData);
        if (isValid) {
            processTransaction(transactionData);
            json response = {
                {"jsonrpc", "2.0"},
                {"result", "Transaction successfully processed"},
                {"id", params.contains("id") ? params["id"] : nullptr}
            };
            return response;
        } else {
            json response = {
                {"jsonrpc", "2.0"},
                {"error", {"code", -32602}, "message", "Invalid transaction data"},
                {"id", params.contains("id") ? params["id"] : nullptr}
            };
            return response;
        }
    }
} // namespace SPHINXHttp
