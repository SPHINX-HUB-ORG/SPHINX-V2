// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include "Server_http.hpp"

namespace SPHINX {
    using boost::asio::ip::tcp;

    std::string processHttpRequest(const std::string& request) {
        // Process the incoming HTTP request and return an appropriate HTTP response
        if (request.find("/create_bridge") != std::string::npos) {
            // Extract the bridge address from the request
            // Create the bridge and return a response
            return "HTTP/1.1 200 OK\r\n\r\nBridge created successfully!";
        } else if (request.find("/handle_transaction") != std::string::npos) {
            // Extract transaction data from the request
            // Handle the transaction and return a response
            return "HTTP/1.1 200 OK\r\n\r\nTransaction handled successfully!";
        }

        // Return a response for other requests
        return "HTTP/1.1 404 Not Found\r\n\r\n";
    }

    void startHttpServer() {
        try {
            boost::asio::io_context io_context;
            tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 8080));

            while (true) {
                tcp::socket socket(io_context);
                acceptor.accept(socket);

                // Read the request
                boost::asio::streambuf request;
                boost::asio::read_until(socket, request, "\r\n\r\n");

                std::string http_request((std::istreambuf_iterator<char>(&request)),
                                          std::istreambuf_iterator<char>());

                // Process the request and generate the response
                std::string http_response = processHttpRequest(http_request);

                // Send the response
                boost::asio::write(socket, boost::asio::buffer(http_response));
            }
        } catch (std::exception& e) {
            std::cout << "Exception: " << e.what() << "\n";
        }
    }
} // namespace SPHINX
