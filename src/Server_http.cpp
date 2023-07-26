// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.

#include <iostream>
#include <string>
#include <boost/asio.hpp>

namespace SPHINX {
    using boost::asio::ip::tcp;

    std::string createHttpResponse() {
        return "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
    }

    int main() {
        try {
            boost::asio::io_context io_context;
            tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 8080));

            while (true) {
                tcp::socket socket(io_context);
                acceptor.accept(socket);

                // Read the request
                boost::asio::streambuf request;
                boost::asio::read_until(socket, request, "\r\n");

                std::string http_request;
                std::istream request_stream(&request);
                std::getline(request_stream, http_request);

                // Print the request
                std::cout << "Request: " << http_request << "\n";

                // Send the response
                std::string http_response = createHttpResponse();
                boost::asio::write(socket, boost::asio::buffer(http_response));
            }

        } catch (std::exception& e) {
            std::cout << "Exception: " << e.what() << "\n";
        }

        return 0;
    }
} // namespace SPHINX

int main() {
    SPHINX::main();
    return 0;
}
