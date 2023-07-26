// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


/////////////////////////////////////////////////////////////////////////////////////////////////////////
// The provided code belongs to the SPHINX namespace and includes a main function that demonstrates a simple HTTP client using Boost.Asio library. Let's understand the code and its functionality:

// The main function sets up an io_context, a resolver, and a socket for establishing a TCP connection.
  // It resolves the server address and port using the resolver.
  // It connects to the server using boost::asio::connect.
  // It creates an HTTP GET request and sends it to the server using boost::asio::write.
  // It reads and prints the response from the server using boost::asio::read_until and std::cout.
  // It extracts the HTTP version, status code, and status message from the response.
  // It checks the validity of the response.
  // It prints the response headers.
  // It prints the response body if it exists.
  // Exception handling is implemented to catch and display any exceptions that occur during the process.

// Note that the code provided is a simplified version and may require additional implementation details for handling more complex HTTP requests and responses, error handling, and other functionalities related to building an HTTP client using Boost.Asio library.
////////////////////////////////////////////////////////////////////////////////////////////////////////



#include <iostream>
#include <string>
#include <boost/asio.hpp>

namespace SPHINX {
    using boost::asio::ip::tcp;

    int main() {
        try {
            boost::asio::io_context io_context;
            tcp::resolver resolver(io_context);
            tcp::socket socket(io_context);

            // Resolve the server address and port
            tcp::resolver::results_type endpoints = resolver.resolve("localhost", "8080");

            // Connect to the server
            boost::asio::connect(socket, endpoints);

            // Send an HTTP GET request
            boost::asio::streambuf request;
            std::ostream request_stream(&request);
            request_stream << "GET / HTTP/1.1\r\n";
            request_stream << "Host: localhost\r\n";
            request_stream << "Connection: close\r\n\r\n";

            // Send the request
            boost::asio::write(socket, request);

            // Read and print the response
            boost::asio::streambuf response;
            boost::asio::read_until(socket, response, "\r\n");

            std::istream response_stream(&response);
            std::string http_version;
            response_stream >> http_version;

            unsigned int status_code;
            response_stream >> status_code;

            std::string status_message;
            std::getline(response_stream, status_message);

            if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
                std::cout << "Invalid response\n";
                return 1;
            }

            std::cout << "Response: " << http_version << " " << status_code << " " << status_message << "\n";

            // Read and print the response headers
            boost::asio::read_until(socket, response, "\r\n\r\n");
            std::string header;
            while (std::getline(response_stream, header) && header != "\r") {
                std::cout << header << "\n";
            }

            std::cout << "\n";

            // Read and print the response body
            if (response.size() > 0) {
                std::cout << &response;
            }

        } catch (std::exception& e) {
            std::cout << "Exception: " << e.what() << "\n";
        }

        return 0;
    }
} // namespace SPHINX
