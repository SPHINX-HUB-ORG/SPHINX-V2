// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.

#include <string>
#include <vector>

#include "lib/Swifftx/SHA3.h"
#include "Hash.hpp"


namespace SPHINXHash {

std::string SPHINX_256(const std::string& message) {
    hashState state;
    BitSequence hashval[SWIFFTX_OUTPUT_BLOCK_SIZE];
      // These lines declare variables state of type hashState and hashval as an array of BitSequence 
      // with a size of SWIFFTX_OUTPUT_BLOCK_SIZE. These variables will be used to store the hash state 
      // and the resulting hash value, respectively.
    
    // Initialize the hash state with the intended hash length
    Init(&state, 256); // Replace "256" with the desired hash length

      // This line initializes the state variable by calling the Init function from the SWIFFTX library. 
      // The second argument 256 specifies the desired hash length in bits. 
      // IT can replace 256 with the desired hash length.

    // Update the hash state with the message
    Update(&state, reinterpret_cast<const BitSequence*>(message.c_str()), message.length() * 8);

      // This line updates the hash state by calling the Update function from the SWIFFTX library. 
      // It takes the state variable, casts the message string to a const BitSequence*, and provides 
      // the length of the message in bits. This step processes the input message and updates the hash
      // state accordingly.

    // Finalize the hash computation and obtain the hash value
    Final(&state, hashval);

      // This line finalizes the hash computation by calling the Final function from the SWIFFTX library.
      // It takes the state variable and the hashval array as arguments. This step computes the final hash
      // value based on the processed input message and stores it in the hashval array.

    // Convert the hash value to a hexadecimal string
    std::string result;
    for (int i = 0; i < SWIFFTX_OUTPUT_BLOCK_SIZE; ++i) {
        char hex[3];
        sprintf(hex, "%02x", hashval[i]);
        result += hex;
    }
      // These lines convert the hashval array to a hexadecimal string representation. It iterates over
      // each element of the hashval array, converts it to a two-digit hexadecimal representation using
      // sprintf, and appends it to the result string.

    return result;
      // This line returns the resulting hash value as a hexadecimal string.
  }
} // namespace SPHINXHash