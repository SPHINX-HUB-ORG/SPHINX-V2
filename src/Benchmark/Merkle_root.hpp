// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINX_MERKLE_HPP
#define SPHINX_MERKLE_HPP

#include <vector>
#include <string>

namespace SPHINXMerkle {

    // Function to compute the Merkle root of a set of transaction hashes
    std::string ComputeMerkleRoot(const std::vector<std::string>& transactionHashes);

    // Benchmark function for Merkle root calculation
    void BM_MerkleRoot(benchmark::State& state);

} // namespace SPHINXMerkle

#endif // SPHINX_MERKLE_HPP
