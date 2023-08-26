// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <vector>
#include <string>
#include <Hash.hpp> // Include the header for SPHINXHash
#include <Consensus/Merkle.hpp>
#include "Benchmark/Benchmark.hpp"
#include "Merkle_root.hpp"

namespace SPHINXMerkle {

    // Function to compute the Merkle root of a set of transaction hashes
    std::string ComputeMerkleRoot(const std::vector<std::string>& transactionHashes) {
        bool mutated = false;
        std::vector<std::string> hashes = transactionHashes;

        while (hashes.size() > 1) {
            if (hashes.size() % 2 != 0) {
                hashes.push_back(hashes.back()); // Duplicate the last hash if the count is odd
            }

            std::vector<std::string> new_hashes;
            for (size_t i = 0; i < hashes.size(); i += 2) {
                // Concatenate and hash the two hashes
                std::string combinedHash = hashes[i] + hashes[i + 1];
                std::string hash = SPHINXHash::SPHINX_256(combinedHash); // Use the actual function name
                new_hashes.push_back(hash);
            }

            hashes = new_hashes;
        }

        return hashes[0];
    }

    static void BM_MerkleRoot(benchmark::State& state) {
        FastRandomContext rng(true);
        std::vector<std::string> leaves;
        leaves.resize(9001);
        for (auto& item : leaves) {
            item = rng.rand256().ToString();
        }

        while (state.KeepRunning()) {
            bool mutation = false;
            std::string root = ComputeMerkleRoot(leaves);
            leaves[mutation] = root;
        }
    }
    BENCHMARK(BM_MerkleRoot);

} // namespace SPHINXMerkle

BENCHMARK_MAIN();

