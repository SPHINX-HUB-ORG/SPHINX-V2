# SPHINX-HUB Project Overview

![Sphinx Hub Logo](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/asset/Logo2.png)

## Table of Contents

- [Introduction](#introduction)
- [Background](#background)
- [Vision](#vision)
- [Key Features](#key-features)
- [Directories](#directories)
- [NOTE](#note)
- [Getting Started](#getting-started)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Introduction

Welcome to our inclusive and dynamic decentralized world, where individuals and institutional from all walks of life are warmly invited to join and support the mission. Here, we believe that everyone has unique skills and passions to offer, and we encourage you to commit your talents towards making a lasting impact in the decentralized realm.

This project is dedicated to the world community as an Open-source Post-quantum blockchain layer 1 project, means anyone can join and contribute based on his/ her passion and skills. SPHINX is a blockchain protocol designed to provide secure and scalable solutions in the post-quantum era.

Together, we form a united front dedicated to creating the most sustainable and robust blockchain ecosystem. Our goal is not only to strengthen the existing web3 ecosystem but also to anticipate and navigate the disruptive challenges posed by the imminent arrival of quantum computers.

In this era of quantum-computers, we envision a future that is brighter and more promising for the global community. By synergizing our efforts, knowledge, and expertise, we strive to shape an innovative landscape that transcends boundaries and unlocks boundless possibilities.

## Background

In a world where technology is constantly advancing, it is crucial for us to recognize the pressing need to transition into the post-quantum era. The advent of quantum computers, with their unparalleled computational power and the ability to solve complex problems at an unprecedented scale, has the potential to revolutionize industries and disrupt existing cryptographic systems.

Traditional cryptographic algorithms, which have served us well in securing sensitive information and facilitating secure transactions, face a formidable challenge in the face of quantum computers. These advanced machines possess the capability to break conventional cryptographic methods, rendering them vulnerable to attacks that were previously inconceivable. The very foundations upon which our digital infrastructure rests are at risk, necessitating a proactive and strategic shift towards post-quantum cryptography.

Entering the post-quantum era is not merely a matter of security; it is an opportunity to redefine the future landscape of technology and safeguard the integrity of our digital interactions. By proactively embracing this transition, we pave the way for a more resilient and trustworthy digital infrastructure. We empower individuals and organizations to continue operating securely, protecting sensitive information, and ensuring the privacy of online communications.

Furthermore, the post-quantum era presents us with the prospect of fostering innovation and pushing the boundaries of what is possible. It opens up avenues for groundbreaking research, collaboration, and the development of new cryptographic techniques that transcend the limitations of classical computing. By investing in this transformative shift, we position ourselves at the forefront of technological advancements, driving progress and staying ahead in an ever-evolving digital landscape.

In conclusion, the urgency to enter the post-quantum era arises from the potential threats posed by quantum computers to our existing cryptographic systems. By embracing this transition, we fortify our digital infrastructure, protect sensitive information, and lay the foundation for a future where security, innovation, and progress coexist harmoniously. Together, let us seize this opportunity to shape a robust and secure post-quantum era, where technology empowers and safeguards us in equal measure.

## Vision

Unlocking the Power of Post-Quantum Technology:
Immerse yourself in a revolutionary project that aims to redefine the blockchain landscape. Our mission is to create a decentralized, secure, and transparent network that remains impervious to both classical and quantum computing attacks.

Empowering the Community for a Secure Future:
Join us on this transformative journey as we provide a platform that empowers individuals and businesses alike with secure and transparent transactions, data storage, and applications.

## Key Features:
- Post-quantum cryptography
- Homomorphic-Hybrid key scheme
- Multi-party computation
- Zero-knowledge proof
- Proof-of-work
- Decentralized, scalable, interoperable network
- Multiple smart contract program language

## Directories

This repository contains the implementation of the SPHINX-HUB, a decentralized hub for secure and efficient data storage and transfer. The project is divided into several directories, each containing specific functionalities. Below is a brief explanation of each file and directory:

### 4. Source Files

Explanation for each source file goes here. Click on the file names below to view the explanations:

<details>
<summary>Click to expand</summary>
<br>

### 1. [Asset.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Asset.cpp)

1. Class $SPX - The Crypto Asset:
- Represents a cryptocurrency asset with properties like id, name, and owner.
- It has functions to get and set the id, name, and owner.
- The buy function allows someone to buy this crypto asset by updating the ownership.

2. Class AssetManager - Managing Assets:
- Handles the management of SPX crypto assets, including issuance, transfers, and ownership changes.
- It has functions like buySPX, issueSPX, setOwner, and transferSPX.

3. Generating a Unique ID:
- The generateUniqueId function creates a unique ID for assets using cryptographic key pairs (hybrid keys).
- The generated ID is based on the asset's public key.

4. Paying Transaction Fee:
- The payTransactionFee function handles transaction fees for asset operations.
- It is called after asset-related operations to deduct transaction fees from the payer's account.

5. Finding an Asset:
- The findAsset function searches for an asset with a given ID in the blockchain data.
- It returns a pointer to the asset if found, otherwise, it returns nullptr.

6. Halving Block Reward:
- The halveBlockReward function is called when the halving threshold is reached (e.g., every 210,000 blocks).
- It reduces the block reward or token issuance rate by halving it.

7. Generating Transaction Data:
- The generateTransactionData function creates transaction data for storing on the blockchain.
- It creates a transaction with inputs and outputs and serializes it to JSON format.
- The transaction is then signed with a private key to generate a signature for verification.

8. Asset Management Parameters:
The class contains parameters like totalSupply, maxSupply, halvingThreshold, and blockReward.
These parameters define the total supply of assets, maximum supply (e.g., 50 million), halving threshold, and initial block reward.
  
### 2. [Block.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Block.cpp)

1. Constructor:
- There are two constructors for creating a Block object.
- The first constructor takes the previousHash of the previous block and initializes other member variables like blockHeight, nonce, and difficulty.
- The second constructor adds a version parameter to set the block's version.

2. Function addTransaction:
- This function is used to add a transaction to the block.
- It takes a transaction as a string and appends it to the transactions_ vector.

3. Function calculateBlockHash:
- This function calculates the hash of the entire block's data (excluding the signature) using the SPHINXHash::SPHINX_256 function.
- It concatenates previousHash_, timestamp_, and all the transactions in transactions_ to form the data.
- The resulting data is then hashed using the SPHINX_256 hash function, and the hash is returned.

4. Function calculateMerkleRoot:
- This function calculates the Merkle root hash of the transactions in the block using the SPHINXMerkleBlock::constructMerkleTree function.
- The constructMerkleTree function is called with the transactions_ vector, and the resulting Merkle root is returned.

5. Function signMerkleRoot:
- This function signs the provided Merkle root with the SPHINCS+ private key and stores the signature and Merkle root in the block.
- The signature_ is set using the SPHINXSign::sign_data function with the provided private key.
- The storedMerkleRoot_ is set with the input merkleRoot.

6. Function verifySignature:
- This function verifies the block's signature using the provided public key.
- It calculates the block hash using the calculateBlockHash function and then calls the SPHINXSign::verify_data function with the block hash, signature, and public key.
- Returns true if the signature is valid, otherwise false.

7. Function verifyMerkleRoot:
- This function verifies the stored Merkle root with the given public key.
- It calls the merkleBlock.verifyMerkleRoot function with the storedMerkleRoot_ and transactions_.
- Returns true if the Merkle root is valid, otherwise false.

8. Function verifyBlock:
- This function verifies the entire block with the given public key by calling verifySignature and verifyMerkleRoot.
- Returns true if both the signature and Merkle root are valid, otherwise false.

9. Function mineBlock:
- This function is used to mine the block with the given difficulty.
- It attempts to find a valid block hash that meets the specified difficulty level (starting with leading zeros).
- It repeatedly increments the nonce_ value and recalculates the block hash until a valid hash is found.
- Once a valid hash is found, the function updates the UTXO (Unspent Transaction Outputs) set based on the transactions included in the block and returns true.
- If no valid hash is found, the function returns false.

10. Serialization and Deserialization Functions:
- Functions like toJson, fromJson, save, and load handle serialization and deserialization of the block data to/from JSON format and files.
Functions for Database Interaction:
- saveToDatabase and loadFromDatabase are used to save and load block data to/from a distributed database using the SPHINXDb::DistributedDb class.

11. Getter Functions:
- Various getter functions (e.g., getPreviousHash, getMerkleRoot, getSignature, etc.) are provided to access the private member variables of the Block class.
- These functions together form the core functionality of the SPHINXBlock::Block class, which is used to represent and manage individual blocks in a blockchain.

### 3. [Blockmanager.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/BlockManager.cpp)

The Block Manager plays a pivotal role in the synchronization, validation, and storage of blocks. It handles incoming blocks from the network, ensures consensus rules are followed, and validates each block's transactions before incorporating them into the blockchain. Additionally, the Block Manager maintains the local copy of the blockchain, tracking the longest valid chain to maintain the network's consensus.

Within "BlockManager.cpp," you will find functions that facilitate block retrieval, storage, and organization. It coordinates with other components, such as the consensus mechanism and network communication, to ensure a coherent and consistent blockchain state across all nodes.

### 4. [Chain.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Chain.cpp)

Supports various operations like adding blocks, transferring funds between chains and shards, performing atomic swaps, and handling bridge transactions. Let's focus on the key functions and their purposes:

- addBlock: This function adds a new block to the blockchain. Before adding the block, it verifies the block's validity using a public key (SPHINXPubKey). If the block is valid, it is added to the chain.

- transferFromSidechain: This function transfers a block from a sidechain to the main chain. It first verifies the block's validity using a public key (SPHINXPubKey). If valid, the block is added to the main chain.

- handleBridgeTransaction: This function handles a bridge transaction, which involves transferring funds from one chain to another. It validates the transaction and, if valid, adds it to the target chain.

- performAtomicSwap: This function performs an atomic swap between the current chain and a target chain. Atomic swaps allow two parties to exchange assets atomically without the need for a trusted third party. The function verifies the validity of the transactions and balances before executing the swap.

- toJson and fromJson: These functions are used to convert the chain data to and from JSON format for storage and communication.

- getBalance and updateBalance: These functions manage the balances of addresses on the chain.

- createShard, joinShard, and transferToShard: These functions are used to create and manage shards, which are separate chains connected to the main chain.

- performShardAtomicSwap: This function performs an atomic swap between the current shard and a target shard.

The code is designed to be interoperable, meaning it supports interactions between different chains and shards through functions like transferFromSidechain, handleBridgeTransaction, and performShardAtomicSwap. It is also scalable as it supports the creation and management of multiple shards, allowing for better resource utilization and transaction processing.


### 5. [Chainmanager.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/ChainManager.cpp)

The Chain Manager acts as the central hub for blockchain management, providing functionalities for chain synchronization, conflict resolution, and chain selection. It ensures that all nodes in the network have the most up-to-date and consistent view of the blockchain. When conflicts or forks occur, the Chain Manager applies consensus rules to determine the longest valid chain, resolving any discrepancies and maintaining the blockchain's single source of truth.

In "ChainManager.cpp," you will find code for handling incoming blocks from the network, verifying their validity, and incorporating them into the local blockchain. It coordinates with other components, such as the Block Manager and Consensus Mechanism, to achieve network-wide consensus and ensure the blockchain's security and integrity.

The proper functioning of "ChainManager.cpp" is crucial to the stability and trustworthiness of the SPHINX-HUB blockchain. It plays a pivotal role in maintaining a unified and consistent view of the blockchain across all nodes, supporting the network's decentralization and facilitating secure and transparent transactions.

### 6. [Checksum.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Checksum.cpp)

Checksum function inspiration from bitcoin.

1. Generating address:
SPHINX addresses are derived from a public key through a series of cryptographic transformations.
A checksum is added to the address to provide a way of verifying its validity.
The address includes both the public key and the checksum.


2. Address verification:
- When a user wants to send funds to a SPHINX address, the recipient provides the address to the sender.
- The sender uses the address to validate the checksum.
- The checksum is recalculated from the address (excluding the existing checksum), and it should match the original checksum provided by the recipient.
- If the checksums match, the sender can be confident that the address is valid and funds will be sent to the intended recipient.

3. Error prevention:
- If the address is mistyped or contains errors, the checksum verification will fail, preventing the sender from sending funds to an incorrect or non-existent address.
- This helps reduce the risk of funds being lost due to human error.


### 7. [Client_http.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Client_http.cpp)

1. Handling HTTP Requests:
- The file contains functions and classes that handle incoming HTTP requests from clients or other nodes in the network.
- These functions are responsible for processing the requests and generating appropriate responses.

2. Verifying Requests:
- The "Client_http.cpp" file might include mechanisms to verify the authenticity and integrity of incoming requests.
- This could involve checking digital signatures, validating data formats, and ensuring that the requests comply with the protocol's specifications.

3. Sending HTTP Responses:
- After processing incoming requests, the "Client_http.cpp" file would generate appropriate HTTP responses to be sent back to the requesting clients or nodes.
- Responses could include data, status codes, or error messages, depending on the nature of the request.

4.Interacting with Other Modules:
- "Client_http.cpp"interact with other modules within the blockchain system, such as the consensus mechanism, blockchain data storage, or transaction processing components.
- This interaction ensures that incoming requests are handled appropriately and that the blockchain operates smoothly.

5. Handling Errors and Exception Handling:
- The file contains error handling and exception management mechanisms to deal with unexpected situations gracefully.
Proper error handling is crucial to maintaining the stability and security of the blockchain system.

### 8. [Common.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Common.cpp)

1. Utility Functions:
- Contain utility functions that perform common operations frequently needed across the blockchain system.
Examples of utility functions might include cryptographic operations, string manipulation, data conversions, and timestamp handling.
Data Structures:

- Define common data structures or data types that are used in different parts of the codebase.
These data structures may include objects, data containers, or custom data types tailored to the specific needs of the blockchain.
Configuration and Constants:

- The file could handle configurations and constants that are used throughout the blockchain system.
This might include network parameters, consensus rules, default settings, and other constant values.
Error Handling and Logging:

- Contain error handling mechanisms and logging functionalities to help debug and troubleshoot issues within the blockchain.

2. Cross-Platform Compatibility:
- If the blockchain project aims for cross-platform compatibility, "Common.cpp" might include code that ensures the system behaves consistently across different platforms and environments.

3. Modularity and Code Reusability:
- The file contributes to the overall modularity and code reusability of the blockchain project by centralizing commonly used functions and data structures.

### 9. [Hash.hpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Hash.hpp)

1. Function Declarations:
- Declaration functions that implement the hash function utilizing SWIFFTX with a 256-bit digest size.
- Function declarations would specify the input parameters and return type of the hash function.

2. SWIFFTX Algorithm:
- SWIFFTX is a cryptographic hash function designed to offer security and performance.

3. Data Structures and Constants:
- The file could define any necessary data structures or constants used in the hash function's implementation.
This might include buffers, state variables, or predefined constants used in the SWIFFTX algorithm.

### 10. [Hybrid_key.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Hybrid_Key.cpp)

### 11. [Key.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Key.cpp)

### 12. [Mempool.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Mempool.hpp)

### 13. [Merkleblock.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/MerkleBlock.cpp)

### 14. [Miner.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Miner.cpp)

### 15. [Node.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Node.cpp)

### 16. [Params.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Params.cpp)

### 17. [Plotpow.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/PlotPoW.hpp)

### 18. [PoW.hpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/PoW.hpp)

### 19. [Requests.hpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Requests.hpp)

### 20. [Script.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Script.cpp)

### 21. [Server.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Server_http.cpp)

### 22. [Sign.hpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Sign.hpp)

### 23. [Tfhe.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Tfhe.cpp)

### 24. [Transaction.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Transaction.cpp)

### 25. [Utils.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Utils.cpp)

### 26. [Utxo.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Utxo.cpp)

### 27. [Verify.hpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Verify.hpp)

### 28. [Wallet.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Wallet.cpp)

### 29. [Base58.c](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/base58.c)

### 30. [Base58check.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/base58check.cpp)

### 31. [db.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/db.cpp)

</details>
<br>


## NOTE

Please note that the project is currently under development, and some features may be incomplete or subject to changes. The code in the repository is a part of the SPHINX blockchain algorithm, which is currently in development and not fully integrated or extensively tested for functionality. The purpose of this repository is to provide a framework in the SPHINX blockchain project.

As the project progresses, further updates and enhancements will be made to ensure the code's stability and reliability. We encourage contributors to participate in improving and refining the SPHINXBlock algorithm by submitting pull requests and providing valuable insights.

We appreciate your understanding and look forward to collaborative efforts in shaping the future of the SPHINX blockchain project.


## Getting Started
To get started with the SPHINX blockchain project, follow the instructions below:

1. Clone the repository.
2. Install the necessary dependencies.
3. Explore the codebase to understand the project structure and components.
4. Run the project or make modifications as needed.


## Contributing

We welcome contributions from the developer community to enhance the SPHINX blockchain project. If you are interested in contributing, please follow the guidelines below:

1. Fork the repository on GitHub.
2. Create a new branch for your feature or bug fix: `git checkout -b feature/your-feature-name` or `git checkout -b bugfix/your-bug-fix`.
3. Make your modifications and ensure the code remains clean and readable.
4. Write tests to cover the changes you've made, if applicable.
5. Commit your changes: `git commit -m "Description of your changes"`.
6. Push the branch to your forked repository: `git push origin your-branch-name`.
7. Open a pull request against the main repository, describing your changes and the problem it solves.
8. Insert your information (i.e name, email) in the authors space.

## License
Specify the license under which the project is distributed (MIT License).

## Contact
If you have any questions, requests, suggestions, or feedback regarding the SPHINX blockchain project, feel free to reach out to us at [sphinxfounders@gmail.com](mailto:sphinxfounders@gmail.com).
