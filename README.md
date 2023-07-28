# SPHINX-HUB

![Sphinx Hub Logo](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/asset/logo3-01.jpg)

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

### Source Files

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

### 10.  [Key.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Key.cpp) & [Hybrid_key.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Hybrid_Key.cpp)

The `Key.cpp` and `Hybrid_Key.cpp` leverages Post-Quantum Public-key Encryption and Key-establishment Algorithms [Crystals-kyber](https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/round-3-submissions) as round-3 post-quantum winners.

In the thrilling era of quantum computers, where we find ourselves in a `Super Position` between classical and quantum realms, the choice of a hybrid key exchange scheme combining curve448 and Kyber1024 holds immense significance. Let's explore why this combination is the perfect fit.

1. Embracing the Best of Both Worlds: `curve448`, a battle-tested and widely adopted algorithm, provides a solid foundation of proven security and efficient key generation. On the other hand, `Kyber1024` represents the cutting-edge of post-quantum cryptography, designed to resist attacks from powerful quantum computers. By combining these two exceptional algorithms, we enter a "Super Position" where we benefit from the strengths of both classical and quantum-resistant cryptography.

2. Inspiration from Tech Giants: The widespread adoption of `curve448` and `Kyber1024` by the larger tech community serves as our guiding light and inspiration. These algorithms have garnered trust and confidence from experts and industry leaders, paving the way for their integration into our hybrid scheme. By following in the footsteps of these role models, we embrace a solution that is not only innovative but also aligns with industry best practices.

In this era of immense technological possibilities, the combination of `curve448` and `Kyber1024` in a hybrid key exchange scheme symbolizes our readiness to face the challenges presented by quantum computing. It demonstrates our commitment to leverage the proven track record of `curve448` and the promising resilience of `Kyber1024`. Together, these algorithms empower us to navigate the quantum landscape with confidence, ensuring the security and longevity of our cryptographic systems.

**Description and logic**;
- `Curve448` given 224-bit security level
- `Kyber-1024` given (equal AES-256) mean 256-bit security level
If we `merged` them it means we will achieve security level nearly `480-bytes`, this not lightweight but more secured


**Functions**;

- The code defines a function called `performX448KeyExchange` that performs the `curve448` key exchange given a private key, public key, and a buffer to store the shared key.

- It defines a structure called `HybridKeypair`, which holds the merged key pair consisting of a `Kyber1024` key pair and and `curve448` key pair, as well as PKE key pair, and a random number generator.

- The function `generate_hybrid_keypair` generates a hybrid key pair by generating a `Kyber1024` key pair, an `curve448` key pair, and a PKE key pair using appropriate functions. It returns the generated hybrid key pair.

- The function `deriveMasterKeyAndChainCode` is used to derive a master private key and chain code from a given seed using the `HMAC-SHA512` function. It returns the `derived master private key` and `chain code` as a pair.

- There are several utility functions defined, such as `deriveKeyHMAC_SHA512` to derive a key using `HMAC-SHA512`, `hashSWIFFTX512` to calculate the `SWIFFTX-512` hash of data, and `generateRandomNonce` to generate a random nonce.

- The function `deriveKeyHKDF` derives a key using the `HKDF` (HMAC-based Key Derivation Function) algorithm with `SHA256` as the default hash function.

- The function hash calculates the `SWIFFTX-256` hash of a given input.

- The function `generateKeyPair` generates a random private key and calculates the corresponding public key by hashing the private key.

- The function `generateAddress` generates an address from a given public key by hashing the public key and taking the first 20 bytes of the hash.

- The function `requestDigitalSignatur`e requests a digital signature for a given data using the provided hybrid key pair.

- The functions `encryptMessage` and `decryptMessage` are used to encrypt and decrypt a message, respectively, using the `Kyber1024` KEM (Key Encapsulation Mechanism).

- The functions `encapsulateHybridSharedSecret` and `decapsulateHybridSharedSecret` are used to encapsulate and decapsulate a shared secret using the `hybrid KEM`, which combines `curve448` and `Kyber1024`.

This code provides a set of functions and structures to support hybrid key generation, key exchange, encryption, decryption, and other cryptographic operations.


**The interaction and collaboration between Key.cpp and Hybrid_Key.hpp**

1. **SPHINXKey Namespace** interacts with the **SPHINXHybridKey Namespace** by calling the function `generate_hybrid_keypair` from the `SPHINXHybridKey` namespace. This function generates the hybrid keypair and its corresponding private and public keys.

2. The function `SPHINXKey::generateAddress` uses the `SPHINXHybridKey::SPHINXHash::SPHINX_256` function to hash the public key and generate an address based on the hash. This address is used for smart contract identification.

3. In `SPHINXHybridKey::generate_hybrid_keypair`, Kyber1024 and X448 keypairs are generated. The function also derives a master private key and chain code using HMAC-SHA512 from a seed value and then derives private and public keys from the master key and chain code using HMAC-SHA512.

4. The `SPHINXHybridKey` namespace provides functions to encrypt and decrypt messages using Kyber1024 for KEM (Key Encapsulation Mechanism).

5. The `SPHINXHybridKey::performX448KeyExchange` function performs the X448 key exchange.

6. The `SPHINXHybridKey` namespace also includes functions to encapsulate and decapsulate shared secrets using the hybrid KEM, combining the results of Kyber1024 and X448.

**Combined Usage**:
The combined usage of `SPHINXKey` and `SPHINXHybridKey` allows for the generation of secure hybrid keypairs that leverage the strengths of both Kyber1024 and X448 cryptographic algorithms. The hybrid keypairs can be used for various cryptographic purposes, including encryption, decryption, and key exchange, making it a versatile and robust cryptographic solution.

**NOTATION**;

The next roadmap as consideration long term security is to completely implement Homomorphic-Hybrid key generation scheme in the [Tfhe.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Tfhe.cpp) protocol the purpose is to leverage [TFHE](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/tree/main/src/Lib/Master-Lib/tfhe-master) library to achieve homomorphic and hybrid scheme key generaion at once.


### 11. [Mempool.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Mempool.hpp)

### 12. [Merkleblock.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/MerkleBlock.cpp) & [Sign.hpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Sign.hpp)

The `SPHINXSign` and `SPHINXMerkleBlock` namespace leverages the power of Merkle trees based on the state-of-the-art [SPHINCS+](https://sphincs.org/) principle, which emerged as the 4th winner in the "Post-Quantum" cryptography competition held by the National Institute of Standards and Technology ([NIST](https://www.nist.gov/publications/breaking-category-five-sphincs-sha-256)).

SPHINCS+ (Stateless PHotonic Isogeny-based Signature Scheme) is a groundbreaking hybrid signature scheme that combines robust hash-based, code-based, and isogeny-based cryptographic components. Its primary goal is to achieve two critical properties: `statelessness` and `post-quantum` security.

In the advent of quantum computers, which have the potential to render traditional cryptographic algorithms vulnerable, the elimination or reduction of reliance on state becomes imperative. Quantum computers, with their ability to exist in multiple states simultaneously, pose significant risks to storing sensitive content in state. The concept of `statelessness` in SPHINCS+ aims to mitigate these risks by eliminating the reliance on state, providing resilience against attacks by powerful quantum computers.

Unlike alternative post-quantum digital signature algorithms such as [Crystals-dilithium](https://pq-crystals.org/dilithium/) which offer high levels of security but are susceptible to "side-channel attacks", side channel atttack means attack on devices, the bad actors can attack on devices to found the "Sign" then it can to used to sign any message that their want, our decision to employ SPHINCS+ as the foundation for our Merkle tree scheme and digital signature scheme ensures both the robustness against quantum adversaries and resistance to side-channel attacks.

With the `SPHINXMerkleBlock` namespace, we empower developers to harness the advanced capabilities of SPHINCS+ and build secure, future-proof applications that can withstand the challenges posed by the dawn of the quantum era.

We know that Hash-Based digital signature scheme is not lattice-based and relly on the strengthness of the hash-function, thats why our default [SPHINXHash](https://github.com/ChyKusuma/SPHINXHash) hash function is based on SWIFFTX which is rely on "Lattice-based", here our purposed is try to achieve both `Statelessness` and `Lattice-based` together at once.

Digital signature scheme like [Gottesman-chuang](https://www.researchgate.net/publication/2186040_Quantum_Digital_Signatures) its trully guarantee by Quantum-Laws, we aware about that, but it's still too expensive technology, its needed new infrastructure, new hardware, a lot of money will only spent into infrastructure, so for today its not solution for us and not applicable. One day, when the world already build the quantum infrastructure i.e Quantum Key Distribution we believed our construction will more safe.


Function

1. JSON and SPHINXKey Namespace

- The code starts with the use of `JSON` library with the alias json from the `nlohmann namespace`.
- Next, a namespace called `SPHINXKey` is declared, which contains a type `SPHINXPubKey` representing a `vector of unsigned` characters. It seems to be used for public keys.

2. Forward Declarations

- Three functions are forward-declared, which means their actual implementation is provided later in the code.
    - These functions are:
    - `generateOrRetrieveSecretKeySeed`: It's expected to generate or retrieve a secret key seed.
    - `generateOrRetrievePublicKeySeed`: It's expected to generate or retrieve a public key seed.
    - `verifySignature`: It's expected to verify a signature using a public key.

3. SPHINXMerkleBlock Namespace

- A new namespace named `SPHINXMerkleBlock` is defined, encapsulating all the classes and functions related to constructed the Merkle block.

4. Transaction class 
 
- The Transaction class represents a transaction and contains `data, signature`, and `publicKey` as its member variables.
It provides a member function `toJson()` to convert the transaction data into a `JSON-formatted` string.

5. Constants

- Several constants are declared, such as `SPHINCS_N, SPHINCS_H, SPHINCS_D, etc`., which might be used to call function from SPHINCS+ library.

6. SignedTransaction Structure

- The `SignedTransactio`n structure represents a signed transaction and includes `transaction, transactionData, data, signature`, and `publicKey` as its members.

7. MerkleBlock class 

- The MerkleBlock class represents a `Merkle block` and includes several helper classes for `Merkle tree` construction: `ForsConstruction, WotsConstruction, HypertreeConstruction`, and `XmssConstruction`.
  - First the hash function used default hash function in library based on `SHAKE256 robust scheme`
  - Then it hashing again using `SPHINXHash` to ensure long term usage.

- It also contains functions for constructing the Merkle tree `(constructMerkleTree)` and verifying the Merkle root `(verifyMerkleRoot)`.

8. Calculate block header

- This function takes the `previous block hash, Merkle root, timestamp`, and `nonce` as inputs and returns the hash of the block's header data.

9. verifyIntegrity Function

This function calls `verifyBlock` and `verifyChain` functions from `Verify.hpp` and prints the results of block and chain integrity verification.

10. sphinxKeyToString Function

- This function converts the SPHINX public key to a string representation.

11. generateHybridKeyPair Function

- This function generates a hybrid key pair using functions from `Key.cpp` It returns the private key as a string and the public key as a `SPHINXKey::SPHINXPubKey`.

12. MerkleTree Construction

- The `constructMerkleTree` function recursively constructs the Merkle tree from a vector of signed transactions.
verifyMerkleRoot Function

13 verifyMerkleRoot Function

- The verifyMerkleRoot function verifies the Merkle root against a vector of transactions, ensuring the validity of transactions using their signatures.

14. hashTransactions Function

- This function calculates the hash of two transactions using the `SPHINX_256` hash function.

15. buildMerkleRoot Function

- This function constructs the Merkle root from a vector of transactions using recursion.

16. Signing and Key Generation Functions

- The sign function is used for signing a message using the SPHINCS signature scheme.
  
- The nested classes `ForsConstruction, WotsConstruction, HypertreeConstruction`, and `XmssConstruction` handle various steps in constructing the `Merkle tree`, involving different cryptographic functions.

17. Verification Function
- The verifySignature function is used to verify the signature of a transaction using the provided public key.

These components work together to provide functionality for constructing and verifying Merkle trees using the SPHINCS+ cryptographic scheme.

*NOTATION

1.  In the provided code for "sign.hpp" and "merkleblock.cpp" the SPHINCS+ implementation appears to be stateless. The functions for `signing` and `verifying` transactions do not rely on any previous state or stored information, and the signing process is done independently for each transaction.

2. The next roadmap is to add additional features to used [Multi-party Computation](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/tree/main/src/Lib/MPC) in this digital signature scheme, we needed to created protocol to interact with the library to provided secure digital signature scheme to ensure long term security guarantee.


### 13. [Miner.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Miner.cpp)

### 14. [Node.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Node.cpp)

### 15. [Params.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Params.cpp)

### 16. [Plotpow.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/PlotPoW.hpp)

### 17. [PoW.hpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/PoW.hpp)

### 18. [Requests.hpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Requests.hpp)

### 19. [Script.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Script.cpp)

### 20. [Server.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Server_http.cpp)

### 21. [Tfhe.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Tfhe.cpp)

### 22. [Transaction.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Transaction.cpp)

### 23. [Utils.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Utils.cpp)

### 24. [Utxo.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Utxo.cpp)

### 25. [Verify.hpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Verify.hpp)

### 26. [Wallet.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/Wallet.cpp)

### 27. [Base58.c](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/base58.c)

### 28. [Base58check.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/base58check.cpp)

### 29. [db.cpp](https://github.com/SPHINX-HUB-ORG/SPHINX-HUB/blob/main/src/db.cpp)

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
