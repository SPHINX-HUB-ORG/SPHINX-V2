# LIBSCAPI - The Secure Computation API

[![Build Status](https://travis-ci.org/cryptobiu/libscapi.svg?branch=master)](https://travis-ci.org/cryptobiu/libscapi)

## Introduction
libscapi is the Open source C++ library for implementing high performance secure two-party and multiparty computation protocols (SCAPI stands for the "Secure Computation API"). It provides a reliable, efficient, and highly flexible cryptographic infrastructure.

Libscapi is developed by [Bar Ilan University Cryptography Research Group](http://crypto.biu.ac.il/). The goal of libscapi is to promote research by Academy and Industry practitioners in this field by providing:
- A consistent API over Primitives, Mid-Layer Protocols, Interactive Mid-Layer Protocols and Communication Channels, simplifying the development and evaluation fo new protocols. We focus on keeping libscapi easy to build and use.
- Integrating best performance open-source implementations by other Academy Research Institutes.  
- High Performance implementation on standard Linux & Intelx64 Architecture. We use modern techniques like Intel Intrinsics  Instructions, Pipelining and TCP optimizations.  

## Publications using libscapi
- Generalizing the SPDZ Compiler For Other Protocols. Accepted ACM-CCS 18 [ABFKLOT18]()  
- An End-to-end System for Large Scale P2P MPC as-a-Service and Low-Bandwidth MPC for Weak Participants. Includes HyperMPC protocol
  Accepted ACM-CCS 18 [BHKL18]()  
- TinyKeys: A New Approach to Efficient Multi-Party Computation [HOSSV18](https://eprint.iacr.org/2018/208)  
- Fast Large-Scale Honest-Majority MPC for Malicious Adversaries [CGHIKLN18](https://eprint.iacr.org/2018/570)
- A Framework for Constructing Fast MPC over Arithmetic Circuits with Malicious Adversaries [LN17](https://eprint.iacr.org/2017/816.pdf)
- Low Cost Constant Round MPC Combining BMR and Oblivious Transfer [HSSV17](https://eprint.iacr.org/2017/214.pdf)

## Benchmarking and Automation
Libscapi is integrated with [MATRIX](https://github.com/cryptobiu/MATRIX) MPC Test Automation Framework. We use MATRIX to benchmark protocols on AWS cloud, including cross region experiments with up to 500 parties. MATRIX can easily run protocols that do not integrate libscapi as well, including for example the SPDZ-2 protocol implementation by Bristol University.  

## Protocol implementations 
The [MPC-Benchmark](https://github.com/cryptobiu/MPC-Benchmark) repository includes protocols implemented using libscapi, and integrated with the MATRIX benchmarking and automation platform. This includes implementations of the protocols listed above.

## libscapi Modules
- Primitives: Dlog, Cryptographic Hash Function, HMAC and KDF, Pseudorandom Functions and Permutations, Pseudo Random Generator, Trapdoor Permutation, Random Oracle etc.
- Mid-layer protocols: Public Key Encryption Schemes: Cramer-Shoup, Damgard-Jurik, El-Gamal
- Interactive Mid-layer protocols: Sigma Protocols, Zero Knowledge Proofs, Commitment Schemes
- OT Extension : Wrappers for LibOTE and SimpleOT by OSU-Cypto and Bristol University  
- Circuits: Some commonly used circuits for AES etc
- Communication Channel: TCP Peer-To-Peer communication setup and channel methods 

## Other Libscapi versions
- [ScapiLite](https://github.com/cryptobiu/ScapiLite) is an experimental version used to develop MPC protocols on Android and Raspberry Pi. It has also been ported to Javascript using emscripten. ScapiLite currently supports secret-sharing protocols only (As no OT has been ported)
- We have discontinued support for the Java Scapi library due to performance and portability issues. We would be happy to support anyone interested in developing new Java or Go bindings.

## License
Libscapi is released under the MIT open source license. However, some of the libraries we use have different licenses. For further information please refer to [LICENSE.md](https://github.com/cryptobiu/libscapi/blob/master/LICENSE.md)

## Documentation

Go to http://biulibscapi.readthedocs.org/ for a detailed explanations of our implementation.

## Installing libscapi

Libscapi runs on Linux (x64 only, 32 bit systems are not supported), MacOS and ARM64 and has been tested on the following version:
- Ubuntu 14.04/16.04/18.04 LTS
- CentOS 7.3
- Mac OS High Sierra 10.13
- ARM64 - tested on Cortex A72 with Ubuntu 18.04 LTS (prior versions to 18.04 on ARM may run as well).  

For detailed instructions, see [INSTALL.md](build_scripts/INSTALL.md)

## Libraries used by libscapi

### Implementations by other Academic Institutes

##### Cryptography Research at Oregon State University : LibOTE A fast, portable, and easy to use Oblivious Transfer Library
[https://github.com/osu-crypto/libOTe](https://github.com/osu-crypto/libOTe)

This library provides several different classes of OT protocols. First is the base OT protocol of Naor-Prinkas [NP00].  
This protocol bootstraps all the other OT extension protocols. Within the OT extension protocols, 
we have 1-out-of-2, 1-out-of-N and ~K-out-of-N, both in the semi-honest and malicious settings.  
All implementations are highly optimized using fast SSE instructions and vectorization to obtain  
optimal performance both in the single and multi-threaded setting.  
See the Performance section for a comparison between protocols and to other libraries.  
Networking can be performed using both the sockets provided by the library and external socket classes.

##### Cryptography and Privacy Engineering Group at TU Darmstadt : OTExtension
[https://github.com/encryptogroup/OTExtension](https://github.com/encryptogroup/OTExtension)

An OT extension library for ARM64 processors. The library implement this OT Extension algorithms:

- General OT
- Correlated OT
- Global correlated OT
- Sender random OT
- Receiver random OT


##### University of Bristol: Advanced Protocols for Real-world Implementation of Computational Oblivious Transfers
[https://github.com/bristolcrypto/apricot](https://github.com/bristolcrypto/apricot)

##### Tung Chou and Claudio Orlandi: The Simplest Oblivious Transfer Protocol
[http://users-cs.au.dk/orlandi/simpleOT/](http://users-cs.au.dk/orlandi/simpleOT/)

### Math and General Purpose Libraries

##### OpenSSL
[https://www.openssl.org/](https://www.openssl.org/)

OpenSSL is an open source project that provides a robust, commercial-grade, and full-featured toolkit for the 
Transport Layer Security (TLS) and Secure Sockets Layer (SSL) protocols.  
It is also a general-purpose cryptography library. For more information about the team and community around the project,    
or to start making your own contributions, start with the community page.  
To get the latest news, download the source, and so on, please see the sidebar or the buttons at the top of every page.

##### The GNU Multiple Precision Arithmetic Library (GMP)
[https://gmplib.org/](https://gmplib.org/)

GMP is a free library for arbitrary precision arithmetic, operating on signed integers, rational numbers,  
and floating-point numbers. There is no practical limit to the precision except the ones implied by the  
available memory in the machine GMP runs on. GMP has a rich set of functions, and the functions have a regular interface.
The main target applications for GMP are cryptography applications and research,  
Internet security applications, algebra systems, computational algebra research, etc.

##### NTL: A Library for doing Number Theory- Victor Shoup
[http://www.shoup.net/ntl/](http://www.shoup.net/ntl/)

NTL is a high-performance, portable C++ library providing data structures and algorithms for manipulating signed,  
arbitrary length integers, and for vectors, matrices, and polynomials over the integers and over finite fields.  
On modern platforms supporting C++11, NTL can be compiled in thread safe and exception safe modes. 

##### Boost
[http://www.boost.org/](http://www.boost.org/)

Boost provides free peer-reviewed portable C++ source libraries.  
We emphasize libraries that work well with the C++ Standard Library.  
Boost libraries are intended to be widely useful, and usable across a broad spectrum of applications.

##### KCP
[https://github.com/skywind3000/kcp/blob/master/README.en.md](https://github.com/skywind3000/kcp/blob/master/README.en.md)

A library for fast and reliable protocol for TCP/UDP.

