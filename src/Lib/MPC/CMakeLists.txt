cmake_minimum_required(VERSION 3.5)
project(scapi)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mavx -maes -msse4.1 -mpclmul -DRDTSC -DTEST=AES128  -O3 -mbmi2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx -maes -msse4.1 -mpclmul -O3")

SET(SCAPI_BASE_DIR $ENV{HOME}/libscapi)
SET(CMAKE_AR  "gcc-ar")
SET(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> qcs <TARGET> <LINK_FLAGS> <OBJECTS>")
SET(CMAKE_CXX_ARCHIVE_FINISH   true)

INCLUDE_DIRECTORIES($ENV{HOME} ${SCAPI_BASE_DIR}/install/include
        ${SCAPI_BASE_DIR}/lib/OTExtensionBristol $ENV{HOME}/libOTe $ENV{HOME}/libOTe/cryptoTools)
link_directories(/usr/ssl/lib/ $ENV{HOME}/libscapi/install/lib )


set(SOURCE_FILES
        src/circuits/BooleanCircuits.cpp
        src/circuits/FourToTwoGarbledBoleanCircuitNoAssumptions.cpp
        src/circuits/FreeXorGarbledBooleanCircuit.cpp
        src/circuits/GarbledBooleanCircuit.cpp
        src/circuits/GarbledBooleanCircuitNoIntrinsics.cpp
        src/circuits/GarbledBooleanCircuitFixedKey.cpp
        src/circuits/GarbledBooleanCircuitNoFixedKey.cpp
        src/circuits/GarbledCircuitFactory.cpp
        src/circuits/HalfGatesGarbledBoleanCircuitNoFixedKey.cpp
        src/circuits/HalfGatesGarbledBooleanCircuit.cpp
        src/circuits/RowReductionGarbledBooleanCircuit.cpp
        src/circuits/StandardGarbledBooleanCircuit.cpp
        src/circuits/TedKrovetzAesNiWrapperC.cpp
        src/circuits/ArithmeticCircuit.cpp
        src/comm/Comm.cpp
        src/comm/CommUDP.cpp
        src/comm/MPCCommunication.cpp
        tools/circuits/scapiBristolConverter/CircuitConverter.cpp
        src/infra/Common.cpp
        src/infra/ConfigFile.cpp
        src/infra/MathAlgorithms.cpp
        src/infra/Scanner.cpp
        src/interactive_mid_protocols/CommitmentSchemeElGamal.cpp
        src/interactive_mid_protocols/CommitmentSchemeElGamalHash.cpp
        src/interactive_mid_protocols/CommitmentSchemePedersen.cpp
        src/interactive_mid_protocols/CommitmentSchemePedersenHash.cpp
        src/interactive_mid_protocols/CommitmentSchemeSimpleHash.cpp
        src/interactive_mid_protocols/OT.cpp
        src/interactive_mid_protocols/OTExtensionBristol.cpp
        src/interactive_mid_protocols/OTFullSimulation.cpp
        src/interactive_mid_protocols/OTFullSimulationROM.cpp
        src/interactive_mid_protocols/OTOneSidedSimulation.cpp
        src/interactive_mid_protocols/OTPrivacyOnly.cpp
        src/interactive_mid_protocols/OTSemiHonest.cpp
        src/interactive_mid_protocols/OTUC.cpp
        src/interactive_mid_protocols/SigmaProtocol.cpp
        src/interactive_mid_protocols/SigmaProtocolAnd.cpp
        src/interactive_mid_protocols/SigmaProtocolCramerShoupEncryptedValue.cpp
        src/interactive_mid_protocols/SigmaProtocolDamgardJurikEncryptedValue.cpp
        src/interactive_mid_protocols/SigmaProtocolDamgardJurikEncryptedZero.cpp
        src/interactive_mid_protocols/SigmaProtocolDamgardJurikProduct.cpp
        src/interactive_mid_protocols/SigmaProtocolDH.cpp
        src/interactive_mid_protocols/SigmaProtocolDHExtended.cpp
        src/interactive_mid_protocols/SigmaProtocolDlog.cpp
        src/interactive_mid_protocols/SigmaProtocolElGamalCmtKnowledge.cpp
        src/interactive_mid_protocols/SigmaProtocolElGamalCommittedValue.cpp
        src/interactive_mid_protocols/SigmaProtocolElGamalEncryptedValue.cpp
        src/interactive_mid_protocols/SigmaProtocolElGamalPrivateKey.cpp
        src/interactive_mid_protocols/SigmaProtocolOrMultiple.cpp
        src/interactive_mid_protocols/SigmaProtocolOrTwo.cpp
        src/interactive_mid_protocols/SigmaProtocolPedersenCmtKnowledge.cpp
        src/interactive_mid_protocols/SigmaProtocolPedersenCommittedValue.cpp
        src/interactive_mid_protocols/ZeroKnowledge.cpp
        src/mid_layer/CramerShoupEnc.cpp
        src/mid_layer/DamgardJurikEnc.cpp
        src/mid_layer/ElGamalEnc.cpp
        src/mid_layer/OpenSSLSymmetricEnc.cpp
        src/primitives/Dlog.cpp
        src/primitives/DlogCryptopp.cpp
        src/primitives/DlogOpenSSL.cpp
        src/primitives/HashOpenSSL.cpp
        src/primitives/Kdf.cpp
        src/primitives/prf.cpp
        src/primitives/PrfOpenSSL.cpp
        src/primitives/Prg.cpp
        src/primitives/RandomOracle.cpp
        src/primitives/TrapdoorPermutation.cpp
        src/primitives/TrapdoorPermutationOpenSSL.cpp
        include/primitives/Mersenne.hpp
        src/primitives/Mersenne.cpp
        include/primitives/Matrix.hpp
        src/infra/Measurement.cpp
        src/cryptoInfra/Protocol.cpp src/mid_layer/OpenSSLMac.cpp include/mid_layer/OpenSSLMac.h)

add_library(scapi ${SOURCE_FILES})

add_custom_target(scapi_build ALL
        COMMAND sudo make -f makefile_libs
        WORKING_DIRECTORY ${SCAPI_BASE_DIR}
        COMMENT "Original libscapi libs makefile target")

TARGET_LINK_LIBRARIES(scapi gmp libboost_system.a libboost_thread.a pthread crypto dl ssl z)
