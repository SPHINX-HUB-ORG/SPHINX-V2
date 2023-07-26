cmake_minimum_required(VERSION 3.5)
project(libscapi_example)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mavx -maes -msse4.1 -mpclmul -mbmi2 -g -fPIC")

SET(SCAPI_BASE_DIR $ENV{HOME}/libscapi)

INCLUDE_DIRECTORIES($ENV{HOME} ${SCAPI_BASE_DIR}/install/include
        ${SCAPI_BASE_DIR}/lib/OTExtensionBristol)
link_directories(/usr/ssl/lib/ $ENV{HOME}/libscapi/install/lib)

set(SOURCE_FILES examples_main.cpp Comm/comm_example.cpp Commitment/CommitmentExample.cpp OT/OTExample.cpp
        SigmaProtocols/SigmaProtocolExample.cpp
        Simple/simple_dlog.cpp Simple/simple_gmac.cpp Simple/simple_sha1.cpp)

add_executable(libscapi_example ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(libscapi_example
        ${SCAPI_BASE_DIR}/libscapi.a
        boost_system boost_thread boost_serialization
        pthread gmp dl crypto ssl z)
