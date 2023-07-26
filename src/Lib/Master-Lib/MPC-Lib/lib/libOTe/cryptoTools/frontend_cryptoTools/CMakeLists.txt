

file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR})

add_executable(frontend_cryptoTools  ${SRCS})
if (APPLE)
target_link_libraries(frontend_cryptoTools cryptoTools tests_cryptoTools boost_system-mt boost_thread-mt)
else()
target_link_libraries(frontend_cryptoTools cryptoTools tests_cryptoTools boost_system boost_thread)
endif()
