cmake_minimum_required(VERSION 3.16)

project(
    PostQuantumGateway
    VERSION 1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

find_library(
    OQS_LIBRARY
    NAMES oqs
    PATHS
        $ENV{HOME}/.local/lib
        /usr/local/lib
        /usr/lib
)

if(NOT OQS_LIBRARY)
    message(FATAL_ERROR "liboqs library not found")
endif()

find_library(
    ZMQ_LIBRARY
    NAMES zmq
    PATHS
        /usr/lib
        /usr/local/lib
        /usr/lib/x86_64-linux-gnu
)

if(NOT ZMQ_LIBRARY)
    message(FATAL_ERROR "ZeroMQ library not found")
endif()

message(STATUS "ZeroMQ library: ${ZMQ_LIBRARY}")
message(STATUS "liboqs library: ${OQS_LIBRARY}")

add_executable(
    gateway
    src/main.cpp
    src/pqc_manager.cpp
    src/ai_enforcement.cpp
    src/ai_decision_receiver.cpp
)

target_include_directories(
    gateway
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../Crow/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    $ENV{HOME}/.local/include
)

target_link_libraries(
    gateway
    PRIVATE
    CURL::libcurl
    OpenSSL::Crypto
    ${OQS_LIBRARY}
    ${ZMQ_LIBRARY}
)

add_executable(
    pqc_client
    ../tests/pqc_client/main.cpp
)

target_include_directories(
    pqc_client
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../Crow/include
    $ENV{HOME}/.local/include
)

target_link_libraries(
    pqc_client
    PRIVATE
    CURL::libcurl
    OpenSSL::Crypto
    ${OQS_LIBRARY}
)
