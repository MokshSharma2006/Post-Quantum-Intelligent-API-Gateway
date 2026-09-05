cmake_minimum_required(VERSION 3.16)

project(PostQuantumGateway
    VERSION 1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(CURL REQUIRED)

add_executable(gateway
    src/main.cpp
)

target_include_directories(gateway PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../Crow/include
)

target_link_libraries(gateway PRIVATE
    CURL::libcurl
)
