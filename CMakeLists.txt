cmake_minimum_required(VERSION 3.20)
project(cygnet_provider VERSION 0.1.3 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

add_subdirectory(provider)
enable_testing()
add_subdirectory(tests)
