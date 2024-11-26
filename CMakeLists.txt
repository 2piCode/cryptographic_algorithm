cmake_minimum_required(VERSION 3.5)

project(cryptographic_algo VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# set(HEADERS )

set (SOURCES main.cpp)

add_executable(cryptographic_algo ${SOURCES})

target_include_directories(cryptographic_algo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
