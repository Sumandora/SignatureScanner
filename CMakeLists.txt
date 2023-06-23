cmake_minimum_required(VERSION 3.20)
project(SignatureScanner)

set(CMAKE_CXX_STANDARD 23)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_executable(SignatureScanner Source/SignatureScanner.cpp Example/Main.cpp)
target_include_directories(SignatureScanner PRIVATE include)