cmake_minimum_required(VERSION 3.20)
project(IDASignatureScanner)

set(CMAKE_CXX_STANDARD 23)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_executable(IDASignatureScanner Source/IDASignatureScanner.cpp Example/Main.cpp)
target_include_directories(IDASignatureScanner PRIVATE include)