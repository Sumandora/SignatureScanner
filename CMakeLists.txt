cmake_minimum_required(VERSION 3.20)

include_guard()

project(SignatureScanner)

add_library(SignatureScanner STATIC "${PROJECT_SOURCE_DIR}/Source/Patterns/Constructors.cpp" "${PROJECT_SOURCE_DIR}/Source/Patterns/Search.cpp" "${PROJECT_SOURCE_DIR}/Source/XRef/Constructors.cpp" "${PROJECT_SOURCE_DIR}/Source/XRef/Search.cpp")
target_include_directories(SignatureScanner PUBLIC "${PROJECT_SOURCE_DIR}/Include")
target_compile_options(SignatureScanner PRIVATE "-Ofast")
target_compile_features(SignatureScanner PRIVATE cxx_std_17)

if(PROJECT_IS_TOP_LEVEL)
	add_subdirectory("Example")
endif()
