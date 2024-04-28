cmake_minimum_required(VERSION 3.20)

include_guard()

project(SignatureScanner)

add_library(SignatureScanner INTERFACE)
target_include_directories(SignatureScanner INTERFACE "${PROJECT_SOURCE_DIR}/Include")

if(PROJECT_IS_TOP_LEVEL)
	enable_testing()
	add_subdirectory("Example")
endif()
