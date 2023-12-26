cmake_minimum_required(VERSION 3.20)

include_guard()

project(SignatureScannerCWrapper)

add_library(SignatureScannerCWrapper STATIC "${PROJECT_SOURCE_DIR}/Source/SignatureScannerWrapper.cpp")
target_include_directories(SignatureScannerCWrapper PUBLIC "${PROJECT_SOURCE_DIR}/Include")
target_compile_options(SignatureScannerCWrapper PRIVATE "-Ofast" "-Wno-conversion-null")
target_compile_features(SignatureScannerCWrapper PRIVATE cxx_std_17)

target_link_libraries(SignatureScannerCWrapper PUBLIC SignatureScanner)
