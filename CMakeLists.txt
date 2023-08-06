cmake_minimum_required(VERSION 3.20)
project(SignatureScanner)

set(CMAKE_CXX_STANDARD 23)

set(CMAKE_CXX_FLAGS "-rdynamic")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(SignatureScanner STATIC Source/Patterns/Constructors.cpp Source/Patterns/Search.cpp Source/XRef/Constructors.cpp Source/XRef/Search.cpp)
target_include_directories(SignatureScanner PUBLIC include)

add_executable(SignatureScannerExample Example/Main.cpp)
target_link_libraries(SignatureScannerExample PRIVATE SignatureScanner)

target_compile_definitions(SignatureScanner PRIVATE SIGNATURESCANNER_ENABLE_IDA_SEARCH)
target_compile_definitions(SignatureScanner PRIVATE SIGNATURESCANNER_ENABLE_STRING_SEARCH)
target_compile_definitions(SignatureScanner PRIVATE SIGNATURESCANNER_ENABLE_XREF_SEARCH)

# In case you are running a x64 bit system but you are inspecting a 32 bit binary, you will need to set this:
#target_compile_definitions(SignatureScanner PRIVATE SIGNATURESCANNER_FORCE_32BIT_MODE)

enable_testing()
add_test(NAME SignatureScannerTest COMMAND $<TARGET_FILE:SignatureScannerExample>)
