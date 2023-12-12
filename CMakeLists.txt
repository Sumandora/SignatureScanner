cmake_minimum_required(VERSION 3.20)

if(TARGET SignatureScanner)
	return()
endif()

project(SignatureScanner)

add_library(SignatureScanner STATIC "${PROJECT_SOURCE_DIR}/Source/Patterns/Constructors.cpp" "${PROJECT_SOURCE_DIR}/Source/Patterns/Search.cpp" "${PROJECT_SOURCE_DIR}/Source/XRef/Constructors.cpp" "${PROJECT_SOURCE_DIR}/Source/XRef/Search.cpp")
target_include_directories(SignatureScanner PUBLIC "${PROJECT_SOURCE_DIR}/Include")
target_compile_options(SignatureScanner PRIVATE "-Ofast")
target_compile_features(SignatureScanner PRIVATE cxx_std_17)

if(PROJECT_IS_TOP_LEVEL)
	add_executable(SignatureScannerExample "${PROJECT_SOURCE_DIR}/Example/Main.cpp")
	target_link_libraries(SignatureScannerExample PRIVATE SignatureScanner)
	target_link_options(SignatureScannerExample PRIVATE "-rdynamic") # Embed function names into the example binary

	enable_testing()
	add_test(NAME SignatureScannerTest COMMAND $<TARGET_FILE:SignatureScannerExample>)

	# C Support, is available by using the C wrapper
	add_subdirectory("CWrapper")

	add_executable(SignatureScannerExampleC "${PROJECT_SOURCE_DIR}/ExampleC/Main.c")
	target_link_libraries(SignatureScannerExampleC PRIVATE SignatureScannerCWrapper)
	target_link_options(SignatureScannerExampleC PRIVATE "-rdynamic") # Embed function names into the example binary
	target_compile_options(SignatureScannerExampleC PRIVATE "-Wno-int-conversion" "-Wno-pointer-integer-compare")

	add_test(NAME SignatureScannerTestC COMMAND $<TARGET_FILE:SignatureScannerExampleC>)
endif()
