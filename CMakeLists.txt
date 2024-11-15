cmake_minimum_required(VERSION 3.20)

include_guard()

project(SignatureScanner)

option(
	SIGNATURESCANNER_OPTIMIZE
	"Adds optimized translation units, which contain optimized versions of search functions. A side-effect is that the library is no longer header only."
	ON)
set(SIGNATURESCANNER_OPTIMIZE_FLAGS "-O3" CACHE STRING "Specifies the flags used to optimize the translation units")

if(SIGNATURESCANNER_OPTIMIZE)
	add_library(SignatureScanner STATIC "${PROJECT_SOURCE_DIR}/Source/PatternSignature.cpp"
										"${PROJECT_SOURCE_DIR}/Source/XRefSignature.cpp")
	target_include_directories(SignatureScanner PUBLIC "${PROJECT_SOURCE_DIR}/Include")
	target_compile_definitions(SignatureScanner PUBLIC "SIGNATURESCANNER_OPTIMIZE")
	target_compile_features(SignatureScanner PUBLIC cxx_std_23)
	target_compile_options(SignatureScanner PRIVATE "${SIGNATURESCANNER_OPTIMIZE_FLAGS}")
else()
	add_library(SignatureScanner INTERFACE)
	target_include_directories(SignatureScanner INTERFACE "${PROJECT_SOURCE_DIR}/Include")
	target_compile_features(SignatureScanner INTERFACE cxx_std_23)
endif()

if(PROJECT_IS_TOP_LEVEL)
	enable_testing()
	add_subdirectory("Example")
endif()
