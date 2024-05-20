include_guard()

project(PatternSignature)
add_library(PatternSignature INTERFACE)
target_include_directories(PatternSignature INTERFACE "${PROJECT_SOURCE_DIR}/Include")

target_link_libraries(PatternSignature INTERFACE SignatureScanner)
