include_guard()

project(XRefSignature)
add_library(XRefSignature INTERFACE)
target_include_directories(XRefSignature INTERFACE "${PROJECT_SOURCE_DIR}/Include")

target_link_libraries(XRefSignature INTERFACE SignatureScanner)
