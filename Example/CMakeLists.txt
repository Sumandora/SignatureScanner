add_executable(SignatureScannerExample "CXX/Main.cpp")
target_link_libraries(SignatureScannerExample PRIVATE SignatureScanner)
target_link_options(SignatureScannerExample PRIVATE "-rdynamic") # Embed function names into the example binary

# C Support, is available by using the C wrapper
add_subdirectory("../CWrapper" "CWrapper")

add_executable(SignatureScannerExampleC "C/Main.c")
target_link_libraries(SignatureScannerExampleC PRIVATE SignatureScannerCWrapper)
target_link_options(SignatureScannerExampleC PRIVATE "-rdynamic") # Embed function names into the example binary
target_compile_options(SignatureScannerExampleC PRIVATE "-Wno-int-conversion" "-Wno-pointer-integer-compare")

enable_testing()
add_test(NAME SignatureScannerTest COMMAND $<TARGET_FILE:SignatureScannerExample>)
add_test(NAME SignatureScannerTestC COMMAND $<TARGET_FILE:SignatureScannerExampleC>)