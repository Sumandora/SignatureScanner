include("FetchContent")
FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest
        GIT_PROGRESS TRUE
        GIT_TAG v1.15.2
)
FetchContent_MakeAvailable(googletest)
include("GoogleTest")

add_executable(SignatureScannerTests "Source/Main.cpp")
target_link_libraries(SignatureScannerTests PRIVATE SignatureScanner GTest::gtest_main)

gtest_discover_tests(SignatureScannerTests)
