include("FetchContent")
FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest
        GIT_PROGRESS TRUE
        GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

add_subdirectory("../Modules/Pattern" "PatternSignatures")
add_subdirectory("../Modules/XRef" "XRefSignatures")

add_executable(SignatureScannerTests "Source/Main.cpp")
target_link_libraries(SignatureScannerTests PRIVATE PatternSignature XRefSignature GTest::gtest_main)
target_link_options(SignatureScannerTests PRIVATE "-rdynamic") # Embed function names into the example binary

include("GoogleTest")
gtest_discover_tests(SignatureScannerTests)
