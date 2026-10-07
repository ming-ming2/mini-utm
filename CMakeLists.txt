cmake_minimum_required(VERSION 3.20)
project(mini_utm LANGUAGES CXX)

# C++20, 컴파일러 확장 없이
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# VS Code 등 에디터가 include 경로·옵션을 알 수 있도록 build/compile_commands.json 생성
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-Wall -Wextra -Wpedantic)

# libpcap: 시스템에 설치된 pkg-config 정보로 찾는다
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)

# main.cpp를 뺀 본체. 실행 파일과 테스트가 같이 쓴다
add_library(mini_utm_core STATIC
    src/capture.cpp
    src/config.cpp
    src/decoder.cpp
    src/firewall.cpp
    src/portscan.cpp
    src/logger.cpp
)
target_include_directories(mini_utm_core PUBLIC src)
target_link_libraries(mini_utm_core PUBLIC PkgConfig::PCAP)

# 실행 파일
add_executable(mini_utm src/main.cpp)
target_link_libraries(mini_utm PRIVATE mini_utm_core)

# 테스트 (Catch2 v2). tests/data를 상대 경로로 열므로 프로젝트 루트에서 실행한다
enable_testing()
find_package(Catch2 2 REQUIRED)

add_executable(unit_tests
    tests/test_main.cpp
    tests/capture_test.cpp
    tests/config_test.cpp
    tests/decoder_test.cpp
    tests/firewall_test.cpp
    tests/logger_test.cpp
    tests/portscan_test.cpp
)
target_link_libraries(unit_tests PRIVATE mini_utm_core Catch2::Catch2)

include(Catch)
catch_discover_tests(unit_tests WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
