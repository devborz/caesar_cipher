cmake_minimum_required(VERSION 3.10.2:)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_COVERAGE "Build coverage" OFF)

set(
 HUNTER_CACHE_SERVERS
 "https://github.com/bmstu-iu8-cpp-sem-3/hunter-cache"
 CACHE STRING "Default cache server"
)

include("cmake/HunterGate.cmake")

huntergate(
 URL "https://github.com/ruslo/hunter/archive/v0.23.34.tar.gz"
 SHA1 "70287b1ffa810ee4e952052a9adff9b4856d0d54"
)

project(my_project)

hunter_add_package(GTest)

find_package(GTest CONFIG REQUIRED)

add_library(caesar_cipher INTERFACE
)

add_executable(main
  ${CMAKE_CURRENT_SOURCE_DIR}/sources/main.cpp)

add_executable(tests
  ${CMAKE_CURRENT_SOURCE_DIR}/tests/test.cpp)

target_include_directories(caesar_cipher INTERFACE
  $<BUILD_INTERFACE:${${PROJECT_NAME}_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(main caesar_cipher)
target_link_libraries(tests caesar_cipher GTest::main)

enable_testing()
add_test(NAME unit_tests COMMAND tests)
