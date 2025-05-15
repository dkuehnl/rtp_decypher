cmake_minimum_required(VERSION 3.16)

project(test_main LANGUAGES CXX)

enable_testing()

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Test)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Test)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(test_main tst_test_main.cpp)

target_link_libraries(test_main
    Qt${QT_VERSION_MAJOR}::Test
    rtp_decypher_lib
)

add_test(NAME test_main COMMAND test_main)
