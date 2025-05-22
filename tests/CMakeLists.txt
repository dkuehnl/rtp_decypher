cmake_minimum_required(VERSION 3.16)

project(TestPcapReader LANGUAGES CXX)

enable_testing()

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Test)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Test)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(TestPcapReader tst_pcapreader.cpp)
target_link_libraries(TestPcapReader
    Qt${QT_VERSION_MAJOR}::Test
    rtp_decypher_lib
)
add_test(NAME TestPcapReader COMMAND TestPcapReader)

add_executable(TestStreamAnalyzer tst_streamanalyzer.cpp)
target_link_libraries(TestStreamAnalyzer
    Qt${QT_VERSION_MAJOR}::Test
    rtp_decypher_lib
)
add_test(NAME TestStreamAnalyzer COMMAND TestStreamAnalyzer)

add_executable(TestRtpParser tst_rtpparser.cpp)
target_link_libraries(TestRtpParser
    Qt${QT_VERSION_MAJOR}::Test
    rtp_decypher_lib
)
add_test(NAME TestRtpParser COMMAND TestRtpParser)
