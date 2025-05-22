cmake_minimum_required(VERSION 3.16)

project(rtp_decypher LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PCAPPP_ROOT      "${CMAKE_SOURCE_DIR}/external/PcapPlusPlus" CACHE PATH "")

include_directories(
    ${PCAPPP_ROOT}/include        # PcapPlusPlus-Header
)

link_directories(
    ${PCAPPP_ROOT}/lib            # PcapPlusPlus-Libs
    C:/msys64/mingw64/lib
)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)

add_library(rtp_decypher_lib STATIC
  fileutils.cpp
  pcapreader.cpp
  streamanalyzer.cpp
  rtpparser.cpp
)

target_link_libraries(rtp_decypher_lib
  Qt${QT_VERSION_MAJOR}::Core
  Pcap++
  Packet++
  Common++
  pcap
  ws2_32
  iphlpapi
)

add_executable(rtp_decypher
  main.cpp
  fileutils.h fileutils.cpp
  pcapreader.h pcapreader.cpp
  streamanalyzer.h streamanalyzer.cpp
  rtpparser.h rtpparser.cpp
)
target_link_libraries(rtp_decypher
  Qt${QT_VERSION_MAJOR}::Core
  rtp_decypher_lib
)

include(GNUInstallDirs)
install(TARGETS rtp_decypher
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
add_subdirectory(tests)
