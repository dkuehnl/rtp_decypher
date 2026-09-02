cmake_minimum_required(VERSION 3.16)

project(rtp_decypher VERSION 0.3 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

if (MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

set(PCAPPP_ROOT "${CMAKE_SOURCE_DIR}/external/PcapPlusPlus" CACHE PATH "Path to a PcapPlusPlus install (include/ and lib/ subfolders)")

include_directories(
    ${PCAPPP_ROOT}/include        # PcapPlusPlus headers
)

link_directories(
    ${PCAPPP_ROOT}/lib            # PcapPlusPlus libs
    C:/msys64/mingw64/lib
)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Widgets)

add_subdirectory(src)

include(GNUInstallDirs)
install(TARGETS rtp_decypher
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

enable_testing()
add_subdirectory(tests)
