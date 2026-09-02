add_library(rtp_decypher_lib STATIC
    pcapreader.h pcapreader.cpp
    rtpparser.h rtpparser.cpp
    streamanalyzer.h streamanalyzer.cpp
)

target_include_directories(rtp_decypher_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(rtp_decypher_lib PUBLIC
    Qt${QT_VERSION_MAJOR}::Core
    Pcap++
    Packet++
    Common++
    pcap
    ws2_32
    iphlpapi
)
