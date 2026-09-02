#include "rtpparser.h"
#include <QDebug>

bool RtpParser::is_rtp(const uint8_t* udp_data, size_t udp_length, size_t offset) {
    if (udp_length < offset + 12) return false;
    uint8_t version = (udp_data[offset] >> 6) & 0x03;
    return version == 2;
}

RtpLayer RtpParser::parse_rtp(const uint8_t* udp_data, size_t udp_length, size_t offset) {
    if (!is_rtp(udp_data, udp_length, offset)) return {};
    RtpLayer layer{};
    layer.version = (udp_data[offset] >> 6) & 0x03;
    layer.payload_type = udp_data[offset + 1] & 0x7F;
    layer.sequence_nbr = (udp_data[offset + 2] << 8) | udp_data[offset + 3];
    layer.timestamp = (udp_data[offset + 4] << 24) |
                      (udp_data[offset + 5] << 16) |
                      (udp_data[offset + 6] << 8) |
                      udp_data[offset + 7];
    layer.ssrc = (udp_data[offset + 8] << 24) |
                 (udp_data[offset + 9] << 16) |
                 (udp_data[offset + 10] << 8) |
                 udp_data[offset + 11];

    layer.rtp_payload = udp_data + offset + 12;
    layer.rtp_payload_size = udp_length - (offset + 12);

    return layer;

}
