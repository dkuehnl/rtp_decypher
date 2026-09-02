#ifndef RTPPARSER_H
#define RTPPARSER_H

#include <cstddef>
#include <cstdint>

struct RtpLayer {
    uint8_t  version;
    bool     padding;
    bool     extension;
    uint8_t  csrc_count;

    bool     marker;
    uint8_t  payload_type;

    uint16_t sequence_nbr;
    uint32_t timestamp;
    uint32_t ssrc;

    const uint8_t* rtp_payload;
    size_t         rtp_payload_size;
};

namespace RtpParser {

bool is_rtp(const uint8_t* udp_data, size_t len, size_t offset);
RtpLayer parse_rtp(const uint8_t* udp_data, size_t upd_length, size_t offset);

}
#endif // RTPPARSER_H
