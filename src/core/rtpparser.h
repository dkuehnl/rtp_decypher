#ifndef RTPPARSER_H
#define RTPPARSER_H

#include <cstddef>
#include <cstdint>

/// @brief A parsed RTP header plus a view onto its payload.
///
/// rtp_payload points into the buffer passed to RtpParser::parse_rtp(); it
/// is only valid as long as that buffer is alive.
struct RtpLayer {
    uint8_t  version;      ///< RTP version field (expected to be 2).
    bool     padding;      ///< Padding flag (currently unused by the parser).
    bool     extension;    ///< Extension flag (currently unused by the parser).
    uint8_t  csrc_count;   ///< CSRC count (currently unused by the parser).

    bool     marker;       ///< Marker bit (currently unused by the parser).
    uint8_t  payload_type; ///< RTP payload type.

    uint16_t sequence_nbr; ///< RTP sequence number.
    uint32_t timestamp;    ///< RTP timestamp.
    uint32_t ssrc;         ///< Synchronization source identifier.

    const uint8_t* rtp_payload;     ///< Pointer to the RTP payload bytes.
    size_t         rtp_payload_size; ///< Size of the RTP payload in bytes.
};

/// @brief Minimal RTP (RFC 3550) header parsing over a raw UDP payload.
namespace RtpParser {

/// @brief Checks whether the bytes at @p offset look like an RTP header.
///
/// Only checks that at least 12 bytes are available from @p offset and that
/// the version field equals 2 -- it does not otherwise validate the header.
/// @param udp_data Raw UDP payload buffer.
/// @param len Length of @p udp_data in bytes.
/// @param offset Byte offset into @p udp_data where the RTP header would start.
/// @return true if the data at @p offset plausibly starts an RTP header.
bool is_rtp(const uint8_t* udp_data, size_t len, size_t offset);

/// @brief Parses an RTP header at @p offset into @p udp_data.
///
/// Returns a default-constructed (all-zero) RtpLayer if is_rtp() would
/// return false for the same arguments.
/// @param udp_data Raw UDP payload buffer.
/// @param upd_length Length of @p udp_data in bytes.
/// @param offset Byte offset into @p udp_data where the RTP header starts.
/// @return The parsed RTP header and a view onto its payload.
RtpLayer parse_rtp(const uint8_t* udp_data, size_t upd_length, size_t offset);

}
#endif // RTPPARSER_H
