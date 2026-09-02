#ifndef STREAMANALYZER_H
#define STREAMANALYZER_H

#include "pcapreader.h"
#include "rtpparser.h"

#include <map>
#include <QList>

/// @brief Sequence-number analysis result for a single SSRC's RTP stream.
struct SequenceStat {
    size_t expected_pkt = 0; ///< Packets expected, derived from first/last sequence number and detected rollovers.
    size_t actual_pkt = 0;   ///< Packets actually present for this SSRC.
    size_t rollover = 0;     ///< Number of detected 16-bit sequence-number rollovers.
    bool seq_break = false;  ///< Whether a forward gap (> 1) in sequence numbers was detected.
};

/// @brief Parses the RTP packets within one UDP flow and groups them by SSRC.
///
/// Construction runs RtpParser::parse_rtp() over every packet in the given
/// stream (skipping any that don't parse as RTP) and buckets the results by
/// SSRC; analyse_sequence() then computes loss/rollover statistics per SSRC.
class StreamAnalyzer
{
public:
    /// @brief Parses the given UDP packet stream as RTP.
    /// @param stream UDP packets belonging to a single flow (see PcapReader::get_stream()).
    /// @param offset Byte offset into each packet's payload where the RTP header starts.
    StreamAnalyzer(const std::vector<PacketInfo>& stream, size_t offset = 0);

    /// @return The RTP payload types seen across all parsed packets (not deduplicated).
    const QList<uint8_t>& get_codecs();

    /// @return The distinct SSRCs found in the stream.
    QList<uint32_t> get_ssrcs();

    /// @brief Computes sequence-number statistics for one SSRC.
    /// @param ssrc SSRC to analyse.
    /// @return Packet-count and rollover/gap statistics for that SSRC.
    SequenceStat analyse_sequence(uint32_t ssrc);

    /// @brief Looks up the parsed RTP packets for one SSRC.
    /// @param ssrc SSRC to look up.
    /// @return The parsed RtpLayer entries for that SSRC, or empty if unknown.
    std::vector<RtpLayer> get_rtp_stream(uint32_t ssrc);

    /// @brief Number of RTP packets recorded for the given SSRC.
    /// @param ssrc SSRC to look up.
    /// @return Packet count for that SSRC, or 0 if unknown.
    size_t get_rtp_per_ssrc(uint32_t ssrc);

private:
    std::vector<PacketInfo> m_stream;
    std::map<uint32_t, std::vector<RtpLayer>> m_rtp_stream;
    QList<uint8_t> m_codecs{};
    size_t m_offset;

    /// @brief Parses m_stream into m_rtp_stream/m_codecs.
    void parse_stream();
};

#endif // STREAMANALYZER_H
