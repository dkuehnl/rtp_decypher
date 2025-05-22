#ifndef STREAMANALYZER_H
#define STREAMANALYZER_H

#include "pcapreader.h"
#include "rtpparser.h"

#include <map>
#include <QList>

struct SequenceStat {
    size_t expected_pkt = 0;
    size_t actual_pkt = 0;
    size_t rollover = 0;
    bool seq_break = false;
};

class StreamAnalyzer
{
public:
    StreamAnalyzer(const std::vector<PacketInfo>& stream);
    const QList<uint8_t>& get_codecs();
    QList<uint32_t> get_ssrcs();
    SequenceStat analyse_sequence(uint32_t ssrc);

private:
    std::vector<PacketInfo> m_stream;
    std::map<uint32_t, std::vector<RtpLayer>> m_rtp_stream;
    QList<uint8_t> m_codecs{};
    size_t m_offset = 0;

    void parse_stream();
};

#endif // STREAMANALYZER_H
