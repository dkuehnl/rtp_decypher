#include "streamanalyzer.h"

StreamAnalyzer::StreamAnalyzer(const std::vector<PacketInfo>& stream)
    : m_stream(stream)
{
    if(m_stream.empty()) {
        return;
    }
    StreamAnalyzer::parse_stream();
}

void StreamAnalyzer::parse_stream() {
    for (const auto& element : m_stream) {
        RtpLayer packet = RtpParser::parse_rtp(element.payload, element.payload_size, m_offset);
        if (packet.version != 2) {
            continue;
        }
        m_rtp_stream[packet.ssrc].push_back(packet);
        m_codecs.append(packet.payload_type);
    }
}

const QList<uint8_t>& StreamAnalyzer::get_codecs() {
    return m_codecs;
}

QList<uint32_t> StreamAnalyzer::get_ssrcs() {
    QList<uint32_t> ssrcs;
    for (const auto& [key, value] : m_rtp_stream) {
        ssrcs.append(key);
    }
    return ssrcs;
}

SequenceStat StreamAnalyzer::analyse_sequence(uint32_t ssrc) {
    uint16_t prev_seq;
    SequenceStat stat;
    auto key = m_rtp_stream.find(ssrc);
    if (key != m_rtp_stream.end() && !key->second.empty()) {
        //actual packet-size:
        stat.actual_pkt = key->second.size();

        //Rollover and Sequence-Gap:
        prev_seq = key->second.front().sequence_nbr;
        for (const auto& packet : key->second) {
            uint16_t current_seq = packet.sequence_nbr;

            uint16_t forward_diff = (current_seq - prev_seq) & 0xFFFF;
            uint16_t backward_diff = (prev_seq - current_seq) & 0xFFFF;

            if (backward_diff > 0x8000 && (0xFFFF - prev_seq) < 1000){
                stat.rollover++;
                prev_seq = current_seq;
                continue;
            }

            if ((current_seq - prev_seq) > 1) stat.seq_break = true;
            prev_seq = current_seq;
        }

        //exptected packet-size:
        uint16_t first = key->second.front().sequence_nbr;
        uint16_t last = key->second.back().sequence_nbr;
        uint32_t raw_diff = (uint32_t(last) + stat.rollover  * 65536u) - uint32_t(first);

        stat.expected_pkt = raw_diff + 1;
    }

    return stat;
}
