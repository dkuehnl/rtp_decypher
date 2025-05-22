#include <QtTest>
#include <winsock2.h>
#include "../streamanalyzer.h"

std::vector<uint8_t> make_valid_rtp_payload(uint16_t sequence_number = 1234, uint32_t timestamp = 1, uint32_t ssrc = 0xDEADBEEF) {
    // 12-Byte RTP-Header + 4-Byte Nutzdaten (codec-abhängig)
    std::vector<uint8_t> rtp = {
        0x80, 0x08,             // V=2, P=0, X=0, CC=0 | M=0, PT=8
        0x12, 0x34,             // SeqNum = 0x1234
        0x00,0x00,0x00,0x01,    // Timestamp = 1
        0xDE,0xAD,0xBE,0xEF,    // SSRC = 0xDEADBEEF
        // RTP-Payload (Dummy-Audio/Video-Bytes)
        0x11,0x22,0x33,0x44
    };

    rtp[2] = static_cast<uint8_t>((sequence_number >> 8) & 0xFF);
    rtp[3] = static_cast<uint8_t>(sequence_number & 0xFF);

    rtp[4] = static_cast<uint8_t>((timestamp >> 24) & 0xFF);
    rtp[5] = static_cast<uint8_t>((timestamp >> 16) & 0xFF);
    rtp[6] = static_cast<uint8_t>((timestamp >> 8) & 0xFF);
    rtp[7] = static_cast<uint8_t>(timestamp & 0xFF);

    rtp[8] = static_cast<uint8_t>((ssrc >> 24) & 0xFF);
    rtp[9] = static_cast<uint8_t>((ssrc >> 16) & 0xFF);
    rtp[10] = static_cast<uint8_t>((ssrc >> 8) & 0xFF);
    rtp[11] = static_cast<uint8_t>(ssrc & 0xFF);

    return rtp;
}

std::vector<PacketInfo> make_dummy_rtp_stream(
    int num_packets = 50,
    uint32_t ssrc = 0xDEADBEEF,
    uint32_t start_timestamp = 1,
    uint16_t start_seq = 10,
    uint32_t timestamp_incre = 160) {
    static std::vector<std::shared_ptr<std::vector<uint8_t>>> storage;
    storage.clear();

    std::vector<PacketInfo> stream;
    stream.reserve(num_packets);

    for (int i = 0; i < num_packets; i++) {
        uint16_t seq = start_seq + i;
        uint32_t ts = start_timestamp + i * timestamp_incre;

        auto payload_ptr = std::make_shared<std::vector<uint8_t>>(make_valid_rtp_payload(seq, ts, ssrc));
        storage.push_back(payload_ptr);

        PacketInfo packet;
        packet.source_ip = "192.168.178.1";
        packet.destination_ip = "217.0.178.1";
        packet.source_port = 30569;
        packet.destination_port = 56123;
        packet.payload_size = payload_ptr->size();
        packet.payload = payload_ptr->data();

        stream.push_back(packet);
    }
    return stream;
}

PacketInfo make_dummy_packet_info() {
    static std::vector<uint8_t> raw = make_valid_rtp_payload();

    PacketInfo pi;
    pi.source_ip        = "192.168.0.100";
    pi.destination_ip   = "192.168.0.200";
    pi.source_port      = 5004;
    pi.destination_port = 5004;
    pi.payload_size     = raw.size();
    pi.payload          = raw.data();  // Zeiger auf die Rohdaten

    return pi;
}

class TestStreamAnalyzer : public QObject
{
    Q_OBJECT

private slots:
    void test_get_rtp_codecs();
    void test_get_rtp_ssrcs();
    void test_check_sequence();
};

void TestStreamAnalyzer::test_get_rtp_codecs() {
    std::vector<PacketInfo> stream{ make_dummy_packet_info() };
    StreamAnalyzer sa(stream);

    QList<uint8_t> codecs = sa.get_codecs();
    QCOMPARE(codecs.size(), 1);

    for (const auto& codec : codecs) {
        QCOMPARE(codec, uint8_t(8));
    }
}

void TestStreamAnalyzer::test_get_rtp_ssrcs() {
    std::vector<PacketInfo> stream{ make_dummy_packet_info() };
    StreamAnalyzer sa(stream);

    QList<uint32_t> ssrcs = sa.get_ssrcs();
    QCOMPARE(ssrcs.size(), 1);

    for (const auto& ssrc : ssrcs) {
        QCOMPARE(ssrc, uint32_t(0xDEADBEEF));
    }
}

void TestStreamAnalyzer::test_check_sequence() {
    auto stream = make_dummy_rtp_stream();
    StreamAnalyzer sa(stream);

    SequenceStat stat = sa.analyse_sequence(0xDEADBEEF);
    QCOMPARE(stat.expected_pkt, 50);
    QCOMPARE(stat.actual_pkt, 50);
    QCOMPARE(stat.rollover, 0);
    QCOMPARE(stat.seq_break, false);
}

QTEST_APPLESS_MAIN(TestStreamAnalyzer)

#include "tst_streamanalyzer.moc"
