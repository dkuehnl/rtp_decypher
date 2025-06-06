#include <QtTest>
#include <winsock2.h>
#include "../streamanalyzer.h"

static std::vector<uint8_t> make_valid_rtp_payload(uint16_t sequence_number = 1234,
                                                   uint32_t timestamp = 1,
                                                   uint32_t ssrc = 0xDEADBEEF)
{
    // 12‐Byte RTP‐Header + 4 Byte Nutzdaten
    std::vector<uint8_t> rtp = {
        0x80, 0x08,             // V=2, P=0, X=0, CC=0 | M=0, PT=8
        0x12, 0x34,             // SeqNum = 0x1234 (wird unten überschrieben)
        0x00, 0x00, 0x00, 0x01, // Timestamp = 1 (wird unten überschrieben)
        0xDE, 0xAD, 0xBE, 0xEF, // SSRC = 0xDEADBEEF (wird unten überschrieben)
        // RTP‐Payload (Dummy‐Audio/Video‐Bytes)
        0x11, 0x22, 0x33, 0x44
    };

    // Sequence Number anpassen
    rtp[2]  = static_cast<uint8_t>((sequence_number >> 8) & 0xFF);
    rtp[3]  = static_cast<uint8_t>(sequence_number & 0xFF);

    // Timestamp anpassen
    rtp[4]  = static_cast<uint8_t>((timestamp >> 24) & 0xFF);
    rtp[5]  = static_cast<uint8_t>((timestamp >> 16) & 0xFF);
    rtp[6]  = static_cast<uint8_t>((timestamp >> 8) & 0xFF);
    rtp[7]  = static_cast<uint8_t>(timestamp & 0xFF);

    // SSRC anpassen
    rtp[8]  = static_cast<uint8_t>((ssrc >> 24) & 0xFF);
    rtp[9]  = static_cast<uint8_t>((ssrc >> 16) & 0xFF);
    rtp[10] = static_cast<uint8_t>((ssrc >> 8) & 0xFF);
    rtp[11] = static_cast<uint8_t>(ssrc & 0xFF);

    return rtp;
}


// ----- make_dummy_rtp_stream: generiert einen ganzen RTP‐Stream als Vektor von PacketInfo -----
static std::vector<PacketInfo> make_dummy_rtp_stream(int num_packets = 50,
                                                     uint32_t ssrc = 0xDEADBEEF,
                                                     uint32_t start_timestamp = 1,
                                                     uint16_t start_seq = 10,
                                                     uint32_t timestamp_incre = 160)
{
    std::vector<PacketInfo> stream;
    stream.reserve(num_packets);

    for (int i = 0; i < num_packets; i++) {
        uint16_t seq = static_cast<uint16_t>(start_seq + i);
        uint32_t ts  = start_timestamp + i * timestamp_incre;

        // 1) Erstelle das gültige RTP‐Payload (inkl. Header + Nutzdaten)
        std::vector<uint8_t> payload = make_valid_rtp_payload(seq, ts, ssrc);

        // 2) Befülle ein PacketInfo‐Objekt:
        PacketInfo packet;
        packet.source_ip        = "192.168.178.1";
        packet.destination_ip   = "217.0.178.1";
        packet.source_port      = 30569;
        packet.destination_port = 56123;
        packet.payload_size     = payload.size();

        // 3) Jetzt den Payload‐Vector direkt kopieren (deep copy)
        packet.payload = std::move(payload);

        // 4) Paket in den Stream aufnehmen
        stream.push_back(std::move(packet));
    }

    return stream;
}


// ----- make_dummy_packet_info: ein einzelnes PacketInfo mit RTP----
static PacketInfo make_dummy_packet_info()
{
    // 1) Baue ein einzelnes RTP‐Payload
    std::vector<uint8_t> raw = make_valid_rtp_payload();

    // 2) Fülle PacketInfo, payload_size und copy des Vektors
    PacketInfo pi;
    pi.source_ip        = "192.168.0.100";
    pi.destination_ip   = "192.168.0.200";
    pi.source_port      = 5004;
    pi.destination_port = 5004;
    pi.payload_size     = raw.size();   // z. B. 16 Bytes
    pi.payload          = std::move(raw); // payload enthält jetzt die Bytes

    return pi;
}

class TestStreamAnalyzer : public QObject
{
    Q_OBJECT

private slots:
    void test_get_rtp_codecs();
    void test_get_rtp_ssrcs();
    void test_check_sequence();
    void test_check_brocken_sequence();
    void test_rollover();
    void test_get_rtp_per_ssrc();
    void test_payload_size();
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

void TestStreamAnalyzer::test_check_brocken_sequence() {
    auto stream = make_dummy_rtp_stream(70, 0xDEADBEEF, 1, 0);

    size_t drop_start = 23;
    size_t drop_count = 10;
    stream.erase(
        stream.begin() + drop_start,
        stream.begin() + drop_start + drop_count);

    QCOMPARE(stream.size(), 60);

    StreamAnalyzer sa(stream);

    SequenceStat stat = sa.analyse_sequence(0xDEADBEEF);
    QCOMPARE(stat.rollover, 0);
    QCOMPARE(stat.seq_break, true);
    QCOMPARE(stat.expected_pkt, 70);
    QCOMPARE(stat.actual_pkt, 60);
}

void TestStreamAnalyzer::test_rollover() {
    auto stream = make_dummy_rtp_stream(30, 0xDEADBEEF, 1, 65530);
    StreamAnalyzer sa(stream);

    SequenceStat stat = sa.analyse_sequence(0xDEADBEEF);
    QCOMPARE(stat.rollover, 1);
    QCOMPARE(stat.seq_break, false);
    QCOMPARE(stat.expected_pkt, 30);
    QCOMPARE(stat.actual_pkt, 30);
}

void TestStreamAnalyzer::test_get_rtp_per_ssrc() {
    auto stream = make_dummy_rtp_stream(50);
    StreamAnalyzer sa(stream);

    size_t count = sa.get_rtp_per_ssrc(0xDEADBEEF);
    QCOMPARE(count, 50);
}

QTEST_APPLESS_MAIN(TestStreamAnalyzer)

#include "tst_streamanalyzer.moc"
