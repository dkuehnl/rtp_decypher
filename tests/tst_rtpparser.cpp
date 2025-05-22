#include <QtTest>
#include "../rtpparser.h"

#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/UdpLayer.h"

class TestRtpParser : public QObject
{
    Q_OBJECT

private slots:
    void test_is_rtp();
    void test_is_no_rtp();
    void test_real_rtp_pcap();
    void test_ac_rtp_pcap();
    void test_parse_rtp();

private:
    std::vector<uint8_t> make_valid_rtp_payload() {
        // RTP Header-Felder:
        // Byte 0: V=2 (bits 7–6 = 10), P=0, X=0, CC=0  => 0b10'0'0'0000 = 0x80
        // Byte 1: M=0, PT=96                      => 0b0'1100000 = 0x60
        // Bytes 2–3: Sequence Number = 0x1234     => { 0x12, 0x34 }
        // Bytes 4–7: Timestamp = 0x00000001       => { 0x00,0x00,0x00,0x01 }
        // Bytes 8–11: SSRC = 0xDEADBEEF           => { 0xDE,0xAD,0xBE,0xEF }
        std::vector<uint8_t> v = {
            0x80, 0x60, 0x12, 0x34,
            0x00, 0x00, 0x00, 0x01,
            0xDE, 0xAD, 0xBE, 0xEF
        };
        // Hinten dran noch ein paar Nutzdaten (Payload), z.B. 4 Byte „Audio“
        v.insert(v.end(), { 0x11, 0x22, 0x33, 0x44 });
        return v;
    }

    // Dummy 2: komplett zufällige Bytes (kein RTP)
    // Länge hier auf 16 Bytes gesetzt, kann aber beliebig sein
    std::vector<uint8_t> make_random_payload() {
        return {
            0x00, 0xFF, 0x8A, 0xC3,
            0x5D, 0x19, 0xBE, 0xEF,
            0x42, 0x99, 0x37, 0xAC,
            0x10, 0x20, 0x30, 0x40
        };
    }
};

void TestRtpParser::test_is_rtp() {
    auto rtp = TestRtpParser::make_valid_rtp_payload();
    QVERIFY(RtpParser::is_rtp(rtp.data(), rtp.size(), 0));
}

void TestRtpParser::test_is_no_rtp() {
    auto rtp = TestRtpParser::make_random_payload();
    QVERIFY(!RtpParser::is_rtp(rtp.data(), rtp.size(), 0));
}

void TestRtpParser::test_real_rtp_pcap() {
    QString pcap = QFINDTESTDATA("data/test_pcap_small_rtp.pcap");
    QVERIFY(QFile::exists(pcap));

    pcpp::PcapFileReaderDevice reader(pcap.toStdString());
    QVERIFY(reader.open());

    pcpp::RawPacket raw_packet;
    size_t total_packets = 0;
    size_t rtp_count = 0;

    while (reader.getNextPacket(raw_packet)) {
        pcpp::Packet parsed(&raw_packet);
        auto udp_layer = parsed.getLayerOfType<pcpp::UdpLayer>();
        if (!udp_layer) continue;

        total_packets++;
        const uint8_t* payload = udp_layer->getLayerPayload();
        size_t len = udp_layer->getLayerPayloadSize();

        if (RtpParser::is_rtp(payload, len, 0)) {
            rtp_count++;
        }
    }
    reader.close();
    QVERIFY(total_packets > 0);
    QCOMPARE(total_packets, 18);
    QCOMPARE(rtp_count, size_t(18));
}

void TestRtpParser::test_ac_rtp_pcap() {
    QString pcap = QFINDTESTDATA("data/test_pcap_small_rtp_ac.pcap");
    QVERIFY(QFile::exists(pcap));

    pcpp::PcapFileReaderDevice reader(pcap.toStdString());
    QVERIFY(reader.open());

    pcpp::RawPacket raw_packet;
    size_t total_packets = 0;
    size_t rtp_count = 0;

    while (reader.getNextPacket(raw_packet)) {
        pcpp::Packet parsed(&raw_packet);
        auto udp_layer = parsed.getLayerOfType<pcpp::UdpLayer>();
        if (!udp_layer) continue;

        total_packets++;
        const uint8_t* payload = udp_layer->getLayerPayload();
        size_t len = udp_layer->getLayerPayloadSize();

        if (RtpParser::is_rtp(payload, len, 37)) {
            rtp_count++;
        }
    }
    reader.close();
    QVERIFY(total_packets > 0);
    QCOMPARE(total_packets, 11);
    QCOMPARE(rtp_count, size_t(11));
}

void TestRtpParser::test_parse_rtp() {
    QString pcap = QFINDTESTDATA("data/test_pcap_small_rtp.pcap");
    QVERIFY(QFile::exists(pcap));

    pcpp::PcapFileReaderDevice reader(pcap.toStdString());
    QVERIFY(reader.open());

    pcpp::RawPacket raw_packet;
    size_t total_packets = 0;

    while (reader.getNextPacket(raw_packet)) {
        pcpp::Packet parsed(&raw_packet);
        auto udp_layer = parsed.getLayerOfType<pcpp::UdpLayer>();
        if (!udp_layer) continue;

        total_packets++;
        const uint8_t* payload = udp_layer->getLayerPayload();
        size_t len = udp_layer->getLayerPayloadSize();
        RtpLayer rtp_packet = RtpParser::parse_rtp(payload, len, 0);

        QCOMPARE(rtp_packet.ssrc, uint32_t(0xfcf58944));
    }
    reader.close();
}

QTEST_APPLESS_MAIN(TestRtpParser)

#include "tst_rtpparser.moc"
