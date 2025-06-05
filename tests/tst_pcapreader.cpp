#include <QtTest>
#include "../pcapreader.h"

class TestPcapReader : public QObject
{
    Q_OBJECT

private slots:
    void test_valid_file();
    void test_nopcap_file();
    void test_packet_count();
    void test_packet_count_ac_pcap();
    void test_packet_count_mixed();
    void test_packet_struct();
    void test_get_endpoints();
    void test_get_stream();
    void test_get_pkt_count_per_stream();
};

void TestPcapReader::test_valid_file() {
    QString real_pcap = QFINDTESTDATA("data/testfile.pcap");
    QVERIFY(QFile::exists(real_pcap));

    PcapReader reader(real_pcap);
    QCOMPARE(reader.is_valid(), true);
}

void TestPcapReader::test_nopcap_file() {
    QString fake_pcap = QFINDTESTDATA("data/test_txt.log");
    QVERIFY(QFile::exists(fake_pcap));

    PcapReader reader(fake_pcap);
    QCOMPARE(reader.is_valid(), false);
}

void TestPcapReader::test_packet_count() {
    QString real_pcap = QFINDTESTDATA("data/testfile.pcap");
    QVERIFY(QFile::exists(real_pcap));

    PcapReader reader(real_pcap);
    QCOMPARE(reader.get_total_packet_count(), 2182);
}

void TestPcapReader::test_packet_count_ac_pcap() {
    QString ac_pcap = QFINDTESTDATA("data/ac_trace.pcap");
    QVERIFY(QFile::exists(ac_pcap));

    PcapReader reader(ac_pcap);
    QCOMPARE(reader.get_total_packet_count(), 2957);
}

void TestPcapReader::test_packet_count_mixed() {
    QString mixed_pcap = QFINDTESTDATA("data/mixed_trace.pcap");
    QVERIFY(QFile::exists(mixed_pcap));

    PcapReader reader(mixed_pcap);
    QCOMPARE(reader.get_total_packet_count(), 1652198);
}

void TestPcapReader::test_packet_struct() {
    QString file = QFINDTESTDATA("data/testfile.pcap");
    QVERIFY(QFile::exists(file));

    PcapReader reader(file);
    QVERIFY(reader.is_valid());
    auto const& streams = reader.get_packets_per_source();

    QCOMPARE(streams.size(), size_t(4));

    Flow_Endpoints epA{"93.215.253.146", 43722};
    Flow_Endpoints epB{"93.215.253.146", 43723};
    Flow_Endpoints epC{"217.0.173.15", 61414};
    Flow_Endpoints epD{"217.0.173.15", 61415};

    QVERIFY(streams.find(epA) != streams.end());
    QVERIFY(streams.find(epB) != streams.end());
    QVERIFY(streams.find(epC) != streams.end());
    QVERIFY(streams.find(epD) != streams.end());

    QCOMPARE(streams.at(epA).size(), size_t(1100));
    QCOMPARE(streams.at(epB).size(), size_t(24));
    QCOMPARE(streams.at(epC).size(), size_t(1054));
    QCOMPARE(streams.at(epD).size(), size_t(4));
}

void TestPcapReader::test_get_endpoints() {
    QString file = QFINDTESTDATA("data/testfile.pcap");
    QVERIFY(QFile::exists(file));

    PcapReader reader(file);
    QVERIFY(reader.is_valid());

    std::vector<Flow_Endpoints> expect = {
        {"93.215.253.146", 43722, "217.0.173.15", 61414},
        {"93.215.253.146", 43723},
        {"217.0.173.15", 61414},
        {"217.0.173.15", 61415}
    };
    const std::vector<Flow_Endpoints>& actual = reader.get_flow_endpoints();

    for (auto const& ep : expect) {
        auto element = std::find_if(
            actual.begin(), actual.end(),
            [&](Flow_Endpoints const& a) {
                return a.source_ip == ep.source_ip
                       && a.source_port == ep.source_port;
            });
        QVERIFY2(element != actual.end(), qPrintable(QString("Endpoint %1:%2 nicht gefunden")
                                                    .arg(QString::fromStdString(ep.source_ip))
                                                    .arg(ep.source_port)));
    }
}

void TestPcapReader::test_get_stream() {
    QString file = QFINDTESTDATA("data/testfile.pcap");
    QVERIFY(QFile::exists(file));

    PcapReader reader(file);
    QVERIFY(reader.is_valid());

    Flow_Endpoints ep = {"93.215.253.146", 43722, "217.0.173.15", 61414};
    const auto& stream = reader.get_stream(ep);
    QCOMPARE(stream.size(), 1100);
}

void TestPcapReader::test_get_pkt_count_per_stream() {
    QString file = QFINDTESTDATA("data/testfile.pcap");
    QVERIFY(QFile::exists(file));

    PcapReader reader(file);
    QVERIFY(reader.is_valid());

    QCOMPARE(reader.get_pkt_count("93.215.253.146", 43722, "217.0.173.15", 61414), 1100);
}

QTEST_APPLESS_MAIN(TestPcapReader)

#include "tst_pcapreader.moc"
