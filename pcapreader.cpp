#include "pcapreader.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/UdpLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include <qdebug.h>

PcapReader::PcapReader(const QString& filepath)
    : m_reader(nullptr), m_valid(false), m_total_packet_count(0), m_total_udp_count(0)
{
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(filepath.toStdString());
    if (reader && reader->open()) {
        m_reader = reader;
        m_valid = true;
        PcapReader::extract_udp_streams();
    } else {
        delete reader;
        m_valid = false;
    }
}

bool PcapReader::is_valid() const {
    return m_valid;
}

unsigned int PcapReader::get_total_packet_count() {
    return m_total_packet_count;
}

unsigned int PcapReader::get_total_udp_count() {
    return m_total_udp_count;
}

void PcapReader::extract_udp_streams() {
    pcpp::RawPacket raw_packet;
    while (m_reader->getNextPacket(raw_packet)) {
        m_total_packet_count++;
        pcpp::Packet parsed_packet(&raw_packet);
        pcpp::IPv4Layer* ip_packet = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
        if (ip_packet == nullptr) {
            continue;
        }
        pcpp::UdpLayer* udp_packet = parsed_packet.getLayerOfType<pcpp::UdpLayer>();
        if (udp_packet == nullptr) {
            continue;
        }

        m_total_udp_count++;
        Flow_Endpoints ep {
            ip_packet->getSrcIPv4Address().toString(),
            udp_packet->getSrcPort(),
            ip_packet->getDstIPv4Address().toString(),
            udp_packet->getDstPort(),
        };

        PacketInfo packet;
        packet.source_ip = ip_packet->getSrcIPv4Address().toString();
        packet.destination_ip = ip_packet->getDstIPv4Address().toString();
        packet.source_port = udp_packet->getSrcPort();
        packet.destination_port = udp_packet->getDstPort();
        packet.payload_size = udp_packet->getLayerPayloadSize();
        packet.payload = std::vector<uint8_t>(udp_packet->getLayerPayload(), udp_packet->getLayerPayload() + udp_packet->getLayerPayloadSize());

        auto &vector = m_packets_per_source[ep];
        vector.push_back(packet);
    }

}

const std::unordered_map<Flow_Endpoints, std::vector<PacketInfo>>& PcapReader::get_packets_per_source() const {
    return m_packets_per_source;
}

std::vector<Flow_Endpoints> PcapReader::get_flow_endpoints() {
    std::vector<Flow_Endpoints> endpoints;
    for (const auto& elements : m_packets_per_source) {
        endpoints.push_back(elements.first);
    }
    return endpoints;
}

const std::vector<PacketInfo>& PcapReader::get_stream(const Flow_Endpoints& ep) const {
    static const std::vector<PacketInfo> empty{};
    auto element = m_packets_per_source.find(ep);

    return (element != m_packets_per_source.end())
        ? element->second
        : empty;
}

uint16_t PcapReader::get_pkt_count(const std::string& source_ip, uint16_t source_port, const std::string& dest_ip, uint16_t dest_port) {
    static const std::vector<PacketInfo> empty{};
    Flow_Endpoints ep = {source_ip, source_port, dest_ip, dest_port};
    auto element = m_packets_per_source.find(ep);
    return (element != m_packets_per_source.end())
        ? element->second.size()
        : 0;
}

