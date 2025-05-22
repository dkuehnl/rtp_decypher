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
        Endpoint ep {
            ip_packet->getSrcIPv4Address().toString(),
            udp_packet->getSrcPort()
        };

        PacketInfo packet {
            ip_packet->getSrcIPv4Address().toString(),
            ip_packet->getDstIPv4Address().toString(),
            udp_packet->getSrcPort(),
            udp_packet->getDstPort(),
            udp_packet->getLayerPayloadSize(),
            udp_packet->getLayerPayload()
        };

        auto &vector = m_packets_per_source[ep];
        vector.push_back(packet);
    }

}

const std::unordered_map<Endpoint, std::vector<PacketInfo>>& PcapReader::get_packets_per_source() const {
    return m_packets_per_source;
}

std::vector<Endpoint> PcapReader::show_sockets() {
    std::vector<Endpoint> endpoints;
    for (const auto& elements : m_packets_per_source) {
        endpoints.push_back(elements.first);
    }
    return endpoints;
}

const std::vector<PacketInfo>& PcapReader::get_stream(const std::string& source_ip, uint16_t source_port) const {
    static const std::vector<PacketInfo> empty{};
    Endpoint ep = {source_ip, source_port};
    auto element = m_packets_per_source.find(ep);
    return (element != m_packets_per_source.end())
        ? element->second
        : empty;
}

