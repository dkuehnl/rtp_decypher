#ifndef PCAPREADER_H
#define PCAPREADER_H

#include "pcapplusplus/PcapFileDevice.h"

#include <QString>
#include <unordered_map>
#include <vector>

struct Flow_Endpoints {
    std::string source_ip;
    uint16_t source_port;
    std::string destination_ip;
    uint16_t destination_port;

    bool operator==(Flow_Endpoints const& o) const {
        return source_ip == o.source_ip && source_port == o.source_port;
    }
};

namespace std {
template<>
struct hash<Flow_Endpoints> {
    size_t operator()(Flow_Endpoints const& e) const noexcept {
        auto h1 = std::hash<std::string>()(e.source_ip);
        auto h2 = std::hash<uint16_t>()(e.source_port);
        return h1 ^ (h2 << 1);
    }
};
}

struct PacketInfo {
    std::string source_ip;
    std::string destination_ip;
    uint16_t source_port;
    uint16_t destination_port;
    size_t payload_size;
    std::vector<uint8_t> payload;
};

class PcapReader
{
public:
    PcapReader(const QString& filepath);
    bool is_valid() const;
    unsigned int get_total_packet_count();
    unsigned int get_total_udp_count();
    const std::unordered_map<Flow_Endpoints, std::vector<PacketInfo>>& get_packets_per_source() const;
    std::vector<Flow_Endpoints> get_flow_endpoints();
    const std::vector<PacketInfo>& get_stream(const Flow_Endpoints& ep) const;
    uint16_t get_pkt_count(const std::string& source_ip, uint16_t source_port, const std::string& dest_ip, uint16_t dest_port);

private:
    bool m_valid = false;
    pcpp::IFileReaderDevice* m_reader = nullptr;

    unsigned int m_total_packet_count;
    unsigned int m_total_udp_count;

    std::unordered_map<Flow_Endpoints, std::vector<PacketInfo>> m_packets_per_source;

    void extract_udp_streams();
};

#endif // PCAPREADER_H
