#ifndef PCAPREADER_H
#define PCAPREADER_H

#include "pcapplusplus/PcapFileDevice.h"

#include <QString>
#include <unordered_map>
#include <vector>

/// @brief Identifies a UDP flow by its source/destination IP and port.
///
/// @note operator== (and the matching std::hash specialization below) only
/// compares source_ip and source_port. Two flows that share the same source
/// but differ in destination_ip/destination_port are therefore treated as
/// the same key when used in an unordered_map -- see the TODO on
/// operator== for the resulting bug.
struct Flow_Endpoints {
    std::string source_ip;
    uint16_t source_port;
    std::string destination_ip;
    uint16_t destination_port;

    // TODO: Only source_ip/source_port are compared here (and hashed below),
    // even though the struct also carries destination_ip/destination_port.
    // Two distinct flows that share a source but talk to different
    // destinations collide in PcapReader::m_packets_per_source: their
    // packets get merged into a single bucket instead of being kept apart.
    // Include destination_ip/destination_port in the comparison (and hash)
    // to make Flow_Endpoints a correct 4-tuple key.
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

/// @brief A single UDP packet extracted from a pcap file, with its raw payload.
struct PacketInfo {
    std::string source_ip;
    std::string destination_ip;
    uint16_t source_port;
    uint16_t destination_port;
    size_t payload_size;
    std::vector<uint8_t> payload; ///< Raw UDP payload bytes (potential RTP data).
};

/// @brief Reads a pcap file via PcapPlusPlus and groups its UDP packets by flow.
///
/// Construction opens the file and eagerly extracts every UDP packet into
/// per-flow buckets (see extract_udp_streams()); is_valid() reports whether
/// the file could be opened and parsed.
class PcapReader
{
public:
    /// @brief Opens and parses the given pcap file.
    /// @param filepath Path to a `.pcap` file.
    PcapReader(const QString& filepath);

    /// @brief Whether the file was opened successfully.
    bool is_valid() const;

    /// @return Total number of packets (of any protocol) seen in the file.
    unsigned int get_total_packet_count();

    /// @return Total number of UDP packets seen in the file.
    unsigned int get_total_udp_count();

    /// @return All extracted packets, grouped by flow.
    const std::unordered_map<Flow_Endpoints, std::vector<PacketInfo>>& get_packets_per_source() const;

    /// @return The distinct flow endpoints found in the file.
    std::vector<Flow_Endpoints> get_flow_endpoints();

    /// @brief Looks up the packet stream for a given flow.
    /// @param ep Flow to look up.
    /// @return The packets belonging to @p ep, or an empty vector if unknown.
    const std::vector<PacketInfo>& get_stream(const Flow_Endpoints& ep) const;

    /// @brief Number of packets recorded for the given flow.
    /// @param source_ip Source IP address.
    /// @param source_port Source port.
    /// @param dest_ip Destination IP address.
    /// @param dest_port Destination port.
    /// @return Packet count for that flow, or 0 if unknown.
    uint16_t get_pkt_count(const std::string& source_ip, uint16_t source_port, const std::string& dest_ip, uint16_t dest_port);

private:
    bool m_valid = false;
    pcpp::IFileReaderDevice* m_reader = nullptr;

    unsigned int m_total_packet_count;
    unsigned int m_total_udp_count;

    std::unordered_map<Flow_Endpoints, std::vector<PacketInfo>> m_packets_per_source;

    /// @brief Reads every packet from m_reader and buckets UDP packets by flow.
    void extract_udp_streams();
};

#endif // PCAPREADER_H
