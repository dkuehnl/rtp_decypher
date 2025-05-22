#include <iomanip>
#include <iostream>
#include <set>
#include <winsock2.h>

#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/UdpLayer.h"

int main(int argc, char *argv[])
{
    std::string path = "C:/Users/dkueh/Workspace/cpp/rtp_decypher/rtp_decypher/external/files/testfile.pcap";
    std::set<uint16_t> rtp_ports = {43722, 61414};
    std::set<size_t> header_length;

    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(path);
    if (!reader->open()) {
        std::cerr << "File couldn't be opened!\n" << std::endl;
        return 1;
    }

    pcpp::RawPacket r_packet;
    size_t rtp_counter = 0;
    size_t total_count = 0;

    while (reader->getNextPacket(r_packet)) {
        total_count++;
        pcpp::Packet parsedPacket(&r_packet);
        pcpp::UdpLayer* udp_layer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
        if (udp_layer == nullptr) {
            continue;
        }

        uint16_t src_port = udp_layer->getSrcPort();
        uint16_t dst_port = udp_layer->getDstPort();

        if (rtp_ports.count(src_port) || rtp_ports.count(dst_port)) {
            rtp_counter++;
            std::cout << udp_layer->getLayerPayloadSize() << " (Payload-Size)" << std::endl;
            std::cout << "0x" << std::hex << static_cast<int>(udp_layer->getProtocol()) << " (get Protocol)" << std::endl;
            std::cout << udp_layer->getOsiModelLayer() << " (getOsiModelLayer)" << std::endl;
            std::cout << std::hex << static_cast<const void*>(udp_layer->getLayerPayload()) << " (get LayerPayload)" << std::endl;
            std::cout << std::hex << static_cast<const void*>(udp_layer->getData()) << " (getData)" << std::endl;

            const uint8_t* payload = udp_layer->getLayerPayload();
            size_t payload_len = udp_layer->getLayerPayloadSize();
            std::cout << "Payload Bytes: " << std::endl;
            for (size_t i = 0; i < std::min(payload_len, static_cast<size_t>(16)); i++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(payload[i]) << " ";
            }
            std::cout << std::dec << std::endl;
            break;
        }
    }

    reader->close();
    delete reader;

    std::cout << "Insgesamt: " << total_count << " Pakete durchlaufen." << std::endl;
    std::cout << rtp_counter << " davon sind RTP-Pakete (nach Ports " << rtp_ports.size() << ")" << std::endl;
    std::cout << "Gefundene Header-Laengen: " << std::endl;
    for (const auto& element : header_length) {
        std::cout << element << std::endl;
    }
    return 0;
}
