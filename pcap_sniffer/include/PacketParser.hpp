#pragma once

#include <span>
#include <cstdint>
#include <string>
#include <optional>
#include <pcap.h>

namespace net {

    struct PacketInfo {
        std::string timestamp;
        std::string src_mac;
        std::string dst_mac;
        std::string src_ip;
        std::string dst_ip;
        std::string protocol;
        uint16_t src_port{0};
        uint16_t dst_port{0};
        uint32_t packet_size{0};
    };

    class PacketParser {
    public:
        static std::optional<PacketInfo> parse(const struct pcap_pkthdr* header, std::span<const uint8_t> packet_data);

    private:
        static std::string format_mac(std::span<const uint8_t, 6> mac_bytes);
        static std::string format_timestamp(const struct timeval& tv);
    };

} // namespace net