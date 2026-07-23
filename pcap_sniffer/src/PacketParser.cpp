#include "PacketParser.hpp"
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <format>
#include <ctime>

namespace net {

std::string PacketParser::format_mac(std::span<const uint8_t, 6> mac) {
    return std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

std::string PacketParser::format_timestamp(const struct timeval& tv) {
    std::time_t nowtime = tv.tv_sec;
    std::tm* tm_info = std::localtime(&nowtime);
    std::array<char, 64> buffer{};
    std::strftime(buffer.data(), buffer.size(), "%Y-%m-%d %H:%M:%S", tm_info);
    return std::format("{}.{:06d}", buffer.data(), tv.tv_usec);
}

std::optional<PacketInfo> PacketParser::parse(const struct pcap_pkthdr* header, std::span<const uint8_t> packet) {
    // Проверка минимального размера для Ethernet заголовка (14 байт)
    if (packet.size() < 14) {
        return std::nullopt;
    }

    PacketInfo info;
    info.timestamp = format_timestamp(header->ts);
    info.packet_size = header->len;

    // L2 — Ethernet
    auto dst_mac_span = packet.subspan<0, 6>();
    auto src_mac_span = packet.subspan<6, 6>();
    info.dst_mac = format_mac(dst_mac_span);
    info.src_mac = format_mac(src_mac_span);

    uint16_t ether_type = (packet[12] << 8) | packet[13];
    std::span<const uint8_t> l3_payload = packet.subspan(14);

    // L3 — IPv4
    if (ether_type == ETH_P_IP) {
        if (l3_payload.size() < sizeof(iphdr)) return info;

        const auto* ip_hdr = reinterpret_cast<const iphdr*>(l3_payload.data());
        std::array<char, INET_ADDRSTRLEN> src_buf{}, dst_buf{};

        inet_ntop(AF_INET, &(ip_hdr->saddr), src_buf.data(), src_buf.size());
        inet_ntop(AF_INET, &(ip_hdr->daddr), dst_buf.data(), dst_buf.size());

        info.src_ip = src_buf.data();
        info.dst_ip = dst_buf.data();

        size_t ip_hdr_len = ip_hdr->ihl * 4;
        if (l3_payload.size() < ip_hdr_len) return info;

        std::span<const uint8_t> l4_payload = l3_payload.subspan(ip_hdr_len);

        // L4 — TCP / UDP
        if (ip_hdr->protocol == IPPROTO_TCP && l4_payload.size() >= sizeof(tcphdr)) {
            const auto* tcp = reinterpret_cast<const tcphdr*>(l4_payload.data());
            info.protocol = "TCP";
            info.src_port = ntohs(tcp->source);
            info.dst_port = ntohs(tcp->dest);
        } else if (ip_hdr->protocol == IPPROTO_UDP && l4_payload.size() >= sizeof(udphdr)) {
            const auto* udp = reinterpret_cast<const udphdr*>(l4_payload.data());
            info.protocol = "UDP";
            info.src_port = ntohs(udp->source);
            info.dst_port = ntohs(udp->dest);
        } else {
            info.protocol = std::format("IPv4 (proto {})", ip_hdr->protocol);
        }
    }
    // L3 — IPv6
    else if (ether_type == ETH_P_IPV6) {
        if (l3_payload.size() < sizeof(ip6_hdr)) return info;

        const auto* ip6 = reinterpret_cast<const ip6_hdr*>(l3_payload.data());
        std::array<char, INET6_ADDRSTRLEN> src_buf{}, dst_buf{};

        inet_ntop(AF_INET6, &(ip6->ip6_src), src_buf.data(), src_buf.size());
        inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_buf.data(), dst_buf.size());

        info.src_ip = src_buf.data();
        info.dst_ip = dst_buf.data();
        info.protocol = "IPv6";
    } else {
        info.protocol = std::format("EtherType 0x{:04x}", ether_type);
    }

    return info;
}

} // namespace net