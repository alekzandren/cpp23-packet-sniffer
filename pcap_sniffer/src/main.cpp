#include "PcapSession.hpp"
#include "PacketParser.hpp"
#include <iostream>
#include <csignal>
#include <atomic>
#include <memory>
#include <format>

namespace {
    std::atomic<bool> running{true};
    net::PcapSession* global_session = nullptr;

    void signal_handler(int signal) {
        if (signal == SIGINT || signal == SIGTERM) {
            running = false;
            if (global_session) {
                global_session->stop_capture();
            }
        }
    }
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::string device;

    if (argc > 1) {
        device = argv[1];
    } else {
        auto default_dev = net::PcapSession::find_default_device();
        if (!default_dev) {
            std::cerr << "[!] Не удалось определить сетевой интерфейс по умолчанию.\n";
            return 1;
        }
        device = *default_dev;
    }

    std::cout << std::format("[*] Запуск захвата пакетов на интерфейсе: {}\n", device);
    std::cout << std::format("{:<24} | {:<17} -> {:<17} | {:<5} | {:<21} -> {:<21} | {:<6}\n",
                             "Timestamp", "Src MAC", "Dst MAC", "Proto", "Src IP:Port", "Dst IP:Port", "Bytes");
    std::cout << std::string(115, '-') << '\n';

    try {
        net::PcapSession session(device);
        global_session = &session;

        session.start_capture([](const struct pcap_pkthdr* header, const u_char* data) {
            if (!running) return;

            std::span<const uint8_t> packet_span(data, header->caplen);
            auto info = net::PacketParser::parse(header, packet_span);

            if (info) {
                std::string src_endpoint = info->src_port ? std::format("{}:{}", info->src_ip, info->src_port) : info->src_ip;
                std::string dst_endpoint = info->dst_port ? std::format("{}:{}", info->dst_ip, info->dst_port) : info->dst_ip;

                std::cout << std::format("{:<24} | {:<17} -> {:<17} | {:<5} | {:<21} -> {:<21} | {:<6}\n",
                                         info->timestamp,
                                         info->src_mac, info->dst_mac,
                                         info->protocol,
                                         src_endpoint, dst_endpoint,
                                         info->packet_size);
            }
        });
    } catch (const std::exception& ex) {
        std::cerr << "[!] Ошибка: " << ex.what() << '\n';
        return 1;
    }

    std::cout << "\n[*] Захват пакетов завершен.\n";
    return 0;
}