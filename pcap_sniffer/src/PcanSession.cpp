#include "PcapSession.hpp"
#include <iostream>
#include <stdexcept>
#include <array>

namespace net {

    PcapSession::PcapSession(std::string_view interface_name)
        : device_name_(interface_name) {
        std::array<char, PCAP_ERRBUF_SIZE> errbuf{};

        pcap_t* raw_handle = pcap_open_live(
            device_name_.c_str(),
            BUFSIZ,
            1,
            1000,
            errbuf.data()
        );

        if (!raw_handle) {
            throw std::runtime_error("Ошибка открытия интерфейса " + device_name_ + ": " + errbuf.data());
        }

        handle_.reset(raw_handle);
    }

    std::optional<std::string> PcapSession::find_default_device() {
        std::array<char, PCAP_ERRBUF_SIZE> errbuf{};
        pcap_if_t* alldevs = nullptr;

        if (pcap_findalldevs(&alldevs, errbuf.data()) == -1 || !alldevs) {
            return std::nullopt;
        }

        std::string default_dev = alldevs->name;
        pcap_freealldevs(alldevs);
        return default_dev;
    }

    void PcapSession::start_capture(PacketCallback callback) {
        if (!handle_) return;

        auto trampoline = [](u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
            auto& cb = *reinterpret_cast<PacketCallback*>(user_data);
            cb(pkthdr, packet);
        };

        pcap_loop(handle_.get(), 0, trampoline, reinterpret_cast<u_char*>(&callback));
    }

    void PcapSession::stop_capture() noexcept {
        if (handle_) {
            pcap_breakloop(handle_.get());
        }
    }

} // namespace net