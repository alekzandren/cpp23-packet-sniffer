#pragma once

#include <pcap.h>
#include <memory>
#include <string>
#include <string_view>
#include <functional>
#include <optional>

namespace net {

    struct PcapDeleter {
        void operator()(pcap_t* handle) const noexcept {
            if (handle) {
                pcap_close(handle);
            }
        }
    };

    using PcapHandle = std::unique_ptr<pcap_t, PcapDeleter>;

    class PcapSession {
    public:
        using PacketCallback = std::function<void(const struct pcap_pkthdr*, const u_char*)>;

        explicit PcapSession(std::string_view interface_name);
        ~PcapSession() = default;

        PcapSession(const PcapSession&) = delete;
        PcapSession& operator=(const PcapSession&) = delete;
        PcapSession(PcapSession&&) noexcept = default;
        PcapSession& operator=(PcapSession&&) noexcept = default;

        void start_capture(PacketCallback callback);
        void stop_capture() noexcept;

        static std::optional<std::string> find_default_device();

    private:
        std::string device_name_;
        PcapHandle handle_;
    };

} // namespace net