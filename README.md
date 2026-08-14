# Modern C++23 Packet Sniffer

[![C++23](https://img.shields.io/badge/C%2B%2B-23-blue.svg?style=flat-square&logo=cplusplus&logoColor=white)](https://en.cppreference.com/w/cpp/23)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg?style=flat-square)](https://github.com/alekzandren/cpp23-packet-sniffer)
[![Version](https://img.shields.io/badge/Version-1.0.0-blueviolet.svg?style=flat-square)](https://github.com/alekzandren/cpp23-packet-sniffer)
[![Library: libpcap](https://img.shields.io/badge/Library-libpcap-informational.svg?style=flat-square)](https://www.tcpdump.org/)
[![Category: Network Security](https://img.shields.io/badge/Category-Network%20Security-red.svg?style=flat-square)](https://github.com/alekzandren/cpp23-packet-sniffer)

A lightweight, high-performance, real-time network packet sniffer and header parser written in **C++23** using **libpcap**.

This project demonstrates modern C++ principles, including strict resource management (RAII), zero-copy memory abstractions (`std::span`), and a modular architecture configured for JetBrains CLion and CMake.

---

## Key Features

* **Real-Time Capture:** Captures and processes live network traffic on selected interfaces using `libpcap`.
* **Multi-Layer Protocol Parsing:**
  * **L2 (Data Link):** Ethernet frames (MAC addresses, EtherType).
  * **L3 (Network):** IPv4 & IPv6 headers, address formatting.
  * **L4 (Transport):** TCP & UDP source/destination ports.
* **Modern C++23 Architecture:**
  * **RAII Resource Management:** `pcap_t` handles wrapped in custom `std::unique_ptr` deleters to prevent resource leaks.
  * **Safe Memory Handling:** Raw packet buffers parsed safely using `std::span` without unnecessary memory allocations.
  * **Clean Type Safety:** Extensive use of `std::string_view`, `std::optional`, and `std::format`.
* **Graceful Termination:** Asynchronous signal handling (`SIGINT` / `Ctrl+C`) calling `pcap_breakloop()` for safe shutdown.

---

## Project Structure

```text
.
├── CMakeLists.txt
├── include/
│   ├── PcapSession.hpp   # RAII wrapper for libpcap handles & loop management
│   └── PacketParser.hpp  # Zero-copy header extraction & formatting
└── src/
    ├── main.cpp          # CLI entry point & signal handling
    ├── PcapSession.cpp
    └── PacketParser.cpp
```

---

## Getting Started

**Prerequisites**

You need a C++23 compliant compiler (GCC 13+ or Clang 16+), CMake 3.25+, and `libpcap` installed.

**Ubuntu / Debian**
```Bash
sudo apt update
sudo apt install build-essential cmake libpcap-dev pkg-config
```

**Fedora / RHEL**
```Bash
sudo dnf install gcc-c++ cmake libpcap-devel pkgconf-pkg-config
```

**macOS (Homebrew)**
```Bash
brew install cmake libpcap pkg-config
```

---

## Building & Running
1. Build via CMake
```bash
mkdir build && cd build
cmake ..
cmake --build .
```

2. Execution
Capturing raw network packets requires administrative privileges (root or CAP_NET_RAW capability).
Option A: Run with `sudo`
```bash
# Capture on default interface
sudo ./pcap_sniffer

# Or specify a custom interface (e.g., eth0, wlan0)
sudo ./pcap_sniffer eth0
```

Option B: Grant privileges to binary (Recommended for CLion debugging)
```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./pcap_sniffer
./pcap_sniffer
```

---

## Example Output
```plaintext
[*] Capturing on interface: eth0
Timestamp                | Src MAC           -> Dst MAC           | Proto | Src IP:Port           -> Dst IP:Port           | Bytes 
-----------------------------------------------------------------------------------------------------------------------------------
2026-07-23 14:10:05.1234 | aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66 | TCP   | 192.168.1.15:443      -> 192.168.1.100:54321   | 66    
2026-07-23 14:10:05.1298 | 11:22:33:44:55:66 -> aa:bb:cc:dd:ee:ff | UDP   | 192.168.1.1:53        -> 192.168.1.15:61002   | 84
```
---

## License
This project is open-source and available under the MIT License.
