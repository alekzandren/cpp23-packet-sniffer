cmake_minimum_required(VERSION 3.25)
project(. CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Поиск libpcap через PkgConfig
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS} include)
link_directories(${PCAP_LIBRARY_DIRS})

add_executable(pcap_sniffer
        src/main.cpp
        pcap_sniffer/src/PcapSession.cpp
        src/PacketParser.cpp
)

target_link_libraries(pcap_sniffer PRIVATE ${PCAP_LIBRARIES})