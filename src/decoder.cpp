#include "decoder.hpp"

#include <algorithm>
#include <span>

namespace {

using Bytes = std::span<const std::uint8_t>;

// DESIGN 4장의 헤더 길이와 필드 값
constexpr std::size_t kEthernetHeaderLen = 14;
constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
constexpr std::size_t kIpv4MinHeaderLen = 20;
constexpr std::uint8_t kProtocolTcp = 6;
constexpr std::uint16_t kFragmentOffsetMask = 0x1FFF;
constexpr std::size_t kTcpMinHeaderLen = 20;
constexpr std::uint8_t kTcpFlagSyn = 0x02;
constexpr std::uint8_t kTcpFlagAck = 0x10;

// Big Endian 정수 읽기. 호출하는 쪽이 길이를 먼저 확인한다
std::uint16_t read_u16(Bytes b, std::size_t offset) {
    return static_cast<std::uint16_t>((b[offset] << 8) | b[offset + 1]);
}

std::uint32_t read_u32(Bytes b, std::size_t offset) {
    return (std::uint32_t{b[offset]} << 24) | (std::uint32_t{b[offset + 1]} << 16) |
           (std::uint32_t{b[offset + 2]} << 8) | std::uint32_t{b[offset + 3]};
}

MacAddress read_mac(Bytes b, std::size_t offset) {
    MacAddress mac;
    std::copy_n(b.begin() + static_cast<std::ptrdiff_t>(offset), mac.bytes.size(), mac.bytes.begin());
    return mac;
}

struct EthernetFields {
    MacAddress dst_mac;
    MacAddress src_mac;
    Bytes payload;  // IPv4 헤더부터 프레임 끝까지
};

struct Ipv4Fields {
    std::uint32_t src_ip;
    std::uint32_t dst_ip;
    Bytes payload;  // TCP 헤더부터 Total Length 끝까지. 이더넷 패딩은 포함하지 않는다
};

struct TcpFields {
    std::uint16_t src_port;
    std::uint16_t dst_port;
};

// DESIGN 4.1
std::variant<EthernetFields, DropReason> decode_ethernet(Bytes frame) {
    if (frame.size() < kEthernetHeaderLen) {
        return DropReason::TruncatedEthernet;
    }
    if (read_u16(frame, 12) != kEtherTypeIpv4) {
        return DropReason::NotIpv4;
    }
    return EthernetFields{read_mac(frame, 0), read_mac(frame, 6), frame.subspan(kEthernetHeaderLen)};
}

// DESIGN 4.2. 표의 순서대로 검사한다
std::variant<Ipv4Fields, DropReason> decode_ipv4(Bytes ip) {
    if (ip.size() < kIpv4MinHeaderLen) {
        return DropReason::TruncatedIpv4;
    }
    const unsigned version = ip[0] >> 4;
    if (version != 4) {
        return DropReason::InvalidIpv4;
    }
    const std::size_t header_len = static_cast<std::size_t>(ip[0] & 0x0F) * 4;
    if (header_len < kIpv4MinHeaderLen || header_len > ip.size()) {
        return DropReason::InvalidIpv4;
    }
    const std::size_t total_len = read_u16(ip, 2);
    if (total_len < header_len) {
        return DropReason::InvalidIpv4;
    }
    if (total_len > ip.size()) {
        return DropReason::TruncatedIpv4;
    }
    // Protocol을 Fragment Offset보다 먼저 검사한다
    if (ip[9] != kProtocolTcp) {
        return DropReason::NotTcp;
    }
    if ((read_u16(ip, 6) & kFragmentOffsetMask) != 0) {
        return DropReason::Ipv4Fragment;
    }
    // 이후 단계의 남은 길이는 캡처 길이가 아니라 Total Length − IHL × 4
    return Ipv4Fields{read_u32(ip, 12), read_u32(ip, 16),
                      ip.subspan(header_len, total_len - header_len)};
}

// DESIGN 4.3
std::variant<TcpFields, DropReason> decode_tcp(Bytes tcp) {
    if (tcp.size() < kTcpMinHeaderLen) {
        return DropReason::TruncatedTcp;
    }
    const std::size_t data_offset = tcp[12] >> 4;
    if (data_offset < 5 || data_offset * 4 > tcp.size()) {
        return DropReason::InvalidTcp;
    }
    // SYN이 설정되고 ACK가 설정되지 않은 패킷만 분석 대상
    const std::uint8_t flags = tcp[13];
    if ((flags & (kTcpFlagSyn | kTcpFlagAck)) != kTcpFlagSyn) {
        return DropReason::NotConnectionAttempt;
    }
    return TcpFields{read_u16(tcp, 0), read_u16(tcp, 2)};
}

}  // namespace

const char* to_string(DropReason reason) {
    // default를 두지 않아야 새 DropReason이 빠졌을 때 -Wswitch가 경고한다
    switch (reason) {
    case DropReason::TruncatedEthernet:
        return "truncated_ethernet";
    case DropReason::NotIpv4:
        return "not_ipv4";
    case DropReason::TruncatedIpv4:
        return "truncated_ipv4";
    case DropReason::InvalidIpv4:
        return "invalid_ipv4";
    case DropReason::NotTcp:
        return "not_tcp";
    case DropReason::Ipv4Fragment:
        return "ipv4_fragment";
    case DropReason::TruncatedTcp:
        return "truncated_tcp";
    case DropReason::InvalidTcp:
        return "invalid_tcp";
    case DropReason::NotConnectionAttempt:
        return "not_connection_attempt";
    }
    return "unknown";  // enum 범위 밖의 값. 정상적으로는 오지 않는다
}

DecodeResult Decoder::decode(const RawFrame& frame) const {
    const auto ethernet = decode_ethernet(frame.bytes);
    if (const auto* reason = std::get_if<DropReason>(&ethernet)) {
        return *reason;
    }
    const auto& eth = std::get<EthernetFields>(ethernet);

    const auto ipv4 = decode_ipv4(eth.payload);
    if (const auto* reason = std::get_if<DropReason>(&ipv4)) {
        return *reason;
    }
    const auto& ip = std::get<Ipv4Fields>(ipv4);

    const auto tcp = decode_tcp(ip.payload);
    if (const auto* reason = std::get_if<DropReason>(&tcp)) {
        return *reason;
    }
    const auto& ports = std::get<TcpFields>(tcp);

    DecodedPacket packet;
    packet.timestamp = frame.timestamp;
    packet.src_ip = ip.src_ip;
    packet.dst_ip = ip.dst_ip;
    packet.src_port = ports.src_port;
    packet.dst_port = ports.dst_port;
    packet.src_mac = eth.src_mac;
    packet.dst_mac = eth.dst_mac;
    return packet;
}
