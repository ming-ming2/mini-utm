#pragma once

#include <cstddef>
#include <cstdint>
#include <variant>

#include "capture.hpp"

// DESIGN 4.4. IP는 호스트 바이트 순서
struct DecodedPacket {
    TimePoint timestamp;
    std::uint32_t src_ip = 0;
    std::uint32_t dst_ip = 0;
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
};

// DESIGN 4장. Stats::drops의 인덱스로도 쓰므로 순서를 바꾸면 kDropReasonCount도 확인한다
enum class DropReason {
    TruncatedEthernet,
    NotIpv4,
    TruncatedIpv4,
    InvalidIpv4,
    NotTcp,
    Ipv4Fragment,
    TruncatedTcp,
    InvalidTcp,
    NotConnectionAttempt,
};

inline constexpr std::size_t kDropReasonCount =
    static_cast<std::size_t>(DropReason::NotConnectionAttempt) + 1;

using DecodeResult = std::variant<DecodedPacket, DropReason>;

// 로그·통계 출력용 이름("truncated_tcp" 등)
const char* to_string(DropReason reason);

// 상태를 갖지 않는다. 예외를 던지지 않는다
class Decoder {
public:
    DecodeResult decode(const RawFrame& frame) const;

private:
    // TODO: 시그니처 미정 (SPEC 5.3)
    // decode_ethernet: 이더넷 헤더를 검사하고 IPv4 시작 위치를 구한다
    // decode_ipv4:     IPv4 헤더를 검사하고 TCP 시작 위치와 Total Length - IHL * 4를 구한다
    // decode_tcp:      TCP 헤더를 검사하고 포트를 읽는다. 연결 시도 패킷이 아니면 제외한다
};
