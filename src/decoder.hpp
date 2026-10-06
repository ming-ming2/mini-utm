#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <variant>

#include "capture.hpp"

// MAC 주소. 다른 6바이트 값과 섞여 쓰이지 않도록 별도 타입으로 둔다.
struct MacAddress {
    std::array<std::uint8_t, 6> bytes{};

    bool operator==(const MacAddress&) const = default;
};

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

// 상태를 갖지 않는다. 예외를 던지지 않는다.
// 계층별 해석(이더넷 → IPv4 → TCP)은 decoder.cpp 안의 함수로 나눈다(SPEC 5.3)
class Decoder {
public:
    DecodeResult decode(const RawFrame& frame) const;
};
