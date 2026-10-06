// Decoder 테스트. 정상 SYN 프레임을 코드로 만들고, 시험마다 필요한 바이트만 바꿔서 넣는다
#include <catch2/catch.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include "capture.hpp"
#include "decoder.hpp"

// 실패 메시지에 DropReason이 "{?}" 대신 이름으로 찍히게 한다
namespace Catch {
template <>
struct StringMaker<DropReason> {
    static std::string convert(DropReason reason) { return to_string(reason); }
};
}  // namespace Catch

namespace {

using Frame = std::vector<std::uint8_t>;

// 프레임 안에서 각 헤더가 시작하는 위치
constexpr std::size_t kIp = 14;   // 이더넷 헤더 14바이트 뒤
constexpr std::size_t kTcp = 34;  // IPv4 헤더 20바이트 뒤

// 198.51.100.7:51234 → 10.1.1.55:8090, SYN, 옵션 없음. 이더넷 14 + IPv4 20 + TCP 20 = 54바이트
Frame make_syn_frame() {
    return {
        // 이더넷: 목적지 MAC, 출발지 MAC, EtherType(IPv4)
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x00,
        // IPv4
        0x45, 0x00,              // Version 4, IHL 5 / TOS
        0x00, 0x28,              // Total Length 40 (IPv4 20 + TCP 20)
        0x00, 0x01,              // Identification
        0x40, 0x00,              // Flags(DF) / Fragment Offset 0
        0x40, 0x06,              // TTL / Protocol 6(TCP)
        0x00, 0x00,              // Header Checksum (검증하지 않음)
        0xC6, 0x33, 0x64, 0x07,  // 출발지 198.51.100.7
        0x0A, 0x01, 0x01, 0x37,  // 목적지 10.1.1.55
        // TCP
        0xC8, 0x22,              // 출발지 Port 51234
        0x1F, 0x9A,              // 목적지 Port 8090
        0x00, 0x00, 0x00, 0x01,  // Sequence Number
        0x00, 0x00, 0x00, 0x00,  // Acknowledgment Number
        0x50, 0x02,              // Data Offset 5 / Flags SYN
        0xFF, 0xFF,              // Window
        0x00, 0x00,              // Checksum
        0x00, 0x00,              // Urgent Pointer
    };
}

void set_u16(Frame& f, std::size_t offset, std::uint16_t value) {
    f[offset] = static_cast<std::uint8_t>(value >> 8);
    f[offset + 1] = static_cast<std::uint8_t>(value & 0xFF);
}

const TimePoint kTimestamp{std::chrono::seconds{1700000000}};

DecodeResult decode(const Frame& f) {
    const RawFrame frame{kTimestamp, std::span<const std::uint8_t>(f)};
    return Decoder{}.decode(frame);
}

// 제외되어야 하는 프레임의 사유. 제외되지 않으면 그 테스트를 중단한다
DropReason drop_reason(const Frame& f) {
    const DecodeResult result = decode(f);
    REQUIRE(std::holds_alternative<DropReason>(result));
    return std::get<DropReason>(result);
}

DecodedPacket decoded(const Frame& f) {
    const DecodeResult result = decode(f);
    REQUIRE(std::holds_alternative<DecodedPacket>(result));
    return std::get<DecodedPacket>(result);
}

}  // namespace

TEST_CASE("정상 SYN 프레임은 DecodedPacket이 된다", "[decoder]") {
    const DecodedPacket p = decoded(make_syn_frame());

    CHECK(p.timestamp == kTimestamp);
    CHECK(p.src_ip == 0xC6336407);  // 198.51.100.7 (호스트 바이트 순서)
    CHECK(p.dst_ip == 0x0A010137);  // 10.1.1.55
    CHECK(p.src_port == 51234);
    CHECK(p.dst_port == 8090);
    CHECK(p.src_mac == MacAddress{{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}});
    CHECK(p.dst_mac == MacAddress{{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}});
}

TEST_CASE("IP 패킷의 끝은 Total Length로 판단한다", "[decoder]") {
    SECTION("이더넷 패딩이 붙어도 해석된다") {
        Frame f = make_syn_frame();
        f.resize(60, 0xEE);  // 최소 이더넷 프레임 60바이트까지 패딩

        CHECK(decoded(f).dst_port == 8090);
    }
    SECTION("Total Length 밖의 바이트를 TCP 헤더로 읽지 않는다 (Insertion 방지)") {
        Frame f = make_syn_frame();
        set_u16(f, kIp + 2, 20 + 19);  // TCP가 19바이트뿐이라고 선언. 캡처된 바이트는 그대로 54

        CHECK(drop_reason(f) == DropReason::TruncatedTcp);
    }
}

TEST_CASE("이더넷 검사 (DESIGN 4.1)", "[decoder]") {
    SECTION("14바이트 미만이면 truncated_ethernet") {
        Frame f = make_syn_frame();
        f.resize(13);
        CHECK(drop_reason(f) == DropReason::TruncatedEthernet);
    }
    SECTION("IPv6면 not_ipv4") {
        Frame f = make_syn_frame();
        set_u16(f, 12, 0x86DD);
        CHECK(drop_reason(f) == DropReason::NotIpv4);
    }
    SECTION("ARP면 not_ipv4") {
        Frame f = make_syn_frame();
        set_u16(f, 12, 0x0806);
        CHECK(drop_reason(f) == DropReason::NotIpv4);
    }
    SECTION("VLAN 태그가 붙으면 not_ipv4") {
        Frame f = make_syn_frame();
        set_u16(f, 12, 0x8100);
        CHECK(drop_reason(f) == DropReason::NotIpv4);
    }
}

TEST_CASE("IPv4 검사 (DESIGN 4.2)", "[decoder]") {
    Frame f = make_syn_frame();

    SECTION("남은 길이가 20바이트 미만이면 truncated_ipv4") {
        f.resize(kIp + 19);
        CHECK(drop_reason(f) == DropReason::TruncatedIpv4);
    }
    SECTION("Version이 4가 아니면 invalid_ipv4") {
        f[kIp] = 0x65;
        CHECK(drop_reason(f) == DropReason::InvalidIpv4);
    }
    SECTION("IHL이 5 미만이면 invalid_ipv4") {
        f[kIp] = 0x44;
        CHECK(drop_reason(f) == DropReason::InvalidIpv4);
    }
    SECTION("IHL × 4가 남은 길이보다 크면 invalid_ipv4") {
        f[kIp] = 0x4F;  // 60바이트 헤더라고 주장하지만 남은 길이는 40
        CHECK(drop_reason(f) == DropReason::InvalidIpv4);
    }
    SECTION("Total Length가 IHL × 4보다 작으면 invalid_ipv4") {
        set_u16(f, kIp + 2, 19);
        CHECK(drop_reason(f) == DropReason::InvalidIpv4);
    }
    SECTION("Total Length가 남은 길이보다 크면 truncated_ipv4") {
        set_u16(f, kIp + 2, 1000);
        CHECK(drop_reason(f) == DropReason::TruncatedIpv4);
    }
    SECTION("Protocol이 TCP가 아니면 not_tcp") {
        f[kIp + 9] = 17;  // UDP
        CHECK(drop_reason(f) == DropReason::NotTcp);
    }
    SECTION("Fragment Offset이 0이 아니면 ipv4_fragment") {
        set_u16(f, kIp + 6, 0x0001);
        CHECK(drop_reason(f) == DropReason::Ipv4Fragment);
    }
    SECTION("TCP가 아닌 조각은 ipv4_fragment가 아니라 not_tcp") {
        f[kIp + 9] = 17;
        set_u16(f, kIp + 6, 0x0001);
        CHECK(drop_reason(f) == DropReason::NotTcp);
    }
    SECTION("More Fragments만 켜진 첫 조각은 Fragment Offset이 0이므로 통과") {
        set_u16(f, kIp + 6, 0x2000);
        CHECK(decoded(f).dst_port == 8090);
    }
}

TEST_CASE("TCP 검사 (DESIGN 4.3)", "[decoder]") {
    Frame f = make_syn_frame();

    SECTION("Data Offset이 5 미만이면 invalid_tcp") {
        f[kTcp + 12] = 0x40;
        CHECK(drop_reason(f) == DropReason::InvalidTcp);
    }
    SECTION("Data Offset × 4가 남은 길이보다 크면 invalid_tcp") {
        f[kTcp + 12] = 0x60;  // 24바이트 헤더라고 주장하지만 남은 길이는 20
        CHECK(drop_reason(f) == DropReason::InvalidTcp);
    }
    SECTION("SYN+ACK면 not_connection_attempt") {
        f[kTcp + 13] = 0x12;
        CHECK(drop_reason(f) == DropReason::NotConnectionAttempt);
    }
    SECTION("ACK만 있으면 not_connection_attempt") {
        f[kTcp + 13] = 0x10;
        CHECK(drop_reason(f) == DropReason::NotConnectionAttempt);
    }
    SECTION("플래그가 없으면(NULL 스캔) not_connection_attempt") {
        f[kTcp + 13] = 0x00;
        CHECK(drop_reason(f) == DropReason::NotConnectionAttempt);
    }
    SECTION("FIN만 있으면(FIN 스캔) not_connection_attempt") {
        f[kTcp + 13] = 0x01;
        CHECK(drop_reason(f) == DropReason::NotConnectionAttempt);
    }
    SECTION("SYN+FIN은 ACK가 없으므로 연결 시도로 통과 (DESIGN 문구 그대로)") {
        f[kTcp + 13] = 0x03;
        CHECK(decoded(f).dst_port == 8090);
    }
}

TEST_CASE("to_string은 DESIGN의 제외 사유 이름을 돌려준다", "[decoder]") {
    CHECK(std::string(to_string(DropReason::TruncatedEthernet)) == "truncated_ethernet");
    CHECK(std::string(to_string(DropReason::NotIpv4)) == "not_ipv4");
    CHECK(std::string(to_string(DropReason::TruncatedIpv4)) == "truncated_ipv4");
    CHECK(std::string(to_string(DropReason::InvalidIpv4)) == "invalid_ipv4");
    CHECK(std::string(to_string(DropReason::NotTcp)) == "not_tcp");
    CHECK(std::string(to_string(DropReason::Ipv4Fragment)) == "ipv4_fragment");
    CHECK(std::string(to_string(DropReason::TruncatedTcp)) == "truncated_tcp");
    CHECK(std::string(to_string(DropReason::InvalidTcp)) == "invalid_tcp");
    CHECK(std::string(to_string(DropReason::NotConnectionAttempt)) == "not_connection_attempt");
}

namespace {

// 실제 pcap을 Capture로 읽어 Decoder에 넣은 결과를 모은다
struct DecodeTally {
    Decoder decoder;
    std::size_t frames = 0;
    std::vector<DecodedPacket> packets;
    std::size_t drops[kDropReasonCount] = {};
};

void tally(u_char* user, const pcap_pkthdr* header, const u_char* bytes) {
    auto& t = *reinterpret_cast<DecodeTally*>(user);
    ++t.frames;
    const DecodeResult result = t.decoder.decode(to_raw_frame(header, bytes));
    if (const auto* reason = std::get_if<DropReason>(&result)) {
        ++t.drops[static_cast<std::size_t>(*reason)];
    } else {
        t.packets.push_back(std::get<DecodedPacket>(result));
    }
}

}  // namespace

TEST_CASE("샘플 pcap에서 연결 시도 12개를 찾는다", "[decoder][pcap]") {
    Capture capture = Capture::open_offline("tests/data/sample.pcap");
    DecodeTally t;
    capture.run(tally, reinterpret_cast<u_char*>(&t));

    // 기댓값은 tests/data/make_sample_pcap.py의 프레임 구성 표에서 온다
    CHECK(t.frames == 18);
    CHECK(t.packets.size() == 12);
    CHECK(t.drops[static_cast<std::size_t>(DropReason::NotConnectionAttempt)] == 3);
    CHECK(t.drops[static_cast<std::size_t>(DropReason::NotTcp)] == 1);
    CHECK(t.drops[static_cast<std::size_t>(DropReason::NotIpv4)] == 2);

    // 모든 프레임은 해석되거나 어떤 사유로 제외된다
    std::size_t dropped = 0;
    for (const std::size_t n : t.drops) {
        dropped += n;
    }
    CHECK(t.packets.size() + dropped == t.frames);

    REQUIRE(t.packets.size() == 12);
    const DecodedPacket& first = t.packets[0];
    CHECK(first.src_ip == 0xC6336407);  // 198.51.100.7
    CHECK(first.src_port == 51234);
    CHECK(first.dst_ip == 0x0A010137);  // 10.1.1.55
    CHECK(first.dst_port == 8090);
    CHECK(first.src_mac == MacAddress{{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}});  // make_sample_pcap.py의 MAC_A
    CHECK(first.dst_mac == MacAddress{{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}});  // MAC_B
}
