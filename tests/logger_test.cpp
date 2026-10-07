// Logger 테스트. 출력을 std::ostringstream으로 받아 문자열로 비교한다
#include <catch2/catch.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <optional>
#include <sstream>
#include <string>

#include "capture.hpp"
#include "decoder.hpp"
#include "firewall.hpp"
#include "logger.hpp"

namespace {

// 로그 시각은 로컬 시간대로 찍힌다. 기댓값을 고정하려고 테스트 프로세스의 시간대를 UTC로 둔다
void use_utc() {
    setenv("TZ", "UTC", 1);
    tzset();
}

constexpr std::uint32_t ip(std::uint32_t a, std::uint32_t b, std::uint32_t c, std::uint32_t d) {
    return (a << 24) | (b << 16) | (c << 8) | d;
}

// 2023-11-14 22:13:20.482999 UTC. 밀리초 아래(999)는 버려져야 한다
const TimePoint kTime{std::chrono::seconds{1700000000} + std::chrono::microseconds{482999}};

DecodedPacket packet(std::uint32_t src, std::uint16_t src_port, std::uint32_t dst,
                     std::uint16_t dst_port) {
    DecodedPacket p;
    p.timestamp = kTime;
    p.src_ip = src;
    p.src_port = src_port;
    p.dst_ip = dst;
    p.dst_port = dst_port;
    return p;
}

std::string fw_line(const DecodedPacket& p, const FwVerdict& verdict) {
    use_utc();
    std::ostringstream out;
    Logger logger(out);
    logger.log_fw(p, verdict);
    return out.str();
}

// frames~drops는 sample.pcap(make_sample_pcap.py)을 재생했을 때의 값. 로그 수는 설정에 따라 달라지므로 임의의 값
Stats sample_stats() {
    Stats stats;
    stats.frames = 18;
    stats.decoded = 12;
    stats.drops[static_cast<std::size_t>(DropReason::NotIpv4)] = 2;
    stats.drops[static_cast<std::size_t>(DropReason::NotTcp)] = 1;
    stats.drops[static_cast<std::size_t>(DropReason::NotConnectionAttempt)] = 3;
    stats.fw_logs = 2;
    stats.fw_allowed = 4;
    stats.portscan_logs = 1;
    return stats;
}

const char* const kSampleStatsText =
    "[STATS] frames=18\n"
    "[STATS] decoded=12\n"
    "[STATS] drop.truncated_ethernet=0\n"
    "[STATS] drop.not_ipv4=2\n"
    "[STATS] drop.truncated_ipv4=0\n"
    "[STATS] drop.invalid_ipv4=0\n"
    "[STATS] drop.not_tcp=1\n"
    "[STATS] drop.ipv4_fragment=0\n"
    "[STATS] drop.truncated_tcp=0\n"
    "[STATS] drop.invalid_tcp=0\n"
    "[STATS] drop.not_connection_attempt=3\n"
    "[STATS] fw_logs=2\n"
    "[STATS] fw_allowed=4\n"
    "[STATS] portscan_logs=1\n";

}  // namespace

TEST_CASE("파일 재생 통계에는 커널 수신·누락 수가 없다", "[logger]") {
    std::ostringstream out;
    Logger logger(out);

    logger.print_stats(sample_stats(), std::nullopt);

    CHECK(out.str() == kSampleStatsText);
}

TEST_CASE("실시간 캡처 통계에는 커널 수신·누락 수가 붙는다", "[logger]") {
    std::ostringstream out;
    Logger logger(out);

    logger.print_stats(sample_stats(), CaptureStats{20, 2});

    CHECK(out.str() == std::string(kSampleStatsText) +
                           "[STATS] kernel_received=20\n"
                           "[STATS] kernel_dropped=2\n");
}

TEST_CASE("모든 제외 사유가 한 줄씩 나온다", "[logger]") {
    std::ostringstream out;
    Logger logger(out);

    logger.print_stats(Stats{}, std::nullopt);

    const std::string text = out.str();
    for (std::size_t i = 0; i < kDropReasonCount; ++i) {
        const std::string line =
            std::string("[STATS] drop.") + to_string(static_cast<DropReason>(i)) + "=0\n";
        CHECK(text.find(line) != std::string::npos);
    }
}

TEST_CASE("[FW] 로그: 정책 일치 Allow", "[logger]") {
    const auto p = packet(ip(198, 51, 100, 7), 51240, ip(10, 1, 1, 55), 8090);

    CHECK(fw_line(p, {Direction::Inbound, 1, FwAction::Allow}) ==
          "2023-11-14 22:13:20.482 [FW]       dir=IN  rule=#1      action=ALLOW "
          "198.51.100.7:51240 -> 10.1.1.55:8090\n");
}

TEST_CASE("[FW] 로그: 기본 정책 Deny에는 차단하지 않았다고 붙인다", "[logger]") {
    const auto p = packet(ip(198, 51, 100, 7), 51234, ip(10, 1, 1, 55), 3306);

    CHECK(fw_line(p, {Direction::Inbound, std::nullopt, FwAction::Deny}) ==
          "2023-11-14 22:13:20.482 [FW]       dir=IN  rule=default action=DENY  "
          "198.51.100.7:51234 -> 10.1.1.55:3306 (detect only, not blocked)\n");
}

TEST_CASE("[FW] 로그: Outbound 정책 Deny", "[logger]") {
    const auto p = packet(ip(10, 1, 1, 20), 40112, ip(203, 0, 113, 10), 4444);

    CHECK(fw_line(p, {Direction::Outbound, 3, FwAction::Deny}) ==
          "2023-11-14 22:13:20.482 [FW]       dir=OUT rule=#3      action=DENY  "
          "10.1.1.20:40112 -> 203.0.113.10:4444 (detect only, not blocked)\n");
}

TEST_CASE("[FW] 로그: 경곗값 주소와 두 자리 정책 번호", "[logger]") {
    const auto p = packet(ip(0, 0, 0, 0), 0, ip(255, 255, 255, 255), 65535);

    CHECK(fw_line(p, {Direction::Inbound, 12, FwAction::Allow}) ==
          "2023-11-14 22:13:20.482 [FW]       dir=IN  rule=#12     action=ALLOW "
          "0.0.0.0:0 -> 255.255.255.255:65535\n");
}

TEST_CASE("[PORTSCAN] 로그", "[logger]") {
    use_utc();
    std::ostringstream out;
    Logger logger(out);

    logger.log_portscan({kTime, ip(198, 51, 100, 7), ip(10, 1, 1, 55), 10, std::chrono::seconds{1}});

    CHECK(out.str() ==
          "2023-11-14 22:13:20.482 [PORTSCAN] 198.51.100.7 -> 10.1.1.55 distinct_ports=10 window=1s\n");
}

TEST_CASE("[PORTSCAN] 로그: 초로 나누어떨어지지 않는 윈도우는 밀리초로", "[logger]") {
    std::ostringstream out;
    Logger logger(out);

    logger.log_portscan({kTime, ip(198, 51, 100, 7), ip(10, 1, 1, 55), 3, std::chrono::milliseconds{1500}});

    CHECK(out.str().find(" window=1500ms\n") != std::string::npos);
}

TEST_CASE("[FW] 로그: 밀리초가 한 자리여도 세 자리로 채운다", "[logger]") {
    auto p = packet(ip(198, 51, 100, 7), 1, ip(10, 1, 1, 55), 2);
    p.timestamp = TimePoint{std::chrono::seconds{1700000000} + std::chrono::microseconds{7000}};

    CHECK(fw_line(p, {Direction::Inbound, 1, FwAction::Allow}).rfind("2023-11-14 22:13:20.007 ", 0) == 0);
}
