// PortScanDetector 테스트. 임계값을 3으로 낮춰 패킷 몇 개로 동작을 확인한다
#include <catch2/catch.hpp>

#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <optional>

#include "capture.hpp"
#include "decoder.hpp"
#include "portscan.hpp"

using namespace std::chrono_literals;

namespace {

constexpr std::uint32_t ip(std::uint32_t a, std::uint32_t b, std::uint32_t c, std::uint32_t d) {
    return (a << 24) | (b << 16) | (c << 8) | d;
}

const std::uint32_t kAttacker = ip(198, 51, 100, 7);
const std::uint32_t kTarget = ip(10, 1, 1, 55);
const std::uint32_t kTarget2 = ip(10, 1, 1, 20);

const TimePoint kStart{std::chrono::seconds{1700000000}};

constexpr std::size_t kThreshold = 3;

PortScanDetector detector() {
    return PortScanDetector(1s, kThreshold, 10s);
}

DecodedPacket packet(Duration at, std::uint32_t dst, std::uint16_t dst_port) {
    DecodedPacket p;
    p.timestamp = kStart + at;
    p.src_ip = kAttacker;
    p.dst_ip = dst;
    p.src_port = 51234;
    p.dst_port = dst_port;
    return p;
}

// 같은 시각에 ports를 차례로 넣고, 마지막 패킷의 결과를 돌려준다
std::optional<PortScanAlert> observe_ports(PortScanDetector& d, Duration at, std::uint32_t dst,
                                           std::initializer_list<std::uint16_t> ports) {
    std::optional<PortScanAlert> last;
    for (const auto port : ports) {
        last = d.observe(packet(at, dst, port));
    }
    return last;
}

}  // namespace

TEST_CASE("서로 다른 Port가 임계값에 도달하면 탐지한다", "[portscan]") {
    auto d = detector();

    CHECK_FALSE(d.observe(packet(0ms, kTarget, 21)));
    CHECK_FALSE(d.observe(packet(100ms, kTarget, 22)));
    const auto alert = d.observe(packet(200ms, kTarget, 23));

    REQUIRE(alert);
    CHECK(alert->timestamp == kStart + 200ms);
    CHECK(alert->src_ip == kAttacker);
    CHECK(alert->dst_ip == kTarget);
    CHECK(alert->distinct_ports == kThreshold);
    CHECK(alert->window == 1s);
}

TEST_CASE("같은 Port를 반복해도 한 번으로 센다", "[portscan]") {
    auto d = detector();

    CHECK_FALSE(observe_ports(d, 0ms, kTarget, {22, 22, 22, 22, 80, 80, 22}));
}

TEST_CASE("하나의 스캔 동안 로그는 한 번만", "[portscan]") {
    auto d = detector();

    REQUIRE(observe_ports(d, 0ms, kTarget, {21, 22, 23}));
    CHECK_FALSE(d.observe(packet(100ms, kTarget, 24)));
    CHECK_FALSE(d.observe(packet(200ms, kTarget, 25)));
}

TEST_CASE("스캔이 멈췄다가 다시 시작하면 새로 탐지한다", "[portscan]") {
    auto d = detector();

    REQUIRE(observe_ports(d, 0ms, kTarget, {21, 22, 23}));
    // 윈도우가 지나 이전 기록이 모두 만료된다
    CHECK_FALSE(d.observe(packet(2s, kTarget, 80)));
    CHECK_FALSE(d.observe(packet(2s, kTarget, 81)));
    CHECK(d.observe(packet(2s, kTarget, 82)));
}

TEST_CASE("윈도우는 경계를 포함한다", "[portscan]") {
    SECTION("정확히 window 전 기록은 남는다") {
        auto d = detector();
        d.observe(packet(0ms, kTarget, 21));
        d.observe(packet(500ms, kTarget, 22));

        CHECK(d.observe(packet(1s, kTarget, 23)));
    }
    SECTION("window보다 조금이라도 오래되면 만료된다") {
        auto d = detector();
        d.observe(packet(0ms, kTarget, 21));
        d.observe(packet(500ms, kTarget, 22));

        CHECK_FALSE(d.observe(packet(1s + 1us, kTarget, 23)));
    }
}

TEST_CASE("목적지 IP가 다르면 따로 집계한다", "[portscan]") {
    auto d = detector();

    CHECK_FALSE(observe_ports(d, 0ms, kTarget, {21, 22}));
    CHECK_FALSE(observe_ports(d, 0ms, kTarget2, {23, 24}));
}

TEST_CASE("출발지·목적지가 뒤바뀐 쌍은 다른 키다", "[portscan]") {
    auto d = detector();

    d.observe(packet(0ms, kTarget, 21));
    d.observe(packet(0ms, kTarget, 22));
    auto reversed = packet(0ms, kAttacker, 23);
    reversed.src_ip = kTarget;

    CHECK_FALSE(d.observe(reversed));
}

TEST_CASE("시각이 역행해도 윈도우 계산은 가장 큰 시각을 따른다", "[portscan]") {
    auto d = detector();

    d.observe(packet(5s, kTarget, 21));
    // 시계가 3초 뒤로 조정됐다. 보정하지 않으면 21번 기록과 2초 차이로 보인다
    d.observe(packet(2s, kTarget, 22));
    const auto alert = d.observe(packet(2s, kTarget, 23));

    REQUIRE(alert);
    // 로그 시각은 보정하지 않은 원래 캡처 시각
    CHECK(alert->timestamp == kStart + 2s);
}

TEST_CASE("상태 정리 후에도 탐지는 그대로 동작한다", "[portscan]") {
    auto d = detector();

    // 0초에 키 2개 생성, 15초에 상태 정리가 일어나 만료된 키가 삭제된다
    observe_ports(d, 0ms, kTarget, {21, 22});
    observe_ports(d, 0ms, kTarget2, {21, 22});

    CHECK_FALSE(observe_ports(d, 15s, kTarget, {80, 81}));
    CHECK(d.observe(packet(15s, kTarget, 82)));
}
