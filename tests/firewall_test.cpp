// FirewallPolicy 테스트. Config를 코드로 만들어 넣고 판정을 확인한다
#include <catch2/catch.hpp>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>

#include "config.hpp"
#include "decoder.hpp"
#include "firewall.hpp"

namespace {

constexpr std::uint32_t ip(std::uint32_t a, std::uint32_t b, std::uint32_t c, std::uint32_t d) {
    return (a << 24) | (b << 16) | (c << 8) | d;
}

const std::uint32_t kInside = ip(10, 1, 1, 55);
const std::uint32_t kInside2 = ip(10, 1, 1, 20);
const std::uint32_t kOutside = ip(198, 51, 100, 7);
const std::uint32_t kOutside2 = ip(203, 0, 113, 10);

DecodedPacket packet(std::uint32_t src, std::uint32_t dst, std::uint16_t dst_port) {
    DecodedPacket p;
    p.src_ip = src;
    p.dst_ip = dst;
    p.src_port = 51234;
    p.dst_port = dst_port;
    return p;
}

// 내부망 10.1.1.0/24
Config config_with(std::initializer_list<FwRule> rules) {
    Config config;
    config.home_nets = {Cidr{ip(10, 1, 1, 0), 0xFFFFFF00}};
    config.rules = rules;
    return config;
}

}  // namespace

TEST_CASE("내부↔내부, 외부↔외부는 판단하지 않는다", "[firewall]") {
    // 일치하는 정책이 있어도 방향이 없으면 판단하지 않는다
    const FirewallPolicy fw(config_with({
        {FwAction::Deny, kInside, 22},
        {FwAction::Deny, kOutside2, 4444},
    }));

    CHECK_FALSE(fw.evaluate(packet(kInside2, kInside, 22)));
    CHECK_FALSE(fw.evaluate(packet(kOutside, kOutside2, 4444)));
}

TEST_CASE("Inbound는 정책에 없으면 기본 Deny", "[firewall]") {
    const FirewallPolicy fw(config_with({}));

    const auto verdict = fw.evaluate(packet(kOutside, kInside, 3306));

    REQUIRE(verdict);
    CHECK(verdict->direction == Direction::Inbound);
    CHECK_FALSE(verdict->rule_number);
    CHECK(verdict->action == FwAction::Deny);
}

TEST_CASE("Outbound는 정책에 없으면 기본 Allow이고 로그를 남기지 않는다", "[firewall]") {
    const FirewallPolicy fw(config_with({}));

    CHECK_FALSE(fw.evaluate(packet(kInside, kOutside2, 443)));
}

TEST_CASE("정책에 일치하면 1부터 센 정책 번호를 준다", "[firewall]") {
    const FirewallPolicy fw(config_with({
        {FwAction::Allow, kInside, 8090},
        {FwAction::Allow, kInside, 22},
        {FwAction::Deny, kOutside2, 4444},
    }));

    SECTION("Inbound allow") {
        const auto verdict = fw.evaluate(packet(kOutside, kInside, 22));
        REQUIRE(verdict);
        CHECK(verdict->direction == Direction::Inbound);
        CHECK(verdict->rule_number == std::optional<std::size_t>{2});
        CHECK(verdict->action == FwAction::Allow);
    }
    SECTION("Outbound deny") {
        const auto verdict = fw.evaluate(packet(kInside2, kOutside2, 4444));
        REQUIRE(verdict);
        CHECK(verdict->direction == Direction::Outbound);
        CHECK(verdict->rule_number == std::optional<std::size_t>{3});
        CHECK(verdict->action == FwAction::Deny);
    }
}

TEST_CASE("처음 일치한 정책 하나만 적용한다", "[firewall]") {
    const FirewallPolicy fw(config_with({
        {FwAction::Deny, kInside, 22},
        {FwAction::Allow, kInside, 22},
    }));

    const auto verdict = fw.evaluate(packet(kOutside, kInside, 22));

    REQUIRE(verdict);
    CHECK(verdict->rule_number == std::optional<std::size_t>{1});
    CHECK(verdict->action == FwAction::Deny);
}

TEST_CASE("IP와 Port가 모두 같아야 일치한다", "[firewall]") {
    const FirewallPolicy fw(config_with({{FwAction::Allow, kInside, 8090}}));

    // Port만 같음, IP만 같음 → 기본 Deny
    const auto other_ip = fw.evaluate(packet(kOutside, kInside2, 8090));
    const auto other_port = fw.evaluate(packet(kOutside, kInside, 8091));
    REQUIRE(other_ip);
    REQUIRE(other_port);
    CHECK_FALSE(other_ip->rule_number);
    CHECK_FALSE(other_port->rule_number);
}

TEST_CASE("정책은 출발지가 아니라 목적지와 비교한다", "[firewall]") {
    // 출발지 Port가 정책 Port와 같아도 일치하지 않는다
    const FirewallPolicy fw(config_with({{FwAction::Allow, kInside, 51234}}));

    const auto verdict = fw.evaluate(packet(kOutside, kInside, 8090));

    REQUIRE(verdict);
    CHECK_FALSE(verdict->rule_number);
}

TEST_CASE("Outbound allow 정책에 일치하면 로그를 남긴다", "[firewall]") {
    const FirewallPolicy fw(config_with({{FwAction::Allow, kOutside2, 443}}));

    const auto verdict = fw.evaluate(packet(kInside, kOutside2, 443));

    REQUIRE(verdict);
    CHECK(verdict->direction == Direction::Outbound);
    CHECK(verdict->action == FwAction::Allow);
}

TEST_CASE("내부망 대역이 여러 개면 하나라도 포함하면 내부", "[firewall]") {
    Config config = config_with({});
    config.home_nets.push_back(Cidr{ip(192, 168, 0, 0), 0xFFFF0000});
    const FirewallPolicy fw(config);

    // 10.1.1.55 → 192.168.3.4: 내부↔내부
    CHECK_FALSE(fw.evaluate(packet(kInside, ip(192, 168, 3, 4), 80)));
    // 198.51.100.7 → 192.168.3.4: Inbound
    const auto verdict = fw.evaluate(packet(kOutside, ip(192, 168, 3, 4), 80));
    REQUIRE(verdict);
    CHECK(verdict->direction == Direction::Inbound);
}
