#include "firewall.hpp"

FirewallPolicy::FirewallPolicy(const Config& config)
    : home_nets_(config.home_nets), rules_(config.rules) {}

std::optional<FwVerdict> FirewallPolicy::evaluate(const DecodedPacket& /*packet*/) const {
    // TODO: DESIGN 5.1 매칭 규칙과 로그 출력 조건
    return std::nullopt;
}

bool FirewallPolicy::is_home(std::uint32_t /*ip*/) const {
    // TODO
    return false;
}

std::optional<Direction> FirewallPolicy::direction_of(const DecodedPacket& /*packet*/) const {
    // TODO
    return std::nullopt;
}
