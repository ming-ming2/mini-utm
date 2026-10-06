#include "firewall.hpp"

FirewallPolicy::FirewallPolicy(const Config& config)
    : home_nets_(config.home_nets), rules_(config.rules) {}

// DESIGN 5.1 매칭 규칙과 동작
std::optional<FwVerdict> FirewallPolicy::evaluate(const DecodedPacket& packet) const {
    const auto direction = direction_of(packet);
    if (!direction) {
        return std::nullopt;
    }

    // First Match. 정책은 방향을 가리지 않고 목적지 IP·Port만 비교한다
    for (std::size_t i = 0; i < rules_.size(); ++i) {
        const FwRule& rule = rules_[i];
        if (rule.ip == packet.dst_ip && rule.port == packet.dst_port) {
            return FwVerdict{*direction, i + 1, rule.action};
        }
    }

    // 기본 정책. Outbound 기본 허용은 로그를 남기지 않는다
    if (*direction == Direction::Inbound) {
        return FwVerdict{Direction::Inbound, std::nullopt, FwAction::Deny};
    }
    return std::nullopt;
}

bool FirewallPolicy::is_home(std::uint32_t ip) const {
    for (const Cidr& net : home_nets_) {
        if (net.contains(ip)) {
            return true;
        }
    }
    return false;
}

// 내부↔내부, 외부↔외부는 경계를 통과하지 않으므로 판단 대상이 아니다
std::optional<Direction> FirewallPolicy::direction_of(const DecodedPacket& packet) const {
    const bool src_home = is_home(packet.src_ip);
    const bool dst_home = is_home(packet.dst_ip);
    if (src_home == dst_home) {
        return std::nullopt;
    }
    return src_home ? Direction::Outbound : Direction::Inbound;
}
