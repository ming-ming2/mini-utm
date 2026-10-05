#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "config.hpp"
#include "decoder.hpp"

enum class Direction { Inbound, Outbound };

struct FwVerdict {
    Direction direction;
    std::optional<std::size_t> rule_number;  // 비어 있으면 기본 정책
    FwAction action;
};

class FirewallPolicy {
public:
    explicit FirewallPolicy(const Config& config);

    // 판단 대상이 아니거나 Outbound 기본 허용이면 비어 있는 값
    std::optional<FwVerdict> evaluate(const DecodedPacket& packet) const;

private:
    bool is_home(std::uint32_t ip) const;
    std::optional<Direction> direction_of(const DecodedPacket& packet) const;

    std::vector<Cidr> home_nets_;
    std::vector<FwRule> rules_;
};
