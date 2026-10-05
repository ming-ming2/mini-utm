#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct Cidr {
    std::uint32_t network = 0;
    std::uint32_t mask = 0;

    bool contains(std::uint32_t ip) const;
};

// FwRule과 FwVerdict가 함께 쓴다. firewall.hpp가 config.hpp를 include하므로 여기에 둔다
enum class FwAction { Allow, Deny };

// fw 줄 하나
struct FwRule {
    FwAction action = FwAction::Allow;
    std::uint32_t ip = 0;
    std::uint16_t port = 0;
};

struct Config {
    std::vector<Cidr> home_nets;  // home_net 줄이 없으면 RFC 1918 대역으로 채운다
    std::vector<FwRule> rules;    // 파일에 기술된 순서를 유지한다
};

// 파일을 열 수 없거나 문법에 맞지 않는 줄이 있으면 줄 번호를 담아 std::runtime_error
Config load_config(const std::string& path);
