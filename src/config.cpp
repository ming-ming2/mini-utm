#include "config.hpp"

#include <charconv>
#include <cstddef>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

namespace {

// 10진수 숫자만으로 된 문자열을 max 이하의 정수로 바꾼다. 부호, 공백, 빈 문자열은 실패
std::optional<std::uint32_t> parse_number(std::string_view s, std::uint32_t max) {
    std::uint32_t value = 0;
    const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
    if (ec != std::errc{} || end != s.data() + s.size() || value > max) {
        return std::nullopt;
    }
    return value;
}

// "a.b.c.d"를 호스트 바이트 순서 정수로 바꾼다.
// 앞자리 0("010")은 도구에 따라 8진수로 읽히므로 받지 않는다
std::optional<std::uint32_t> parse_ipv4(std::string_view s) {
    std::uint32_t ip = 0;
    for (int i = 0; i < 4; ++i) {
        const std::size_t dot = s.find('.');
        const bool last = (i == 3);
        if (last != (dot == std::string_view::npos)) {
            return std::nullopt;  // 점이 3개가 아니다
        }
        const std::string_view octet = last ? s : s.substr(0, dot);
        if (octet.size() > 1 && octet[0] == '0') {
            return std::nullopt;
        }
        const auto value = parse_number(octet, 255);
        if (!value) {
            return std::nullopt;
        }
        ip = (ip << 8) | *value;
        if (!last) {
            s.remove_prefix(dot + 1);
        }
    }
    return ip;
}

std::uint32_t prefix_to_mask(std::uint32_t prefix) {
    // 32비트 값을 32칸 미는 것은 정의되지 않은 동작이므로 /0을 따로 처리한다
    return prefix == 0 ? 0 : ~std::uint32_t{0} << (32 - prefix);
}

// "a.b.c.d/n". 호스트 부분이 0이 아니면(10.1.1.5/24) 오타일 가능성이 높으므로 받지 않는다
std::optional<Cidr> parse_cidr(std::string_view s) {
    const std::size_t slash = s.find('/');
    if (slash == std::string_view::npos) {
        return std::nullopt;
    }
    const auto ip = parse_ipv4(s.substr(0, slash));
    const auto prefix = parse_number(s.substr(slash + 1), 32);
    if (!ip || !prefix) {
        return std::nullopt;
    }
    const std::uint32_t mask = prefix_to_mask(*prefix);
    if ((*ip & ~mask) != 0) {
        return std::nullopt;
    }
    return Cidr{*ip, mask};
}

// "a.b.c.d:port"
std::optional<FwRule> parse_target(FwAction action, std::string_view s) {
    const std::size_t colon = s.find(':');
    if (colon == std::string_view::npos) {
        return std::nullopt;
    }
    const auto ip = parse_ipv4(s.substr(0, colon));
    const auto port = parse_number(s.substr(colon + 1), 65535);
    if (!ip || !port) {
        return std::nullopt;
    }
    return FwRule{action, *ip, static_cast<std::uint16_t>(*port)};
}

[[noreturn]] void fail(const std::string& path, std::size_t line_number, const std::string& reason) {
    throw std::runtime_error(path + ":" + std::to_string(line_number) + ": " + reason);
}

}  // namespace

bool Cidr::contains(std::uint32_t ip) const {
    return (ip & mask) == network;
}

// DESIGN 5.1 설정 파일. 빈 줄과 '#'로 시작하는 줄은 건너뛴다. 단어 사이 공백은 개수와 종류를 가리지 않는다
Config load_config(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error(path + ": cannot open config file");
    }

    Config config;
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(in, line)) {
        ++line_number;
        std::istringstream words(line);
        std::string keyword;
        if (!(words >> keyword) || keyword[0] == '#') {
            continue;
        }

        std::string arg1;
        std::string arg2;
        std::string extra;
        if (keyword == "home_net") {
            if (!(words >> arg1) || (words >> extra)) {
                fail(path, line_number, "expected 'home_net <cidr>'");
            }
            const auto cidr = parse_cidr(arg1);
            if (!cidr) {
                fail(path, line_number, "invalid cidr '" + arg1 + "'");
            }
            config.home_nets.push_back(*cidr);
        } else if (keyword == "fw") {
            if (!(words >> arg1 >> arg2) || (words >> extra)) {
                fail(path, line_number, "expected 'fw <allow|deny> <ip>:<port>'");
            }
            if (arg1 != "allow" && arg1 != "deny") {
                fail(path, line_number, "invalid action '" + arg1 + "'");
            }
            const FwAction action = (arg1 == "allow") ? FwAction::Allow : FwAction::Deny;
            const auto rule = parse_target(action, arg2);
            if (!rule) {
                fail(path, line_number, "invalid target '" + arg2 + "'");
            }
            config.rules.push_back(*rule);
        } else {
            fail(path, line_number, "unknown keyword '" + keyword + "'");
        }
    }
    if (in.bad()) {
        throw std::runtime_error(path + ": read error");
    }

    // DESIGN 5.1 기본 내부망 대역
    if (config.home_nets.empty()) {
        config.home_nets = {
            Cidr{0x0A000000, 0xFF000000},  // 10.0.0.0/8
            Cidr{0xAC100000, 0xFFF00000},  // 172.16.0.0/12
            Cidr{0xC0A80000, 0xFFFF0000},  // 192.168.0.0/16
        };
    }
    return config;
}
