// Config 테스트. 설정 내용을 임시 파일로 써서 load_config에 넘긴다
#include <catch2/catch.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include "config.hpp"

namespace {

// 테스트 하나가 쓰는 임시 설정 파일. 소멸자가 지운다
class TempConfig {
public:
    explicit TempConfig(const std::string& content)
        : path_(std::filesystem::temp_directory_path() / "mini_utm_config_test.conf") {
        std::ofstream(path_) << content;
    }
    ~TempConfig() { std::filesystem::remove(path_); }
    TempConfig(const TempConfig&) = delete;
    TempConfig& operator=(const TempConfig&) = delete;

    std::string path() const { return path_.string(); }

private:
    std::filesystem::path path_;
};

Config load(const std::string& content) {
    const TempConfig file(content);
    return load_config(file.path());
}

// 실패 메시지에 "<경로>:<줄 번호>:"가 들어가는지 확인한다
void require_error_at_line(const std::string& content, int line_number) {
    const TempConfig file(content);
    const std::string expected = file.path() + ":" + std::to_string(line_number) + ":";
    REQUIRE_THROWS_WITH(load_config(file.path()), Catch::Contains(expected));
}

constexpr std::uint32_t ip(std::uint32_t a, std::uint32_t b, std::uint32_t c, std::uint32_t d) {
    return (a << 24) | (b << 16) | (c << 8) | d;
}

}  // namespace

TEST_CASE("Cidr는 대역 안의 IP만 포함한다", "[config]") {
    const Cidr net{ip(10, 1, 1, 0), 0xFFFFFF00};  // 10.1.1.0/24

    CHECK(net.contains(ip(10, 1, 1, 0)));
    CHECK(net.contains(ip(10, 1, 1, 55)));
    CHECK(net.contains(ip(10, 1, 1, 255)));
    CHECK_FALSE(net.contains(ip(10, 1, 2, 0)));
    CHECK_FALSE(net.contains(ip(10, 1, 0, 255)));
}

TEST_CASE("/0은 모든 IP를, /32는 IP 하나만 포함한다", "[config]") {
    CHECK(Cidr{0, 0}.contains(ip(203, 0, 113, 9)));

    const Cidr host{ip(10, 1, 1, 55), 0xFFFFFFFF};
    CHECK(host.contains(ip(10, 1, 1, 55)));
    CHECK_FALSE(host.contains(ip(10, 1, 1, 56)));
}

TEST_CASE("home_net과 fw 줄을 읽는다", "[config]") {
    const Config config = load(
        "home_net 10.1.1.0/24\n"
        "home_net 192.168.0.0/16\n"
        "\n"
        "fw allow 10.1.1.55:8090\n"
        "fw deny  203.0.113.10:4444\n");

    REQUIRE(config.home_nets.size() == 2);
    CHECK(config.home_nets[0].network == ip(10, 1, 1, 0));
    CHECK(config.home_nets[0].mask == 0xFFFFFF00);
    CHECK(config.home_nets[1].network == ip(192, 168, 0, 0));
    CHECK(config.home_nets[1].mask == 0xFFFF0000);

    REQUIRE(config.rules.size() == 2);
    CHECK(config.rules[0].action == FwAction::Allow);
    CHECK(config.rules[0].ip == ip(10, 1, 1, 55));
    CHECK(config.rules[0].port == 8090);
    CHECK(config.rules[1].action == FwAction::Deny);
    CHECK(config.rules[1].ip == ip(203, 0, 113, 10));
    CHECK(config.rules[1].port == 4444);
}

TEST_CASE("fw 줄은 파일에 적힌 순서를 유지한다", "[config]") {
    const Config config = load(
        "fw deny  10.1.1.55:22\n"
        "fw allow 10.1.1.55:8090\n"
        "fw allow 10.1.1.55:22\n");

    REQUIRE(config.rules.size() == 3);
    CHECK(config.rules[0].port == 22);
    CHECK(config.rules[0].action == FwAction::Deny);
    CHECK(config.rules[1].port == 8090);
    CHECK(config.rules[2].port == 22);
    CHECK(config.rules[2].action == FwAction::Allow);
}

TEST_CASE("home_net이 없으면 RFC 1918 대역을 쓴다", "[config]") {
    const Config config = load("fw allow 10.1.1.55:8090\n");

    REQUIRE(config.home_nets.size() == 3);
    CHECK(config.home_nets[0].network == ip(10, 0, 0, 0));
    CHECK(config.home_nets[0].mask == 0xFF000000);
    CHECK(config.home_nets[1].network == ip(172, 16, 0, 0));
    CHECK(config.home_nets[1].mask == 0xFFF00000);
    CHECK(config.home_nets[2].network == ip(192, 168, 0, 0));
    CHECK(config.home_nets[2].mask == 0xFFFF0000);
}

TEST_CASE("빈 파일이면 기본 대역만 있고 정책은 없다", "[config]") {
    const Config config = load("");

    CHECK(config.home_nets.size() == 3);
    CHECK(config.rules.empty());
}

TEST_CASE("빈 줄, 주석, 공백 종류, CRLF를 가리지 않는다", "[config]") {
    const Config config = load(
        "# 내부망\r\n"
        "   \r\n"
        "\thome_net\t10.0.0.0/8  \r\n"
        "  # 들여쓴 주석\n"
        "fw   allow   10.1.1.55:8090\r\n");

    REQUIRE(config.home_nets.size() == 1);
    CHECK(config.home_nets[0].network == ip(10, 0, 0, 0));
    REQUIRE(config.rules.size() == 1);
    CHECK(config.rules[0].port == 8090);
}

TEST_CASE("경곗값을 받는다", "[config]") {
    const Config config = load(
        "home_net 0.0.0.0/0\n"
        "home_net 255.255.255.255/32\n"
        "fw allow 0.0.0.0:0\n"
        "fw deny  255.255.255.255:65535\n");

    REQUIRE(config.home_nets.size() == 2);
    CHECK(config.home_nets[0].mask == 0);
    CHECK(config.home_nets[1].network == 0xFFFFFFFF);
    CHECK(config.home_nets[1].mask == 0xFFFFFFFF);
    REQUIRE(config.rules.size() == 2);
    CHECK(config.rules[0].port == 0);
    CHECK(config.rules[1].ip == 0xFFFFFFFF);
    CHECK(config.rules[1].port == 65535);
}

TEST_CASE("저장소의 예시 설정 파일을 읽는다", "[config]") {
    const Config config = load_config("config/mini_utm.conf");

    CHECK(config.home_nets.size() == 3);
    CHECK(config.rules.size() == 2);
}

TEST_CASE("열 수 없는 설정 파일이면 runtime_error", "[config][error]") {
    REQUIRE_THROWS_AS(load_config("tests/data/no_such.conf"), std::runtime_error);
}

TEST_CASE("문법 오류는 줄 번호를 담아 runtime_error", "[config][error]") {
    SECTION("알 수 없는 키워드") { require_error_at_line("home_net 10.0.0.0/8\nallow 1.2.3.4:80\n", 2); }
    SECTION("인자 개수") {
        require_error_at_line("home_net\n", 1);
        require_error_at_line("home_net 10.0.0.0/8 10.0.0.0/8\n", 1);
        require_error_at_line("fw allow\n", 1);
        require_error_at_line("fw allow 1.2.3.4:80 extra\n", 1);
    }
    SECTION("action") {
        require_error_at_line("fw ALLOW 1.2.3.4:80\n", 1);
        require_error_at_line("fw drop 1.2.3.4:80\n", 1);
    }
    SECTION("IP") {
        require_error_at_line("fw allow 1.2.3:80\n", 1);
        require_error_at_line("fw allow 1.2.3.4.5:80\n", 1);
        require_error_at_line("fw allow 1.2.3.256:80\n", 1);
        require_error_at_line("fw allow 1.2..4:80\n", 1);
        require_error_at_line("fw allow 1.2.3.-4:80\n", 1);
        require_error_at_line("fw allow 010.0.0.1:80\n", 1);
        require_error_at_line("fw allow a.b.c.d:80\n", 1);
    }
    SECTION("Port") {
        require_error_at_line("fw allow 1.2.3.4\n", 1);
        require_error_at_line("fw allow 1.2.3.4:\n", 1);
        require_error_at_line("fw allow 1.2.3.4:65536\n", 1);
        require_error_at_line("fw allow 1.2.3.4:+80\n", 1);
        require_error_at_line("fw allow 1.2.3.4:http\n", 1);
    }
    SECTION("CIDR") {
        require_error_at_line("home_net 10.0.0.0\n", 1);
        require_error_at_line("home_net 10.0.0.0/\n", 1);
        require_error_at_line("home_net 10.0.0.0/33\n", 1);
        require_error_at_line("home_net 10.1.1.5/24\n", 1);  // 호스트 부분이 0이 아님
    }
    SECTION("앞의 빈 줄과 주석도 줄 번호에 센다") {
        require_error_at_line("# comment\n\nfw allow 1.2.3.4:99999\n", 3);
    }
}
