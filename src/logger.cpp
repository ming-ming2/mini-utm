#include "logger.hpp"

#include <chrono>
#include <cstddef>
#include <cstdio>
#include <ctime>
#include <string>

namespace {

// "2026-09-29 14:03:21.482". 로컬 시간대, 밀리초 아래는 버린다
std::string format_time(TimePoint t) {
    const auto seconds = std::chrono::floor<std::chrono::seconds>(t);
    const auto millis =
        std::chrono::duration_cast<std::chrono::milliseconds>(t - seconds).count();
    const std::time_t tt = Clock::to_time_t(seconds);
    std::tm tm{};
    localtime_r(&tt, &tm);

    char date[20];  // "YYYY-MM-DD HH:MM:SS"
    std::strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &tm);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%s.%03d", date, static_cast<int>(millis));
    return buf;
}

// 호스트 바이트 순서 정수를 "a.b.c.d"로
std::string format_ip(std::uint32_t ip) {
    return std::to_string(ip >> 24) + '.' + std::to_string((ip >> 16) & 0xFF) + '.' +
           std::to_string((ip >> 8) & 0xFF) + '.' + std::to_string(ip & 0xFF);
}

std::string format_endpoint(std::uint32_t ip, std::uint16_t port) {
    return format_ip(ip) + ':' + std::to_string(port);
}

// 초 단위로 나누어떨어지면 "1s", 아니면 "500ms". 밀리초 아래는 버린다
std::string format_duration(Duration d) {
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(d).count();
    if (millis % 1000 == 0) {
        return std::to_string(millis / 1000) + 's';
    }
    return std::to_string(millis) + "ms";
}

// 오른쪽을 공백으로 채워 width 글자로 만든다. 출력 스트림의 서식 상태를 바꾸지 않으려고 직접 채운다
std::string pad(std::string s, std::size_t width) {
    if (s.size() < width) {
        s.append(width - s.size(), ' ');
    }
    return s;
}

}  // namespace

Logger::Logger(std::ostream& out) : out_(out) {}

// DESIGN 6장 [FW] 로그. 열을 맞추려고 각 필드를 가장 긴 값의 너비로 채운다
void Logger::log_fw(const DecodedPacket& packet, const FwVerdict& verdict) {
    const bool inbound = verdict.direction == Direction::Inbound;
    const bool deny = verdict.action == FwAction::Deny;
    const std::string rule =
        verdict.rule_number ? "#" + std::to_string(*verdict.rule_number) : "default";

    // "[FW]"는 "[PORTSCAN]"과 같은 너비로 채워 뒤의 내용이 같은 열에서 시작하게 한다
    out_ << format_time(packet.timestamp) << ' ' << pad("[FW]", 10) << ' '
         << pad(inbound ? "dir=IN" : "dir=OUT", 7) << ' ' << pad("rule=" + rule, 12) << ' '
         << pad(deny ? "action=DENY" : "action=ALLOW", 12) << ' '
         << format_endpoint(packet.src_ip, packet.src_port) << " -> "
         << format_endpoint(packet.dst_ip, packet.dst_port);
    // Detection Only. Deny여도 실제로 막지는 않았음을 밝힌다
    if (deny) {
        out_ << " (detect only, not blocked)";
    }
    out_ << '\n';
}

// DESIGN 6장 [PORTSCAN] 로그
void Logger::log_portscan(const PortScanAlert& alert) {
    out_ << format_time(alert.timestamp) << ' ' << "[PORTSCAN]" << ' '
         << format_ip(alert.src_ip) << " -> " << format_ip(alert.dst_ip)
         << " distinct_ports=" << alert.distinct_ports
         << " window=" << format_duration(alert.window) << '\n';
}

// DESIGN 6장. 개수가 0인 제외 사유도 출력해 실행마다 같은 줄이 나오게 한다
void Logger::print_stats(const Stats& stats,
                         const std::optional<CaptureStats>& capture_stats) {
    out_ << "[STATS] frames=" << stats.frames << '\n'
         << "[STATS] decoded=" << stats.decoded << '\n';
    for (std::size_t i = 0; i < kDropReasonCount; ++i) {
        out_ << "[STATS] drop." << to_string(static_cast<DropReason>(i)) << '=' << stats.drops[i]
             << '\n';
    }
    out_ << "[STATS] fw_logs=" << stats.fw_logs << '\n'
         << "[STATS] fw_allowed=" << stats.fw_allowed << '\n'
         << "[STATS] portscan_logs=" << stats.portscan_logs << '\n';
    // 파일 재생에는 커널 버퍼가 관여하지 않는다
    if (capture_stats) {
        out_ << "[STATS] kernel_received=" << capture_stats->received << '\n'
             << "[STATS] kernel_dropped=" << capture_stats->dropped << '\n';
    }
}
