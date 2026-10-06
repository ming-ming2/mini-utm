#include "logger.hpp"

#include <cstddef>

Logger::Logger(std::ostream& out) : out_(out) {}

void Logger::log_fw(const DecodedPacket& /*packet*/, const FwVerdict& /*verdict*/) {
    // TODO: [FW] 로그 한 줄
}

void Logger::log_portscan(const PortScanAlert& /*alert*/) {
    // TODO: [PORTSCAN] 로그 한 줄
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
         << "[STATS] portscan_logs=" << stats.portscan_logs << '\n';
    // 파일 재생에는 커널 버퍼가 관여하지 않는다
    if (capture_stats) {
        out_ << "[STATS] kernel_received=" << capture_stats->received << '\n'
             << "[STATS] kernel_dropped=" << capture_stats->dropped << '\n';
    }
}
