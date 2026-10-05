#include "logger.hpp"

Logger::Logger(std::ostream& out) : out_(out) {}

void Logger::log_fw(const DecodedPacket& /*packet*/, const FwVerdict& /*verdict*/) {
    // TODO: [FW] 로그 한 줄
}

void Logger::log_portscan(const PortScanAlert& /*alert*/) {
    // TODO: [PORTSCAN] 로그 한 줄
}

void Logger::print_stats(const Stats& /*stats*/,
                         const std::optional<CaptureStats>& /*capture_stats*/) {
    // TODO: 종료 통계
}
