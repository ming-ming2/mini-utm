#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <ostream>

#include "capture.hpp"
#include "decoder.hpp"
#include "firewall.hpp"
#include "portscan.hpp"

// DESIGN 6장. on_frame이 채우고 Logger가 출력한다
struct Stats {
    std::uint64_t frames = 0;
    std::uint64_t decoded = 0;
    std::array<std::uint64_t, kDropReasonCount> drops{};
    std::uint64_t fw_logs = 0;
    std::uint64_t portscan_logs = 0;
};

// 로그 형식은 DESIGN 6장
class Logger {
public:
    explicit Logger(std::ostream& out);

    void log_fw(const DecodedPacket& packet, const FwVerdict& verdict);
    void log_portscan(const PortScanAlert& alert);
    // capture_stats가 비어 있으면 커널 수신·누락 수를 출력하지 않는다
    void print_stats(const Stats& stats, const std::optional<CaptureStats>& capture_stats);

private:
    std::ostream& out_;
};
