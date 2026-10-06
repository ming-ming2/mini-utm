// Logger 테스트. 출력을 std::ostringstream으로 받아 문자열로 비교한다
#include <catch2/catch.hpp>

#include <cstddef>
#include <optional>
#include <sstream>
#include <string>

#include "capture.hpp"
#include "decoder.hpp"
#include "logger.hpp"

namespace {

// sample.pcap(make_sample_pcap.py)을 재생했을 때 on_frame이 채우는 값
Stats sample_stats() {
    Stats stats;
    stats.frames = 18;
    stats.decoded = 12;
    stats.drops[static_cast<std::size_t>(DropReason::NotIpv4)] = 2;
    stats.drops[static_cast<std::size_t>(DropReason::NotTcp)] = 1;
    stats.drops[static_cast<std::size_t>(DropReason::NotConnectionAttempt)] = 3;
    stats.fw_logs = 2;
    stats.portscan_logs = 1;
    return stats;
}

const char* const kSampleStatsText =
    "[STATS] frames=18\n"
    "[STATS] decoded=12\n"
    "[STATS] drop.truncated_ethernet=0\n"
    "[STATS] drop.not_ipv4=2\n"
    "[STATS] drop.truncated_ipv4=0\n"
    "[STATS] drop.invalid_ipv4=0\n"
    "[STATS] drop.not_tcp=1\n"
    "[STATS] drop.ipv4_fragment=0\n"
    "[STATS] drop.truncated_tcp=0\n"
    "[STATS] drop.invalid_tcp=0\n"
    "[STATS] drop.not_connection_attempt=3\n"
    "[STATS] fw_logs=2\n"
    "[STATS] portscan_logs=1\n";

}  // namespace

TEST_CASE("파일 재생 통계에는 커널 수신·누락 수가 없다", "[logger]") {
    std::ostringstream out;
    Logger logger(out);

    logger.print_stats(sample_stats(), std::nullopt);

    CHECK(out.str() == kSampleStatsText);
}

TEST_CASE("실시간 캡처 통계에는 커널 수신·누락 수가 붙는다", "[logger]") {
    std::ostringstream out;
    Logger logger(out);

    logger.print_stats(sample_stats(), CaptureStats{20, 2});

    CHECK(out.str() == std::string(kSampleStatsText) +
                           "[STATS] kernel_received=20\n"
                           "[STATS] kernel_dropped=2\n");
}

TEST_CASE("모든 제외 사유가 한 줄씩 나온다", "[logger]") {
    std::ostringstream out;
    Logger logger(out);

    logger.print_stats(Stats{}, std::nullopt);

    const std::string text = out.str();
    for (std::size_t i = 0; i < kDropReasonCount; ++i) {
        const std::string line =
            std::string("[STATS] drop.") + to_string(static_cast<DropReason>(i)) + "=0\n";
        CHECK(text.find(line) != std::string::npos);
    }
}
