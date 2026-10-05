#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <unordered_map>
#include <utility>

#include "capture.hpp"
#include "decoder.hpp"

struct PortScanAlert {
    TimePoint timestamp;  // 보정하지 않은 원래 캡처 시각
    std::uint32_t src_ip = 0;
    std::uint32_t dst_ip = 0;
    std::size_t distinct_ports = 0;
    Duration window{};
};

class PortScanDetector {
public:
    PortScanDetector(Duration window, std::size_t threshold, Duration cleanup_interval);

    // 이번 패킷으로 스캔이 탐지되면 PortScanAlert
    std::optional<PortScanAlert> observe(const DecodedPacket& packet);

private:
    struct PairKey {
        std::uint32_t src_ip = 0;
        std::uint32_t dst_ip = 0;

        bool operator==(const PairKey&) const = default;
    };

    struct PairKeyHash {
        std::size_t operator()(const PairKey& key) const noexcept;
    };

    // DESIGN 5.2 자료구조
    struct PairState {
        std::deque<std::pair<TimePoint, std::uint16_t>> events;
        std::unordered_map<std::uint16_t, std::uint32_t> port_counts;
        bool alerted = false;
    };

    void expire(PairState& state, TimePoint t);
    void cleanup(TimePoint t);

    Duration window_;
    std::size_t threshold_;
    Duration cleanup_interval_;

    std::unordered_map<PairKey, PairState, PairKeyHash> states_;
    TimePoint last_timestamp_{};  // 시각 역행 보정용, 지금까지 처리한 가장 큰 캡처 시각
    TimePoint last_cleanup_{};
};
