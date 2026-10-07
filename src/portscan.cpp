#include "portscan.hpp"

#include <algorithm>
#include <functional>

PortScanDetector::PortScanDetector(Duration window, std::size_t threshold,
                                   Duration cleanup_interval)
    : window_(window), threshold_(threshold), cleanup_interval_(cleanup_interval) {}

// SPEC 5.5 observe 처리 순서
std::optional<PortScanAlert> PortScanDetector::observe(const DecodedPacket& packet) {
    // 1. 시각 역행 보정. 윈도우 계산에는 줄어들지 않는 t를 쓴다 (DESIGN 5.2)
    const TimePoint t = std::max(packet.timestamp, last_timestamp_);
    last_timestamp_ = t;

    // 2. 상태 정리. 키를 지우므로 아래에서 PairState 참조를 얻기 전에 한다
    if (t - last_cleanup_ >= cleanup_interval_) {
        cleanup(t);
    }

    // 3. 슬라이딩 윈도우 (DESIGN 5.2 절차 1~4)
    PairState& state = states_[PairKey{packet.src_ip, packet.dst_ip}];
    expire(state, t);
    state.events.emplace_back(t, packet.dst_port);
    ++state.port_counts[packet.dst_port];

    const std::size_t distinct_ports = state.port_counts.size();
    if (distinct_ports < threshold_) {
        state.alerted = false;
        return std::nullopt;
    }
    // 하나의 스캔 동안 로그는 한 번만
    if (state.alerted) {
        return std::nullopt;
    }
    state.alerted = true;
    // 로그 시각은 보정하지 않은 원래 캡처 시각
    return PortScanAlert{packet.timestamp, packet.src_ip, packet.dst_ip, distinct_ports, window_};
}

// 두 IP를 64비트 하나의 앞뒤 절반에 이어 붙인다. 서로 다른 키는 서로 다른 값이 된다
std::size_t PortScanDetector::PairKeyHash::operator()(const PairKey& key) const noexcept {
    const std::uint64_t packed = (static_cast<std::uint64_t>(key.src_ip) << 32) | key.dst_ip;
    return std::hash<std::uint64_t>{}(packed);
}

// DESIGN 5.2 절차 1. 기록 시각이 정확히 t - window인 기록은 윈도우 안이므로 남긴다
void PortScanDetector::expire(PairState& state, TimePoint t) {
    const TimePoint cutoff = t - window_;
    while (!state.events.empty() && state.events.front().first < cutoff) {
        const auto it = state.port_counts.find(state.events.front().second);
        if (--it->second == 0) {
            state.port_counts.erase(it);
        }
        state.events.pop_front();
    }
}

// DESIGN 5.2 상태 정리. 기록이 모두 만료된 키를 지운다
void PortScanDetector::cleanup(TimePoint t) {
    for (auto it = states_.begin(); it != states_.end();) {
        expire(it->second, t);
        if (it->second.events.empty()) {
            it = states_.erase(it);
        } else {
            ++it;
        }
    }
    last_cleanup_ = t;
}
