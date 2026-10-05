#include "portscan.hpp"

PortScanDetector::PortScanDetector(Duration window, std::size_t threshold,
                                   Duration cleanup_interval)
    : window_(window), threshold_(threshold), cleanup_interval_(cleanup_interval) {}

std::optional<PortScanAlert> PortScanDetector::observe(const DecodedPacket& /*packet*/) {
    // TODO: SPEC 5.5 observe 처리 순서
    return std::nullopt;
}

std::size_t PortScanDetector::PairKeyHash::operator()(const PairKey& /*key*/) const noexcept {
    // TODO
    return 0;
}

void PortScanDetector::expire(PairState& /*state*/, TimePoint /*t*/) {
    // TODO: DESIGN 5.2 절차 1
}

void PortScanDetector::cleanup(TimePoint /*t*/) {
    // TODO
}
