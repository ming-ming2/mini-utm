#include "capture.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

// DESIGN 3장 실시간 캡처 설정값
constexpr int kSnaplen = 65535;
constexpr int kTimeoutMs = 100;
constexpr int kBufferSize = 64 * 1024 * 1024;

// 링크 계층이 이더넷이 아니면 std::runtime_error
void require_ethernet(pcap_t* handle, const std::string& source) {
    const int dlt = pcap_datalink(handle);
    if (dlt != DLT_EN10MB) {
        const char* name = pcap_datalink_val_to_name(dlt);
        throw std::runtime_error(source + ": unsupported link type " +
                                 (name != nullptr ? name : std::to_string(dlt)) +
                                 " (Ethernet required)");
    }
}

// "pcap_activate(eth0): <상태> (<상세>)" 형식. 상세 메시지가 비어 있으면 생략한다
std::string activate_message(pcap_t* handle, const std::string& interface, int status) {
    std::string message = "pcap_activate(" + interface + "): " + pcap_statustostr(status);
    const std::string detail = pcap_geterr(handle);
    if (!detail.empty()) {
        message += " (" + detail + ")";
    }
    return message;
}

}  // namespace

Capture::Capture(pcap_t* handle, bool live) : handle_(handle), live_(live) {}

Capture::~Capture() {
    if (handle_ != nullptr) {
        pcap_close(handle_);
    }
}

Capture::Capture(Capture&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)), live_(other.live_) {}

Capture& Capture::operator=(Capture&& other) noexcept {
    if (this != &other) {
        if (handle_ != nullptr) {
            pcap_close(handle_);
        }
        handle_ = std::exchange(other.handle_, nullptr);
        live_ = other.live_;
    }
    return *this;
}

Capture Capture::open_live(const std::string& interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_create(interface.c_str(), errbuf);
    if (handle == nullptr) {
        throw std::runtime_error("pcap_create(" + interface + "): " + errbuf);
    }
    // 이후 예외가 나면 capture의 소멸자가 핸들을 닫는다
    Capture capture(handle, true);

    // 활성화 전에만 실패하는 함수들이므로 반환값을 확인하지 않는다
    pcap_set_snaplen(handle, kSnaplen);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, kTimeoutMs);
    pcap_set_buffer_size(handle, kBufferSize);

    // 0은 성공, 양수는 경고(캡처는 동작한다), 음수는 실패
    const int status = pcap_activate(handle);
    if (status < 0) {
        throw std::runtime_error(activate_message(handle, interface, status));
    }
    // promiscuous 모드 미지원처럼 탐지 결과에 영향을 주는 경고가 있으므로 알린다
    if (status > 0) {
        std::cerr << "warning: " << activate_message(handle, interface, status) << '\n';
    }

    require_ethernet(handle, interface);
    return capture;
}

Capture Capture::open_offline(const std::string& path) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(path.c_str(), errbuf);
    if (handle == nullptr) {
        // errbuf에 경로가 이미 들어 있다
        throw std::runtime_error(std::string("pcap_open_offline: ") + errbuf);
    }
    Capture capture(handle, false);

    require_ethernet(handle, path);
    return capture;
}

int Capture::run(pcap_handler callback, u_char* user) {
    return pcap_loop(handle_, -1, callback, user);
}

std::optional<CaptureStats> Capture::stats() const {
    if (!live_) {
        return std::nullopt;
    }
    pcap_stat st{};
    if (pcap_stats(handle_, &st) != 0) {
        return std::nullopt;
    }
    return CaptureStats{st.ps_recv, st.ps_drop};
}

pcap_t* Capture::handle() const {
    return handle_;
}

RawFrame to_raw_frame(const pcap_pkthdr* header, const u_char* bytes) {
    const auto since_epoch =
        std::chrono::seconds{header->ts.tv_sec} + std::chrono::microseconds{header->ts.tv_usec};
    return RawFrame{
        TimePoint{std::chrono::duration_cast<Duration>(since_epoch)},
        std::span<const std::uint8_t>(bytes, header->caplen),
    };
}
