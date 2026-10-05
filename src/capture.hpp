#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include <pcap/pcap.h>

using Clock = std::chrono::system_clock;
using TimePoint = Clock::time_point;
using Duration = Clock::duration;

// DESIGN 3장
struct RawFrame {
    TimePoint timestamp;
    std::span<const std::uint8_t> bytes;  // 크기가 캡처 길이. 콜백이 반환될 때까지만 유효하다
};

// pcap_stats의 ps_recv, ps_drop. 실시간 캡처에서만 생성된다
struct CaptureStats {
    std::uint32_t received = 0;
    std::uint32_t dropped = 0;
};

// libpcap 핸들을 소유한다(RAII). 복사는 금지하고 이동은 허용한다
class Capture {
public:
    static Capture open_live(const std::string& interface);
    static Capture open_offline(const std::string& path);

    ~Capture();
    Capture(const Capture&) = delete;
    Capture& operator=(const Capture&) = delete;
    Capture(Capture&& other) noexcept;
    Capture& operator=(Capture&& other) noexcept;

    // pcap_loop의 반환값: 파일 끝 0, pcap_breakloop PCAP_ERROR_BREAK, 오류 PCAP_ERROR
    int run(pcap_handler callback, u_char* user);
    std::optional<CaptureStats> stats() const;
    pcap_t* handle() const;

private:
    Capture(pcap_t* handle, bool live);

    pcap_t* handle_ = nullptr;
    bool live_ = false;
};

RawFrame to_raw_frame(const pcap_pkthdr* header, const u_char* bytes);
