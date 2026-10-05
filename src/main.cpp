#include <csignal>
#include <cstddef>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>

#include <pcap/pcap.h>
#include <unistd.h>

#include "capture.hpp"
#include "config.hpp"
#include "decoder.hpp"
#include "firewall.hpp"
#include "logger.hpp"
#include "portscan.hpp"

using namespace std::chrono_literals;

namespace {

// 시그널 핸들러는 인자를 받을 수 없으므로 전역에 둔다 (SPEC 6.1)
pcap_t* g_handle = nullptr;

// on_frame이 사용할 객체들. 주소를 libpcap의 user 포인터로 전달한다 (SPEC 6.2)
struct Context {
    const Decoder& decoder;
    const FirewallPolicy& firewall;
    PortScanDetector& portscan;
    Logger& logger;
    Stats& stats;
};

struct Options {
    bool live = false;        // -i이면 true, -r이면 false
    std::string source;       // 인터페이스 이름 또는 pcap 파일 경로
    std::string config_file;  // -c
};

void print_usage(const char* prog) {
    std::cerr << "usage: " << prog << " -i <interface> -c <config_file>\n"
              << "       " << prog << " -r <pcap_file> -c <config_file>\n";
}

// -i와 -r 중 정확히 하나와 -c가 있어야 한다
std::optional<Options> parse_options(int argc, char* argv[]) {
    Options opts;
    bool has_i = false;
    bool has_r = false;
    bool has_c = false;

    int opt;
    while ((opt = getopt(argc, argv, "i:r:c:")) != -1) {
        switch (opt) {
        case 'i':
            opts.live = true;
            opts.source = optarg;
            has_i = true;
            break;
        case 'r':
            opts.live = false;
            opts.source = optarg;
            has_r = true;
            break;
        case 'c':
            opts.config_file = optarg;
            has_c = true;
            break;
        default:  // 알 수 없는 옵션, 옵션 값 누락
            return std::nullopt;
        }
    }

    if (has_i == has_r || !has_c || optind != argc) {
        return std::nullopt;
    }
    return opts;
}

// pcap_breakloop만 호출한다 (SPEC 6.5)
void on_signal(int /*signo*/) {
    pcap_breakloop(g_handle);
}

void set_signal_handler(void (*handler)(int)) {
    struct sigaction sa {};
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}

// libpcap이 프레임마다 호출한다. 예외가 밖으로 나가면 안 된다 (SPEC 6.4)
void on_frame(u_char* user, const pcap_pkthdr* header, const u_char* bytes) {
    auto& ctx = *reinterpret_cast<Context*>(user);
    ++ctx.stats.frames;

    const RawFrame frame = to_raw_frame(header, bytes);
    const DecodeResult result = ctx.decoder.decode(frame);
    if (const auto* reason = std::get_if<DropReason>(&result)) {
        ++ctx.stats.drops[static_cast<std::size_t>(*reason)];
        return;
    }
    const auto& packet = std::get<DecodedPacket>(result);
    ++ctx.stats.decoded;

    if (const auto verdict = ctx.firewall.evaluate(packet)) {
        ctx.logger.log_fw(packet, *verdict);
        ++ctx.stats.fw_logs;
    }
    if (const auto alert = ctx.portscan.observe(packet)) {
        ctx.logger.log_portscan(*alert);
        ++ctx.stats.portscan_logs;
    }
}

}  // namespace

// SPEC 6.3
int main(int argc, char* argv[]) {
    // 1. 인자 해석
    const auto opts = parse_options(argc, argv);
    if (!opts) {
        print_usage(argv[0]);
        return 1;
    }

    try {
        // 2. 설정 파일
        const Config config = load_config(opts->config_file);

        // 3. 캡처 초기화
        Capture capture = opts->live ? Capture::open_live(opts->source)
                                     : Capture::open_offline(opts->source);

        // 4. 객체 생성
        Decoder decoder;
        FirewallPolicy firewall(config);
        PortScanDetector portscan(1s, 10, 10s);
        Logger logger(std::cout);
        Stats stats;

        // 5. Context
        Context context{decoder, firewall, portscan, logger, stats};

        // 6. 시그널 핸들러 등록. g_handle을 먼저 설정한다
        g_handle = capture.handle();
        set_signal_handler(on_signal);

        // 7. 캡처 루프. 파일 끝 또는 종료 시그널까지 반환하지 않는다
        const int rc = capture.run(on_frame, reinterpret_cast<u_char*>(&context));

        // 8. 핸들러를 먼저 해제한 뒤 g_handle을 비운다
        set_signal_handler(SIG_DFL);
        g_handle = nullptr;

        // 9. 종료 통계
        logger.print_stats(stats, capture.stats());

        // 10. 종료 코드
        if (rc == PCAP_ERROR) {
            std::cerr << "capture error: " << pcap_geterr(capture.handle()) << '\n';
            return 1;
        }
        return 0;
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
