// =============================================================================
//  main_annotated.cpp — src/main.cpp 해설본 (빌드 대상 아님)
//
//  코드 줄은 src/main.cpp와 한 글자도 다르지 않다. 설명은 전부 "줄 전체 주석"으로만
//  덧붙였다. 원본이 바뀌면 이 파일은 낡은 해설이 되므로 날짜를 확인할 것. (2026-10-02 기준)
//
//  ┌──────────────────────────────────────────────────────────────────────────┐
//  │ 읽는 순서                                                                  │
//  │                                                                          │
//  │  ① main 전체 훑기          → 파일 아래쪽 "▶ ①"   큰 그림: 준비 → 루프 → 마무리 │
//  │  ② 인자 해석               → "▶ ②"  Options, print_usage, parse_options    │
//  │  ③ 객체 조립               → "▶ ③"  main 2~5단계 (Config, Capture, 일꾼들)   │
//  │  ④ Context                → "▶ ④"  on_frame에 넘길 가방                     │
//  │  ⑤ 시그널                  → "▶ ⑤"  g_handle, on_signal, set_signal_handler │
//  │  ⑥ 캡처 루프와 on_frame     → "▶ ⑥"  패킷 한 개가 처리되는 길                 │
//  │  ⑦ 마무리와 예외            → "▶ ⑦"  main 8~10단계, catch, 소멸 순서         │
//  │  ⑧ include와 using         → "▶ ⑧"  필요할 때 참고 (맨 위에 있지만 맨 나중에) │
//  │                                                                          │
//  │  "▶" 표시를 검색(Ctrl+F)해서 번호 순서대로 따라가면 된다.                    │
//  │  SPEC 6장의 단계 번호(1~10)는 main 안의 "// 1. 인자 해석" 같은 주석과 같다.   │
//  └──────────────────────────────────────────────────────────────────────────┘
// =============================================================================


// ▶ ⑧ include와 using ─────────────────────────────────────────────────────────
// #include는 그 파일의 내용을 이 자리에 "복사-붙여넣기"하라는 전처리기 명령이다.
//   <...>  : 시스템/표준 라이브러리 헤더. 컴파일러가 정해진 시스템 경로에서 찾는다.
//   "..."  : 우리 프로젝트 헤더. 먼저 이 파일과 같은 폴더(src/)에서 찾는다.
//
// <csignal>   sigaction, SIGINT, SIGTERM, SIG_DFL. C의 <signal.h>를 C++식으로 감싼 것.
//             앞에 c가 붙은 헤더(cstddef, cstdint ...)는 전부 "C 헤더의 C++판"이다.
// <cstddef>   std::size_t (배열 인덱스, 크기에 쓰는 부호 없는 정수 타입)
// <iostream>  std::cout(표준 출력), std::cerr(표준 에러)
// <optional>  std::optional, std::nullopt — "값이 있을 수도, 없을 수도 있음"을 표현
// <stdexcept> std::runtime_error — 초기화 실패를 알리는 예외 타입
// <string>    std::string
// <variant>   std::variant, std::get_if, std::get — "둘 중 하나"를 담는 타입
#include <csignal>
#include <cstddef>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>

// <pcap/pcap.h>  libpcap API: pcap_t, pcap_pkthdr, pcap_breakloop, PCAP_ERROR ...
// <unistd.h>     POSIX(리눅스/유닉스 공통) 헤더. 여기서는 getopt, optarg, optind 때문에 쓴다.
//                C++ 표준이 아니라 운영체제가 제공하는 헤더라서 윈도우에는 없다.
#include <pcap/pcap.h>
#include <unistd.h>

// main.cpp는 모든 컴포넌트를 조립하는 곳이라 우리 헤더를 전부 include한다.
// (SPEC 2.1 include 관계에서 main.cpp를 그림에서 생략한 이유)
#include "capture.hpp"
#include "config.hpp"
#include "decoder.hpp"
#include "firewall.hpp"
#include "logger.hpp"
#include "portscan.hpp"

// using namespace X; → X 안의 이름을 앞에 X:: 없이 쓰게 해 준다.
// std::chrono_literals 안에는 시간 리터럴 연산자가 들어 있어서, 이 줄이 있어야
// 아래 main에서 1s(1초), 10s(10초) 같은 표기를 쓸 수 있다. (100ms, 5min 등도 가능)
// "using namespace std;" 처럼 std 전체를 푸는 건 이름 충돌 위험 때문에 피하고,
// 이렇게 필요한 작은 namespace만 푸는 게 관례다.
using namespace std::chrono_literals;

// 이름 없는 namespace: 이 안의 모든 것은 "main.cpp 안에서만" 보인다.
// 다른 .cpp에 같은 이름(Options, on_frame ...)이 있어도 링크할 때 충돌하지 않는다.
// 아래 } // namespace 까지가 범위다.
namespace {

// ▶ ⑤ 시그널 (1/3) ─────────────────────────────────────────────────────────────
// pcap_t* : libpcap 캡처 핸들을 가리키는 포인터. pcap_t의 내부 구조는 libpcap만 안다.
// nullptr : "아무것도 가리키지 않음". C의 NULL 대신 C++11부터 쓰는 포인터 전용 값.
//
// 왜 전역인가: 시그널 핸들러는 운영체제가 on_signal(int) 모양으로만 불러 준다.
// on_frame의 user 포인터 같은 빈칸이 없어서, 핸들을 전달할 방법이 전역 변수뿐이다.
// 값은 main 6단계에서 채우고 8단계에서 다시 비운다.
// 시그널 핸들러는 인자를 받을 수 없으므로 전역에 둔다 (SPEC 6.1)
pcap_t* g_handle = nullptr;

// ▶ ④ Context ─────────────────────────────────────────────────────────────────
// on_frame에 넘길 "도구 위치를 모은 가방". 실물은 main의 지역 변수이고 여기엔 참조만 있다.
//
// T& (참조): 이미 있는 객체의 "별명". 복사가 아니라 원본을 그대로 가리킨다.
//   - 만들 때 반드시 무엇을 가리킬지 정해야 하고(초기화 필수), 나중에 바꿀 수 없다.
//   - 그래서 Context는 main 5단계에서 { ... }로 한 번에 다섯 개를 다 채워 만든다.
//
// const T& : 원본을 가리키되 "읽기만" 하겠다는 약속. 이 참조로는 원본을 고칠 수 없다.
//   - decoder : 상태가 없으니 읽기만 → const
//   - firewall: 정책 목록을 읽기만 → const
//   - portscan: observe가 내부 집계(states_)를 고친다 → const 아님
//   - logger  : 출력 스트림에 쓴다 → const 아님
//   - stats   : 개수를 올린다 → const 아님
// on_frame이 사용할 객체들. 주소를 libpcap의 user 포인터로 전달한다 (SPEC 6.2)
struct Context {
    const Decoder& decoder;
    const FirewallPolicy& firewall;
    PortScanDetector& portscan;
    Logger& logger;
    Stats& stats;
};

// ▶ ② 인자 해석 (1/3) ──────────────────────────────────────────────────────────
// 명령줄 인자를 해석한 결과를 담는 구조체.
// "= false" 같은 기본 멤버 초기화자: Options opts; 라고만 써도 live는 false로 시작한다.
// std::string은 따로 안 적어도 빈 문자열로 시작한다.
// -i와 -r은 둘 중 하나만 오므로 source 하나에 담고, 어느 쪽이었는지는 live로 구분한다.
struct Options {
    bool live = false;        // -i이면 true, -r이면 false
    std::string source;       // 인터페이스 이름 또는 pcap 파일 경로
    std::string config_file;  // -c
};

// ▶ ② 인자 해석 (2/3) ──────────────────────────────────────────────────────────
// 사용법을 표준 에러(stderr)로 출력한다. 결과물(로그)이 아니라 안내문이라서 cout이 아닌 cerr.
//
// const char* prog : C 스타일 문자열(문자 배열의 첫 주소). main의 argv[0](실행 파일 이름)을 받는다.
// std::cerr << A << B << C : <<는 왼쪽 스트림에 오른쪽 값을 차례로 흘려 넣는다.
//   << 한 번이 끝나면 다시 std::cerr를 돌려주기 때문에 이렇게 줄줄이 이어 쓸 수 있다.
//   세미콜론(;)이 나올 때까지가 한 문장이라, 두 줄에 걸쳐 써도 하나의 출력문이다.
void print_usage(const char* prog) {
    std::cerr << "usage: " << prog << " -i <interface> -c <config_file>\n"
              << "       " << prog << " -r <pcap_file> -c <config_file>\n";
}

// ▶ ② 인자 해석 (3/3) ──────────────────────────────────────────────────────────
// 반환 타입 std::optional<Options>: "Options가 들어 있거나, 비어 있거나".
//   - 인자가 올바르면 Options를 담아 돌려주고
//   - 틀리면 std::nullopt(빈 값)를 돌려준다. → main이 사용법을 출력하고 종료.
//   예외를 던지지 않고 "실패했음"을 반환값으로 알리는 방법이다.
//
// int argc      : 인자 개수. "./mini_utm -r a.pcap -c b.conf" 이면 5 (프로그램 이름 포함)
// char* argv[]  : 인자 문자열들의 배열. argv[0]="./mini_utm", argv[1]="-r", argv[2]="a.pcap" ...
// -i와 -r 중 정확히 하나와 -c가 있어야 한다
std::optional<Options> parse_options(int argc, char* argv[]) {
    Options opts;
    // 어떤 옵션이 나왔는지 기록해 두었다가, 루프가 끝난 뒤 조합이 올바른지 한 번에 검사한다.
    bool has_i = false;
    bool has_r = false;
    bool has_c = false;

    // getopt: POSIX 표준 옵션 해석 함수. 부를 때마다 옵션을 하나씩 꺼내 준다.
    //   "i:r:c:" : 허용하는 옵션 목록. 글자 뒤의 ':'는 "이 옵션은 값을 하나 받는다"는 뜻.
    //   반환값    : 찾은 옵션 글자('i','r','c'). 모르는 옵션이거나 값이 빠지면 '?'.
    //               더 이상 옵션이 없으면 -1.
    //   optarg   : (전역 변수) 방금 찾은 옵션의 값. 예: -r a.pcap 이면 "a.pcap"을 가리킨다.
    //   optind   : (전역 변수) 다음에 볼 argv의 위치. 루프가 끝나면 "옵션이 아닌 첫 인자" 위치.
    //   모르는 옵션일 때 getopt가 "invalid option -- 'x'"를 stderr에 직접 출력한다.
    //
    // (opt = getopt(...)) != -1 : 대입한 값을 바로 비교에 쓰는 관용구.
    //   "getopt 결과를 opt에 넣고, 그 값이 -1이 아닌 동안 반복"이라는 뜻. 괄호가 꼭 필요하다.
    int opt;
    while ((opt = getopt(argc, argv, "i:r:c:")) != -1) {
        switch (opt) {
        case 'i':
            opts.live = true;
            // optarg(const char*)를 std::string에 대입하면 문자열 내용이 "복사"된다.
            // 그래서 이후에 optarg가 다른 곳을 가리켜도 opts.source는 안전하다.
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

    // 조합 검사. 하나라도 걸리면 실패.
    //   has_i == has_r : 둘 다 true(-i와 -r 동시) 이거나 둘 다 false(둘 다 없음)일 때 참.
    //                    "정확히 하나만"을 한 번에 검사하는 짧은 표현(XOR의 반대).
    //   !has_c         : -c(설정 파일)가 없음
    //   optind != argc : 옵션 뒤에 남는 인자가 있음. 예: ./mini_utm -r a.pcap -c b.conf extra
    if (has_i == has_r || !has_c || optind != argc) {
        return std::nullopt;
    }
    // Options를 그대로 반환하면 std::optional<Options>로 자동 변환되어 "값이 든" 상태가 된다.
    return opts;
}

// ▶ ⑤ 시그널 (2/3) ─────────────────────────────────────────────────────────────
// Ctrl+C(SIGINT)나 kill(SIGTERM)을 받으면 운영체제가 호출하는 함수.
// 모양(void 반환, int 하나)은 운영체제가 정한 것이라 바꿀 수 없다.
//
// int /*signo*/ : 매개변수에 이름을 안 붙이면 "안 쓰는 인자"라고 컴파일러에게 알리는 셈이 되어
//                 unused parameter 경고가 나지 않는다. 주석으로 원래 이름만 남겨 둔 것.
//
// 하는 일은 pcap_breakloop 하나뿐: 돌고 있는 pcap_loop에게 "멈춰" 깃발을 세운다.
// 시그널 핸들러는 프로그램 실행 도중 아무 지점에나 끼어들어 실행되므로, 안에서 할 수 있는 일이
// 아주 제한적이다(DESIGN 2.3). 출력·정리는 pcap_loop가 반환된 뒤 main이 한다.
// pcap_breakloop만 호출한다 (SPEC 6.5)
void on_signal(int /*signo*/) {
    pcap_breakloop(g_handle);
}

// ▶ ⑤ 시그널 (3/3) ─────────────────────────────────────────────────────────────
// SIGINT와 SIGTERM이 왔을 때 무엇을 할지 운영체제에 등록하는 도우미.
// main에서 두 번 쓴다: 6단계 등록(on_signal), 8단계 해제(SIG_DFL).
//
// void (*handler)(int) : "함수 포인터" 타입. 읽는 법 → handler는 포인터(*)인데,
//                        int 하나를 받고 void를 돌려주는 "함수"를 가리킨다.
//                        그래서 on_signal(함수 이름)도, SIG_DFL(기본 동작을 뜻하는 특수 값)도 넘길 수 있다.
void set_signal_handler(void (*handler)(int)) {
    // struct sigaction sa {};
    //   - "struct"를 굳이 붙인 이유: C 라이브러리에 sigaction이라는 이름의 구조체와 함수가
    //     둘 다 있다. 구조체 쪽이라는 걸 밝히려고 struct를 붙인다.
    //   - {} : 모든 필드를 0으로 초기화. 안 쓰는 필드(sa_flags 등)에 쓰레기값이 들어가지 않게 한다.
    //          sa_flags = 0 이라서 SA_RESTART 같은 추가 동작은 켜지지 않는다.
    struct sigaction sa {};
    // 시그널이 오면 부를 함수
    sa.sa_handler = handler;
    // 핸들러가 실행되는 동안 "추가로 막아 둘 시그널" 목록을 비운다(= 따로 막지 않는다).
    sigemptyset(&sa.sa_mask);
    // 실제 등록. 세 번째 인자는 "이전 설정을 돌려받을 곳"인데 필요 없어서 nullptr.
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}

// ▶ ⑥ 캡처 루프와 on_frame ──────────────────────────────────────────────────────
// libpcap이 프레임 하나마다 한 번씩 호출하는 콜백. 우리 코드 어디에도 on_frame(...)을
// 직접 부르는 곳은 없다. main 7단계에서 capture.run에 "함수 이름"만 넘겼을 뿐이다.
//
// 매개변수 모양은 libpcap의 pcap_handler 타입으로 정해져 있다.
//   u_char* user              : main이 넘긴 &context가 그대로 돌아온 것 (u_char = unsigned char)
//   const pcap_pkthdr* header : 캡처 시각(ts), 캡처 길이(caplen), 원래 길이(len)
//   const u_char* bytes       : 프레임 바이트의 시작 주소. 이 함수가 반환되면 무효가 된다.
//
// 예외가 이 함수 밖으로 나가면 C 라이브러리(libpcap)를 거쳐 전파되어야 하는데, C는 예외를
// 모르므로 안전하지 않다. 그래서 여기서 부르는 메서드들은 예외를 던지지 않게 작성한다(SPEC 8장).
// libpcap이 프레임마다 호출한다. 예외가 밖으로 나가면 안 된다 (SPEC 6.4)
void on_frame(u_char* user, const pcap_pkthdr* header, const u_char* bytes) {
    // (1) user를 다시 Context로 되돌린다.
    //   reinterpret_cast<Context*>(user) : "이 주소를 Context를 가리키는 포인터로 읽어라".
    //       타입 검사 없이 비트 그대로 해석을 바꾸는 가장 강한 캐스트. 넣을 때 &context였으니 안전하다.
    //   * (역참조)                       : 포인터가 가리키는 실제 객체
    //   auto&                           : 타입은 컴파일러가 추론(Context), &이므로 복사하지 않고 별명으로 받는다.
    //   결과적으로 ctx는 main의 context 그 자체다. ctx.xxx 로 바로 쓸 수 있다(-> 대신 .).
    auto& ctx = *reinterpret_cast<Context*>(user);
    // (2) 받은 프레임 수. ++x는 "1 증가". 결과값을 안 쓰는 곳에서는 x++와 같다.
    ++ctx.stats.frames;

    // (3) libpcap 형식(header, bytes) → 우리 형식(RawFrame{timestamp, span})
    //   const : 만든 뒤에 이 함수 안에서 바꾸지 않겠다는 약속. 실수로 고치면 컴파일 에러가 난다.
    const RawFrame frame = to_raw_frame(header, bytes);
    // (4) 해석. DecodeResult = std::variant<DecodedPacket, DropReason>
    //   variant는 "둘 중 정확히 하나"를 담는 상자. 지금 무엇이 들어 있는지는 상자가 기억한다.
    const DecodeResult result = ctx.decoder.decode(frame);
    // (4-1) 들어 있는 게 DropReason인가?
    //   std::get_if<DropReason>(&result) : 상자의 "주소"를 넘기면,
    //       DropReason이 들어 있으면 그 값의 주소를, 아니면 nullptr를 돌려준다.
    //   if (const auto* reason = ...) : 조건 안에서 변수를 선언하는 문법.
    //       선언과 동시에 "nullptr가 아닌가"를 검사하고, reason은 이 if 블록 안에서만 존재한다.
    //   const auto* : 포인터(*)이고 가리키는 값은 읽기만(const). 타입은 const DropReason*로 추론.
    if (const auto* reason = std::get_if<DropReason>(&result)) {
        //   *reason                          : 포인터가 가리키는 DropReason 값
        //   static_cast<std::size_t>(...)    : enum class는 숫자로 자동 변환되지 않으므로 명시적으로 바꾼다.
        //                                      NotIpv4 → 1 처럼 enum의 순번이 배열 칸 번호가 된다.
        //   stats.drops[칸]++                 : 그 사유의 개수를 1 올린다. (배열 크기는 kDropReasonCount)
        ++ctx.stats.drops[static_cast<std::size_t>(*reason)];
        // 제외된 프레임은 여기서 끝. 방화벽/포트 스캔으로 가지 않는다.
        return;
    }
    // (4-2) 여기까지 왔으면 상자 안은 반드시 DecodedPacket이다.
    //   std::get<DecodedPacket>(result) : 그 값을 꺼낸다(참조로). 다른 타입이 들어 있으면 예외를 던지지만,
    //                                     바로 위에서 DropReason인 경우를 걸렀으므로 여기선 일어나지 않는다.
    //   const auto& : 복사하지 않고 result 안의 값을 읽기 전용 별명으로 받는다.
    //                 result가 이 함수 끝까지 살아 있으므로 별명도 안전하다.
    const auto& packet = std::get<DecodedPacket>(result);
    // (5) 해석에 성공한(= 연결 시도로 확정된) 패킷 수
    ++ctx.stats.decoded;

    // (6) 방화벽 판단
    //   evaluate는 std::optional<FwVerdict>를 돌려준다. (로그를 찍어야 하면 값, 아니면 빈 값)
    //   if (const auto verdict = ...) : optional은 조건식에서 "값이 들어 있으면 true"로 동작한다.
    //   *verdict : optional 안의 FwVerdict를 꺼낸다(값이 있을 때만 써야 한다).
    //   여기서는 auto&가 아니라 auto(값)로 받았다: evaluate가 새로 만든 임시 값을 돌려주므로
    //   그 값을 verdict라는 변수로 그대로 받아 두는 것이다.
    if (const auto verdict = ctx.firewall.evaluate(packet)) {
        ctx.logger.log_fw(packet, *verdict);
        ++ctx.stats.fw_logs;
    }
    // (7) 포트 스캔 집계. (6)과 독립이라 같은 패킷이 로그를 두 줄 남길 수도 있다.
    //   observe는 portscan의 내부 상태를 바꾸므로 Context에서 portscan만 const가 아니다.
    if (const auto alert = ctx.portscan.observe(packet)) {
        ctx.logger.log_portscan(*alert);
        ++ctx.stats.portscan_logs;
    }
    // 반환하면 libpcap이 다음 프레임을 기다렸다가 다시 on_frame을 부른다.
}

}  // namespace

// ▶ ① main 전체 훑기 ──────────────────────────────────────────────────────────
// 프로그램의 시작점. 큰 흐름은 세 덩어리다.
//   [준비]   1~6단계 : 인자 해석 → 설정 → 캡처 열기 → 일꾼 만들기 → 가방 싸기 → 시그널 등록
//   [루프]   7단계   : capture.run 안에서 pcap_loop가 프레임마다 on_frame을 부른다
//   [마무리] 8~10단계: 시그널 해제 → 통계 출력 → 종료 코드
// 처음 읽을 때는 각 단계의 주석("// 1. 인자 해석" 등)만 쭉 따라 내려가서 흐름을 잡고,
// 그다음 ② → ⑦ 순서로 세부를 읽는다.
//
// 반환값(int)은 프로그램의 종료 코드다. 0 = 성공, 1 = 실패. 셸에서 echo $?로 확인할 수 있다.
// SPEC 6.3
int main(int argc, char* argv[]) {
    // ▶ ② (이어서) 1단계 — 인자 해석 결과 받기
    //   const auto opts : 타입은 std::optional<Options>로 추론된다. 이후로 바꾸지 않으므로 const.
    //   !opts           : optional이 비어 있으면(nullopt) true → 인자가 틀렸다는 뜻.
    // 1. 인자 해석
    const auto opts = parse_options(argc, argv);
    if (!opts) {
        print_usage(argv[0]);
        return 1;
    }

    // ▶ ⑦ (먼저 구조만) try { ... } catch (...) { ... }
    //   try 블록 안에서 예외가 던져지면, 그 즉시 남은 코드를 건너뛰고 아래 catch로 간다.
    //   이 프로그램에서 예외를 던지는 곳은 load_config(2단계)와 Capture::open_*(3단계)이다.
    try {
        // ▶ ③ 객체 조립 ─────────────────────────────────────────────────────
        // 2단계: 설정 파일 읽기. 실패하면 std::runtime_error가 던져진다(줄 번호 포함).
        //   opts->config_file : optional 안의 Options의 멤버에 접근. 포인터처럼 ->를 쓴다.
        //   const Config      : 읽은 설정은 이후로 바꾸지 않는다.
        // 2. 설정 파일
        const Config config = load_config(opts->config_file);

        // 3단계: 캡처 열기
        //   조건 ? A : B (삼항 연산자) : live면 open_live, 아니면 open_offline의 결과를 쓴다.
        //   Capture::open_live(...) : 클래스 이름::함수 → static 멤버 함수 호출. 객체 없이 부른다.
        //                              생성자가 private이라 Capture는 이 두 함수로만 만들 수 있다.
        //   Capture는 복사가 금지(= delete)되어 있는데 이렇게 받을 수 있는 이유:
        //       함수가 돌려준 임시 객체로 변수를 바로 만드는 경우, C++17부터는 복사도 이동도 없이
        //       그 자리에 바로 만들어진다(guaranteed copy elision).
        //   이 시점에 pcap_t 핸들이 열리고, capture가 소멸할 때 자동으로 닫힌다(RAII).
        // 3. 캡처 초기화
        Capture capture = opts->live ? Capture::open_live(opts->source)
                                     : Capture::open_offline(opts->source);

        // 4단계: 일꾼들 만들기. 전부 main의 지역 변수 = main이 주인이다.
        //   Decoder decoder;                 기본 생성. 상태가 없는 클래스.
        //   FirewallPolicy firewall(config); config에서 home_nets, rules를 복사해 보관.
        //                                    생성자가 explicit이라 "firewall = config" 같은 암시적 변환은 막혀 있다.
        //   PortScanDetector portscan(1s, 10, 10s);
        //                                    1s, 10s는 ⑧의 chrono 리터럴. Duration 타입으로 자동 변환된다.
        //                                    순서대로 윈도우(1초), 임계값(10개), 상태 정리 주기(10초).
        //   Logger logger(std::cout);        출력 대상 스트림을 참조로 보관. 테스트에선 ostringstream을 넘긴다.
        //   Stats stats;                     모든 카운터가 0으로 시작(기본 멤버 초기화자).
        // 4. 객체 생성
        Decoder decoder;
        FirewallPolicy firewall(config);
        PortScanDetector portscan(1s, 10, 10s);
        Logger logger(std::cout);
        Stats stats;

        // ▶ ④ (이어서) 5단계 — 가방 싸기
        //   Context context{...} : 중괄호 초기화. 멤버 선언 순서대로 하나씩 채운다
        //                          (decoder → firewall → portscan → logger → stats).
        //   참조 멤버라서 이 순간 다섯 개가 모두 정해져야 하고, 이후로 바꿀 수 없다.
        // 5. Context
        Context context{decoder, firewall, portscan, logger, stats};

        // ▶ ⑤ (이어서) 6단계 — 시그널 등록
        //   순서가 중요: g_handle을 먼저 채워야 한다. 등록부터 하면, 그 사이에 Ctrl+C가 왔을 때
        //   on_signal이 pcap_breakloop(nullptr)를 부르게 된다.
        //   capture.handle() : Capture가 소유한 핸들의 주소를 빌려 온다(소유권은 여전히 capture).
        // 6. 시그널 핸들러 등록. g_handle을 먼저 설정한다
        g_handle = capture.handle();
        set_signal_handler(on_signal);

        // ▶ ⑥ (이어서) 7단계 — 캡처 루프
        //   여기서 프로그램이 "멈춰 있는" 것처럼 보인다. 실제로는:
        //       capture.run(...) → pcap_loop(handle_, -1, on_frame, &context)
        //                            ├ on_frame(&context, ...)  프레임 1
        //                            ├ on_frame(&context, ...)  프레임 2
        //                            └ ...  파일 끝(0) / Ctrl+C(PCAP_ERROR_BREAK) / 오류(PCAP_ERROR)
        //   on_frame        : 함수 이름만 쓰면 그 함수의 주소(함수 포인터)가 넘어간다. 호출이 아니다.
        //   &context        : context의 주소
        //   reinterpret_cast<u_char*>(...) : libpcap의 user 칸은 u_char* 모양이라 그 모양으로 바꿔서 넣는다.
        //                                    on_frame에서 다시 Context*로 되돌린다(▶ ⑥의 (1)).
        //   const int rc    : 루프가 끝난 이유. 10단계에서 쓴다.
        // 7. 캡처 루프. 파일 끝 또는 종료 시그널까지 반환하지 않는다
        const int rc = capture.run(on_frame, reinterpret_cast<u_char*>(&context));

        // ▶ ⑦ 마무리와 예외 ─────────────────────────────────────────────────
        // 8단계: 시그널 해제 → g_handle 비우기 (순서 중요)
        //   SIG_DFL : "기본 동작으로 되돌려라"는 특수 값. 이후 Ctrl+C는 프로그램을 바로 끝낸다.
        //   왜 필요한가: try 블록이 끝나면 capture가 소멸하면서 핸들이 닫힌다. 그 뒤에도 on_signal이
        //   등록돼 있으면, 그때 온 시그널이 이미 닫힌 핸들에 pcap_breakloop를 부르게 된다.
        //   핸들러를 먼저 떼어 내므로 on_signal이 nullptr인 g_handle을 보는 일은 없다.
        // 8. 핸들러를 먼저 해제한 뒤 g_handle을 비운다
        set_signal_handler(SIG_DFL);
        g_handle = nullptr;

        // 9단계: 종료 통계
        //   capture.stats() : std::optional<CaptureStats>. 실시간 캡처면 커널 수신·누락 수, 파일이면 빈 값.
        //   Logger는 비어 있으면 커널 통계 줄을 출력하지 않는다.
        // 9. 종료 통계
        logger.print_stats(stats, capture.stats());

        // 10단계: 종료 코드
        //   PCAP_ERROR(-1)    : 캡처 중 오류 → 이유를 pcap_geterr로 꺼내 출력하고 1
        //   0, PCAP_ERROR_BREAK(-2) : 파일 끝, Ctrl+C → 정상 종료 0
        //   '\n' : 줄바꿈 문자 하나. std::endl과 달리 버퍼를 강제로 비우지(flush) 않는다.
        //          (std::cerr는 원래 버퍼 없이 바로 출력되므로 차이가 없다.)
        // 10. 종료 코드
        if (rc == PCAP_ERROR) {
            std::cerr << "capture error: " << pcap_geterr(capture.handle()) << '\n';
            return 1;
        }
        // return을 만나면 함수를 떠나기 전에 try 블록의 지역 변수들이 "선언의 역순"으로 소멸한다.
        //   context → stats → logger → portscan → firewall → decoder → capture(여기서 pcap_close) → config
        //   먼저 만든 것이 나중에 사라지므로, context가 가리키던 객체들은 context보다 오래 살아 있다.
        return 0;
    // 예외를 받는 곳.
    //   const std::runtime_error& e : 예외 객체를 복사하지 않고 읽기 전용 참조로 받는다(관례).
    //   e.what() : 예외를 던질 때 넣은 메시지. 예: "pcap_open_offline: /nope.pcap: No such file ..."
    //   예외로 try를 빠져나올 때도, 그때까지 만들어진 지역 변수는 역순으로 소멸한다.
    //   예: 3단계에서 실패하면 config만 소멸하고, capture는 만들어진 적이 없으니 소멸할 것도 없다.
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
