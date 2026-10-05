// Capture 테스트. 프로젝트 루트(mini_dendrite/)에서 실행한다. 데이터 파일을 상대 경로로 연다.
#include <catch2/catch.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>

#include "capture.hpp"

namespace {

const char* const kSamplePcap = "tests/data/sample.pcap";   // 이더넷, 프레임 18개(각 60바이트), make_sample_pcap.py로 생성
const char* const kRawPcap = "tests/data/raw_linktype.pcap";    // 링크 형식 RAW, 프레임 없음

// 캡처 시각을 "1970-01-01부터의 마이크로초"로 바꾼다. 기댓값과 비교하기 쉽게 하려는 용도
std::int64_t to_micros(TimePoint t) {
    return std::chrono::duration_cast<std::chrono::microseconds>(t.time_since_epoch()).count();
}

// run()에 넘길 콜백이 프레임마다 결과를 쌓아 두는 곳. main의 Context와 같은 역할
struct Collected {
    std::size_t frames = 0;
    std::size_t total_bytes = 0;
    RawFrame first;
    RawFrame last;
    std::uint16_t first_ethertype = 0;
};

// libpcap이 프레임마다 부르는 콜백. main의 on_frame과 모양이 같다
void collect(u_char* user, const pcap_pkthdr* header, const u_char* bytes) {
    auto& out = *reinterpret_cast<Collected*>(user);
    const RawFrame frame = to_raw_frame(header, bytes);
    if (out.frames == 0) {
        out.first = frame;
        // span이 실제 프레임 바이트를 가리키는지 확인하려고, 콜백 안에서(바이트가 유효할 때) 읽어 둔다
        out.first_ethertype = static_cast<std::uint16_t>((frame.bytes[12] << 8) | frame.bytes[13]);
    }
    out.last = frame;
    ++out.frames;
    out.total_bytes += frame.bytes.size();
}

}  // namespace

TEST_CASE("파일을 처음부터 끝까지 읽는다", "[capture]") {
    // 준비
    Capture capture = Capture::open_offline(kSamplePcap);
    Collected out;

    // 실행
    const int rc = capture.run(collect, reinterpret_cast<u_char*>(&out));

    // 검증
    CHECK(rc == 0);  // 파일 끝까지 읽으면 0
    CHECK(out.frames == 18);
    CHECK(out.total_bytes == 18 * 60);
}

TEST_CASE("to_raw_frame은 캡처 시각과 바이트를 그대로 옮긴다", "[capture]") {
    Capture capture = Capture::open_offline(kSamplePcap);
    Collected out;
    capture.run(collect, reinterpret_cast<u_char*>(&out));

    // make_sample_pcap.py의 첫/마지막 프레임 시각 (1700000000.000000, 1700000003.900000)
    CHECK(to_micros(out.first.timestamp) == 1700000000000000);
    CHECK(to_micros(out.last.timestamp) == 1700000003900000);

    // span 크기 = caplen
    CHECK(out.first.bytes.size() == 60);  // 54바이트 SYN + 패딩 6바이트
    CHECK(out.last.bytes.size() == 60);

    // 첫 프레임의 EtherType 자리(12~13번 바이트)에 IPv4(0x0800)가 있다
    CHECK(out.first_ethertype == 0x0800);
}

TEST_CASE("to_raw_frame은 timeval을 TimePoint로 바꾼다", "[capture]") {
    // 파일 없이 pcap_pkthdr를 직접 만들어 함수 하나만 시험한다
    const u_char data[3] = {0xAA, 0xBB, 0xCC};
    pcap_pkthdr header{};
    header.ts.tv_sec = 1;
    header.ts.tv_usec = 500000;  // 1.5초
    header.caplen = 3;
    header.len = 3;

    const RawFrame frame = to_raw_frame(&header, data);

    CHECK(to_micros(frame.timestamp) == 1500000);
    CHECK(frame.bytes.size() == 3);
    CHECK(frame.bytes.data() == data);  // 복사하지 않고 원래 바이트를 가리킨다
}

TEST_CASE("파일 재생에서는 커널 통계가 없다", "[capture]") {
    Capture capture = Capture::open_offline(kSamplePcap);

    CHECK_FALSE(capture.stats().has_value());
}

TEST_CASE("열 수 없는 파일이면 runtime_error", "[capture][error]") {
    CHECK_THROWS_AS(Capture::open_offline("tests/data/no_such_file.pcap"), std::runtime_error);
    CHECK_THROWS_WITH(Capture::open_offline("tests/data/no_such_file.pcap"),
                      Catch::Contains("no_such_file.pcap"));
}

TEST_CASE("이더넷이 아닌 파일이면 runtime_error", "[capture][error]") {
    CHECK_THROWS_AS(Capture::open_offline(kRawPcap), std::runtime_error);
    CHECK_THROWS_WITH(Capture::open_offline(kRawPcap), Catch::Contains("unsupported link type RAW"));
}

TEST_CASE("없는 인터페이스면 runtime_error", "[capture][error]") {
    // 권한이 없으면 권한 에러, 있으면 No such device. 어느 쪽이든 runtime_error다
    CHECK_THROWS_AS(Capture::open_live("no_such_if0"), std::runtime_error);
}

TEST_CASE("이동하면 핸들의 주인이 바뀐다", "[capture][move]") {
    Capture a = Capture::open_offline(kSamplePcap);
    pcap_t* const handle = a.handle();
    REQUIRE(handle != nullptr);  // 이게 틀리면 아래 검사는 의미가 없으므로 여기서 멈춘다

    SECTION("이동 생성") {
        Capture b = std::move(a);

        CHECK(b.handle() == handle);
        CHECK(a.handle() == nullptr);  // 이동당한 쪽은 빈 증서
    }

    SECTION("이동 대입") {
        Capture c = Capture::open_offline(kSamplePcap);  // c는 원래 다른 핸들을 갖고 있다
        c = std::move(a);                                 // c의 원래 핸들은 닫히고 a의 것을 받는다

        CHECK(c.handle() == handle);
        CHECK(a.handle() == nullptr);
    }
    // 두 경우 모두 블록이 끝날 때 소멸자가 불린다. 핸들이 두 번 닫히면 여기서 프로그램이 죽는다
}
