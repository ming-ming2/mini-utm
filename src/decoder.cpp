#include "decoder.hpp"

const char* to_string(DropReason /*reason*/) {
    // TODO: default 없는 switch로 작성하면 새 DropReason이 빠졌을 때 -Wswitch가 경고한다
    return "";
}

DecodeResult Decoder::decode(const RawFrame& /*frame*/) const {
    // TODO: DESIGN 4장의 검사를 순서대로 수행
    return DropReason::TruncatedEthernet;
}
