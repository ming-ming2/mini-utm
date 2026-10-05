#!/usr/bin/env python3
"""tests/data/sample.pcap 생성기.

테스트용 pcap을 실제 캡처가 아니라 직접 조립해서 만든다. 출처가 분명하고, 모든 기댓값을
이 파일만 보고 알 수 있다. 주소는 문서용 대역(RFC 5737: 198.51.100.0/24, 203.0.113.0/24)과
사설 대역(10.0.0.0/8)만 쓴다. 체크섬은 0으로 둔다(Mini UTM은 검증하지 않는다).

    python3 tests/data/make_sample_pcap.py      # 프로젝트 루트에서 실행

프레임 구성 (총 18개):
     1  SYN       198.51.100.7:51234 -> 10.1.1.55:8090    연결 시도 (Inbound)
     2  ARP       요청                                     not_ipv4
     3  SYN+ACK   10.1.1.55:8090 -> 198.51.100.7:51234    not_connection_attempt
     4  ACK       198.51.100.7:51234 -> 10.1.1.55:8090    not_connection_attempt
     5  UDP       10.1.1.20:53000 -> 8.8.8.8:53           not_tcp
     6  SYN       10.1.1.20:40112 -> 203.0.113.10:4444    연결 시도 (Outbound)
     7  IPv6      (헤더만)                                 not_ipv4
     8  RST+ACK   203.0.113.10:4444 -> 10.1.1.20:40112    not_connection_attempt
  9-18  SYN x10   203.0.113.9:60000 -> 10.1.1.55:20~29    연결 시도 (1초 안에 서로 다른 Port 10개 = 포트 스캔)

60바이트보다 짧은 프레임은 실제 이더넷처럼 0으로 패딩한다.
"""

import struct
from pathlib import Path

OUT = Path(__file__).with_name("sample.pcap")

MAC_A = bytes.fromhex("020000000001")  # 로컬 관리 주소(U/L 비트 1)
MAC_B = bytes.fromhex("020000000002")
BROADCAST = b"\xff" * 6

SYN, ACK, RST = 0x02, 0x10, 0x04
BASE_SEC = 1700000000  # 2023-11-14 22:13:20 UTC


def ip(addr):
    return bytes(int(x) for x in addr.split("."))


def ethernet(dst, src, ethertype, payload):
    frame = dst + src + struct.pack("!H", ethertype) + payload
    return frame.ljust(60, b"\x00")  # 최소 이더넷 프레임 길이(FCS 제외)까지 패딩


def ipv4(src, dst, protocol, payload):
    total_len = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 1, 0x4000, 64, protocol, 0,
                         ip(src), ip(dst))
    return header + payload


def tcp(sport, dport, flags):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 0xFFFF, 0, 0)


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp_frame(src, sport, dst, dport, flags):
    return ethernet(MAC_B, MAC_A, 0x0800, ipv4(src, dst, 6, tcp(sport, dport, flags)))


def arp_request():
    body = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, MAC_A, ip("10.1.1.20"),
                       b"\x00" * 6, ip("10.1.1.55"))
    return ethernet(BROADCAST, MAC_A, 0x0806, body)


def ipv6_header_only():
    header = struct.pack("!IHBB16s16s", 0x60000000, 0, 59, 64, b"\x00" * 15 + b"\x01",
                         b"\x00" * 15 + b"\x02")  # Next Header 59 = 내용 없음
    return ethernet(MAC_B, MAC_A, 0x86DD, header)


def frames():
    """(초, 마이크로초, 프레임) 목록"""
    out = [
        (0, 0, tcp_frame("198.51.100.7", 51234, "10.1.1.55", 8090, SYN)),
        (0, 100000, arp_request()),
        (0, 200000, tcp_frame("10.1.1.55", 8090, "198.51.100.7", 51234, SYN | ACK)),
        (0, 300000, tcp_frame("198.51.100.7", 51234, "10.1.1.55", 8090, ACK)),
        (1, 0, ethernet(MAC_B, MAC_A, 0x0800,
                        ipv4("10.1.1.20", "8.8.8.8", 17, udp(53000, 53, b"\x12\x34" + b"\x00" * 10)))),
        (1, 500000, tcp_frame("10.1.1.20", 40112, "203.0.113.10", 4444, SYN)),
        (2, 0, ipv6_header_only()),
        (2, 500000, tcp_frame("203.0.113.10", 4444, "10.1.1.20", 40112, RST | ACK)),
    ]
    for i in range(10):  # 0.1초 간격, 0.9초 동안 Port 20~29
        out.append((3, i * 100000, tcp_frame("203.0.113.9", 60000, "10.1.1.55", 20 + i, SYN)))
    return out


def main():
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # LINKTYPE_ETHERNET
    for sec, usec, frame in frames():
        data += struct.pack("<IIII", BASE_SEC + sec, usec, len(frame), len(frame)) + frame
    OUT.write_bytes(data)
    print(f"{OUT}: {len(frames())} frames, {len(data)} bytes")


if __name__ == "__main__":
    main()
