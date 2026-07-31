"""
Phase 1 — Part 1 (incremental commit)

This version implements:
- DNS name encoding (labels)
- Building a DNS query packet (header + question)
- Sending the UDP query and returning the raw response bytes

This is intentionally minimal; parsing and resolution logic will be added
in later commits for Part 2 and Part 3.
"""

"""
Phase 1 — Part 2 (incremental commit)

This version expands Part 1 by adding parsing of DNS responses and
DNS name decompression (pointer handling). The resolver logic (walk
from root to authoritative) will be added in Part 3.
"""

from __future__ import annotations

import random
import socket
import struct
import sys
from typing import List, Tuple, Dict, Any


DEFAULT_ROOT_SERVERS = ("198.41.0.4",)
DEFAULT_TIMEOUT = 3.0


def normalize_name(name: str) -> str:
    name = name.strip()
    if name in {"", "."}:
        return ""
    return name[:-1].lower() if name.endswith(".") else name.lower()


def encode_dns_name(domain_name: str) -> bytes:
    normalized = normalize_name(domain_name)
    if not normalized:
        return b"\x00"
    out = bytearray()
    for label in normalized.split('.'):
        b = label.encode('ascii')
        if len(b) > 63:
            raise ValueError("DNS label too long")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def build_query(domain_name: str, qtype: int = 1) -> bytes:
    tid = random.randint(0, 0xFFFF)
    header = struct.pack('!HHHHHH', tid, 0, 1, 0, 0, 0)
    qname = encode_dns_name(domain_name)
    question = qname + struct.pack('!HH', qtype, 1)
    return header + question


def send_query_raw(server_ip: str, domain_name: str, qtype: int = 1, timeout: float = DEFAULT_TIMEOUT) -> bytes:
    query = build_query(domain_name, qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server_ip, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return data


def decode_name(message: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    visited = set()
    jumped = False
    next_offset = offset
    while True:
        if offset >= len(message):
            raise ValueError('truncated name')
        length = message[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ValueError('truncated pointer')
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            if pointer in visited:
                raise ValueError('pointer loop')
            visited.add(pointer)
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        label = message[offset:offset+length]
        if len(label) != length:
            raise ValueError('truncated label')
        labels.append(label.decode('ascii'))
        offset += length
        if not jumped:
            next_offset = offset
    return '.'.join(labels), next_offset


def parse_header(message: bytes) -> Tuple[Dict[str, int], int]:
    if len(message) < 12:
        raise ValueError('truncated header')
    id_, flags, qdcount, ancount, nscount, arcount = struct.unpack_from('!HHHHHH', message, 0)
    return ({'id': id_, 'flags': flags, 'qdcount': qdcount, 'ancount': ancount, 'nscount': nscount, 'arcount': arcount}, 12)


def parse_question(message: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    name, offset = decode_name(message, offset)
    if offset + 4 > len(message):
        raise ValueError('truncated question')
    qtype, qclass = struct.unpack_from('!HH', message, offset)
    return ({'name': name, 'type': qtype, 'class': qclass}, offset + 4)


def parse_record(message: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    name, offset = decode_name(message, offset)
    if offset + 10 > len(message):
        raise ValueError('truncated record')
    type_, class_, ttl, rdlen = struct.unpack_from('!HHIH', message, offset)
    rdata_offset = offset + 10
    rdata_end = rdata_offset + rdlen
    if rdata_end > len(message):
        raise ValueError('truncated rdata')
    if type_ == 1 and rdlen == 4:
        data = '.'.join(str(b) for b in message[rdata_offset:rdata_end])
    elif type_ in (2, 5):
        data, _ = decode_name(message, rdata_offset)
    else:
        data = message[rdata_offset:rdata_end]
    return ({'name': name, 'type': type_, 'class': class_, 'ttl': ttl, 'data': data}, rdata_end)


def parse_dns_packet(message: bytes) -> Dict[str, Any]:
    header, offset = parse_header(message)
    questions = []
    for _ in range(header['qdcount']):
        q, offset = parse_question(message, offset)
        questions.append(q)
    answers = []
    for _ in range(header['ancount']):
        r, offset = parse_record(message, offset)
        answers.append(r)
    authorities = []
    for _ in range(header['nscount']):
        r, offset = parse_record(message, offset)
        authorities.append(r)
    additionals = []
    for _ in range(header['arcount']):
        r, offset = parse_record(message, offset)
        additionals.append(r)
    return {'header': header, 'questions': questions, 'answers': answers, 'authorities': authorities, 'additionals': additionals}


def _selftest() -> None:
    # test encode/decode and a synthetic name compression case
    enc = encode_dns_name('www.example.com')
    name, off = decode_name(enc, 0)
    assert name == 'www.example.com' and off == len(enc)
    print('part2 self-test passed')


def main(argv: List[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ('-h', '--help'):
        print('Usage: python main.py <domain> [--send] [--selftest]')
        return 0
    if args[0] == '--selftest':
        _selftest()
        return 0
    domain = args[0]
    if '--send' in args:
        raw = send_query_raw(DEFAULT_ROOT_SERVERS[0], domain)
        parsed = parse_dns_packet(raw)
        print('parsed header:', parsed['header'])
        print('answers:', parsed['answers'])
        print('authorities:', parsed['authorities'])
        print('additionals:', parsed['additionals'])
    else:
        print(build_query(domain).hex())
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

