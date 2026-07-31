"""
Phase 1 — Part 1 (incremental commit)

This version implements:
- DNS name encoding (labels)
- Building a DNS query packet (header + question)
- Sending the UDP query and returning the raw response bytes

This is intentionally minimal; parsing and resolution logic will be added
in later commits for Part 2 and Part 3.
"""

from __future__ import annotations

import random
import socket
import struct
import sys
from typing import List, Tuple


DEFAULT_ROOT_SERVERS = ("198.41.0.4",)
DEFAULT_TIMEOUT = 3.0


def normalize_name(name: str) -> str:
    name = name.strip()
    if name in {"", "."}:
        return ""
    return name[:-1].lower() if name.endswith(".") else name.lower()


def encode_dns_name(domain_name: str) -> bytes:
    """Encode a domain name into DNS wire format (length-prefixed labels).

    Example: "www.example.com" -> b"\x03www\x07example\x03com\x00"
    """
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
    """Build a minimal DNS query (no flags set, single question).

    Header (12 bytes) + question (encoded name + type + class)
    """
    # ID, flags, qdcount, ancount, nscount, arcount
    tid = random.randint(0, 0xFFFF)
    header = struct.pack('!HHHHHH', tid, 0, 1, 0, 0, 0)
    qname = encode_dns_name(domain_name)
    question = qname + struct.pack('!HH', qtype, 1)  # class IN
    return header + question


def send_query_raw(server_ip: str, domain_name: str, qtype: int = 1, timeout: float = DEFAULT_TIMEOUT) -> bytes:
    """Send the query and return raw response bytes (no parsing yet)."""
    query = build_query(domain_name, qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server_ip, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return data


def _selftest() -> None:
    # simple encoding check
    enc = encode_dns_name('www.example.com')
    assert enc.startswith(b'\x03www') and enc.endswith(b'\x03com\x00')
    q = build_query('example.com')
    assert len(q) > 12
    print('part1 self-test passed')


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
        print('sending query to root server (raw response bytes will be printed)')
        data = send_query_raw(DEFAULT_ROOT_SERVERS[0], domain)
        print('received', len(data), 'bytes')
        print(data[:200].hex())
    else:
        print(build_query(domain).hex())
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

