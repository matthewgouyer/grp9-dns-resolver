from __future__ import annotations

from dataclasses import dataclass
import random
import socket
import struct
import sys
from typing import Any, List, Optional, Sequence, Tuple


TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
CLASS_IN = 1
DEFAULT_ROOT_SERVERS = ("198.41.0.4",)
DEFAULT_TIMEOUT = 3.0


@dataclass(frozen=True)
class DNSHeader:
    id: int
    flags: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0


@dataclass(frozen=True)
class DNSQuestion:
    name: str
    type_: int
    class_: int


@dataclass(frozen=True)
class DNSRecord:
    name: str
    type_: int
    class_: int
    ttl: int
    data: Any


@dataclass(frozen=True)
class DNSPacket:
    header: DNSHeader
    questions: List[DNSQuestion]
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]


def normalize_name(name: str) -> str:
    name = name.strip()
    if name in {"", "."}:
        return ""
    return name[:-1].lower() if name.endswith(".") else name.lower()


def encode_dns_name(domain_name: str) -> bytes:
    normalized = normalize_name(domain_name)
    if not normalized:
        return b"\x00"
    encoded = bytearray()
    for part in normalized.split("."):
        label = part.encode("ascii")
        if len(label) > 63:
            raise ValueError(f"DNS label too long: {part!r}")
        encoded.append(len(label))
        encoded.extend(label)
    encoded.append(0)
    return bytes(encoded)


def header_to_bytes(header: DNSHeader) -> bytes:
    return struct.pack(
        "!HHHHHH",
        header.id,
        header.flags,
        header.num_questions,
        header.num_answers,
        header.num_authorities,
        header.num_additionals,
    )


def question_to_bytes(question: DNSQuestion) -> bytes:
    return encode_dns_name(question.name) + struct.pack("!HH", question.type_, question.class_)


def build_query(domain_name: str, record_type: int) -> bytes:
    header = DNSHeader(id=random.randint(0, 65535), flags=0, num_questions=1)
    question = DNSQuestion(name=normalize_name(domain_name), type_=record_type, class_=CLASS_IN)
    return header_to_bytes(header) + question_to_bytes(question)


def ip_to_string(raw_ip: bytes) -> str:
    if len(raw_ip) != 4:
        raise ValueError(f"IPv4 records must be 4 bytes, got {len(raw_ip)}")
    return ".".join(str(x) for x in raw_ip)


def decode_name(message: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    visited: set[int] = set()
    jumped = False
    next_offset = offset

    while True:
        if offset >= len(message):
            raise ValueError("DNS name extends past end of packet")

        length = message[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break

        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ValueError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            if pointer in visited:
                raise ValueError("DNS compression pointer loop detected")
            visited.add(pointer)
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            continue

        offset += 1
        label = message[offset : offset + length]
        if len(label) != length:
            raise ValueError("truncated DNS label")
        labels.append(label.decode("ascii"))
        offset += length
        if not jumped:
            next_offset = offset

    return ".".join(labels), next_offset


def parse_header(message: bytes, offset: int = 0) -> Tuple[DNSHeader, int]:
    if offset + 12 > len(message):
        raise ValueError("DNS header is truncated")
    return DNSHeader(*struct.unpack_from("!HHHHHH", message, offset)), offset + 12


def parse_question(message: bytes, offset: int) -> Tuple[DNSQuestion, int]:
    name, offset = decode_name(message, offset)
    if offset + 4 > len(message):
        raise ValueError("DNS question is truncated")
    type_, class_ = struct.unpack_from("!HH", message, offset)
    return DNSQuestion(name=name, type_=type_, class_=class_), offset + 4


def parse_record(message: bytes, offset: int) -> Tuple[DNSRecord, int]:
    name, offset = decode_name(message, offset)
    if offset + 10 > len(message):
        raise ValueError("DNS record header is truncated")
    type_, class_, ttl, data_len = struct.unpack_from("!HHIH", message, offset)
    rdata_offset = offset + 10
    rdata_end = rdata_offset + data_len
    if rdata_end > len(message):
        raise ValueError("DNS record data is truncated")
    if type_ == TYPE_A and data_len == 4:
        data: Any = ip_to_string(message[rdata_offset:rdata_end])
    elif type_ in {TYPE_NS, TYPE_CNAME}:
        data, _ = decode_name(message, rdata_offset)
    else:
        data = message[rdata_offset:rdata_end]
    return DNSRecord(name=name, type_=type_, class_=class_, ttl=ttl, data=data), rdata_end


def parse_dns_packet(message: bytes) -> DNSPacket:
    header, offset = parse_header(message)
    questions: List[DNSQuestion] = []
    for _ in range(header.num_questions):
        question, offset = parse_question(message, offset)
        questions.append(question)

    answers: List[DNSRecord] = []
    for _ in range(header.num_answers):
        record, offset = parse_record(message, offset)
        answers.append(record)

    authorities: List[DNSRecord] = []
    for _ in range(header.num_authorities):
        record, offset = parse_record(message, offset)
        authorities.append(record)

    additionals: List[DNSRecord] = []
    for _ in range(header.num_additionals):
        record, offset = parse_record(message, offset)
        additionals.append(record)

    return DNSPacket(header, questions, answers, authorities, additionals)


def send_query(server_ip: str, domain_name: str, record_type: int, timeout: float = DEFAULT_TIMEOUT) -> DNSPacket:
    query = build_query(domain_name, record_type)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server_ip, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return parse_dns_packet(data)


def get_answer(packet: DNSPacket) -> Optional[str]:
    for record in packet.answers:
        if record.type_ == TYPE_A:
            return record.data
    return None


def get_nameserver_ip(packet: DNSPacket) -> Optional[str]:
    for record in packet.additionals:
        if record.type_ == TYPE_A:
            return record.data
    return None


def get_nameserver(packet: DNSPacket) -> Optional[str]:
    for record in packet.authorities:
        if record.type_ == TYPE_NS:
            return record.data
    return None


def resolve(domain_name: str, record_type: int = TYPE_A, root_servers: Sequence[str] = DEFAULT_ROOT_SERVERS) -> str:
    if record_type != TYPE_A:
        raise NotImplementedError("Phase 1 resolver only supports A records")

    qname = normalize_name(domain_name)
    nameserver = root_servers[0]
    while True:
        response = send_query(nameserver, qname, record_type)
        answer = get_answer(response)
        if answer:
            return answer

        ns_ip = get_nameserver_ip(response)
        if ns_ip:
            nameserver = ns_ip
            continue

        ns_domain = get_nameserver(response)
        if ns_domain:
            nameserver = resolve(ns_domain, TYPE_A, root_servers=root_servers)
            continue

        raise LookupError(f"could not resolve {domain_name}")


def _selftest() -> None:
    encoded = encode_dns_name("www.example.com")
    decoded, next_offset = decode_name(encoded, 0)
    assert decoded == "www.example.com"
    assert next_offset == len(encoded)

    calls: List[Tuple[str, str, int]] = []

    def fake_send(server_ip: str, domain_name: str, record_type: int, timeout: float = DEFAULT_TIMEOUT) -> DNSPacket:
        calls.append((server_ip, domain_name, record_type))
        if server_ip == "198.41.0.4" and domain_name == "example.com":
            return DNSPacket(
                header=DNSHeader(1, 0, 1, 0, 1, 1),
                questions=[],
                answers=[],
                authorities=[DNSRecord("example.com", TYPE_NS, CLASS_IN, 300, "ns.example.net")],
                additionals=[DNSRecord("ns.example.net", TYPE_A, CLASS_IN, 300, "203.0.113.53")],
            )
        if server_ip == "203.0.113.53" and domain_name == "example.com":
            return DNSPacket(
                header=DNSHeader(2, 0, 1, 1, 0, 0),
                questions=[],
                answers=[DNSRecord("example.com", TYPE_A, CLASS_IN, 60, "93.184.216.34")],
                authorities=[],
                additionals=[],
            )
        raise AssertionError(f"unexpected query: {(server_ip, domain_name, record_type)}")

    global send_query
    original_send_query = send_query
    try:
        send_query = fake_send  # type: ignore[assignment]
        assert resolve("example.com") == "93.184.216.34"
        assert calls == [
            ("198.41.0.4", "example.com", TYPE_A),
            ("203.0.113.53", "example.com", TYPE_A),
        ]
    finally:
        send_query = original_send_query  # type: ignore[assignment]

    print("self-test passed")


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help"}:
        print("Usage: python main.py <domain> [--selftest]")
        return 0

    if args[0] == "--selftest":
        _selftest()
        return 0

    try:
        print(resolve(args[0]))
        return 0
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

