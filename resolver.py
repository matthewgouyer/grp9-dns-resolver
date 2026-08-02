"""
CS 158A DNS Resolver
Group 9: Lu Tun, Matthew Gouyer

Phase 1 follows the "Implement DNS in a Weekend" guide by Julia Evans
(https://implement-dns.wizardzines.com/). The Phase 2 cache and the two
Phase 3 extensions are ours.

Run it like:
    python resolver.py example.com
    python resolver.py example.com --trace
    python resolver.py --selftest
"""

from __future__ import annotations

import random
import socket
import struct
import sys
import time
from typing import List, Tuple, Dict, Any, Callable, Sequence, Optional

# this is a.root-servers.net
DEFAULT_ROOT_SERVERS = ("198.41.0.4",)
DEFAULT_TIMEOUT = 3.0

TYPE_A = 1
TYPE_NS = 2

CLASS_IN = 1


# ---------------------------------------------------------------------------
# Phase 1: building the query
# ---------------------------------------------------------------------------

def normalize_name(name: str) -> str:
    # lowercase + drop trailing dot so cache keys line up
    name = name.strip()
    if name in {"", "."}:
        return ""
    return name[:-1].lower() if name.endswith(".") else name.lower()


def encode_dns_name(domain_name: str) -> bytes:
    # length-prefixed labels, zero byte at the end (RFC 1035 4.1.2)
    normalized = normalize_name(domain_name)
    if not normalized:
        return b"\x00"
    out = bytearray()
    for label in normalized.split("."):
        b = label.encode("ascii")
        if len(b) > 63:
            raise ValueError("DNS label too long")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def build_query(domain_name: str, qtype: int = TYPE_A) -> bytes:
    # RD bit stays 0, were doing the walking ourselves
    tid = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", tid, 0, 1, 0, 0, 0)
    question = encode_dns_name(domain_name) + struct.pack("!HH", qtype, CLASS_IN)
    return header + question


def send_query_raw(server_ip: str, domain_name: str, qtype: int = TYPE_A,
                   timeout: float = DEFAULT_TIMEOUT) -> bytes:
    query = build_query(domain_name, qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server_ip, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return data


# ---------------------------------------------------------------------------
# Phase 1: parsing the response
# ---------------------------------------------------------------------------

def decode_name(message: bytes, offset: int) -> Tuple[str, int]:
    # follows compression pointers (RFC 1035 4.1.4). visited stops a packet
    # whose pointer aims back at itself from looping us forever
    labels: List[str] = []
    visited = set()
    jumped = False
    next_offset = offset
    while True:
        if offset >= len(message):
            raise ValueError("truncated name")
        length = message[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ValueError("truncated pointer")
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            if pointer in visited:
                raise ValueError("pointer loop")
            visited.add(pointer)
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        label = message[offset:offset + length]
        if len(label) != length:
            raise ValueError("truncated label")
        labels.append(label.decode("ascii"))
        offset += length
        if not jumped:
            next_offset = offset
    return ".".join(labels), next_offset


def parse_header(message: bytes) -> Tuple[Dict[str, int], int]:
    if len(message) < 12:
        raise ValueError("truncated header")
    id_, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", message, 0)
    return ({"id": id_, "flags": flags, "qdcount": qd,
             "ancount": an, "nscount": ns, "arcount": ar}, 12)


def parse_question(message: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    name, offset = decode_name(message, offset)
    if offset + 4 > len(message):
        raise ValueError("truncated question")
    qtype, qclass = struct.unpack_from("!HH", message, offset)
    return ({"name": name, "type": qtype, "class": qclass}, offset + 4)


def parse_record(message: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    name, offset = decode_name(message, offset)
    if offset + 10 > len(message):
        raise ValueError("truncated record")
    type_, class_, ttl, rdlen = struct.unpack_from("!HHIH", message, offset)
    rdata_offset = offset + 10
    rdata_end = rdata_offset + rdlen
    if rdata_end > len(message):
        raise ValueError("truncated rdata")

    if type_ == TYPE_A and rdlen == 4:
        data: Any = ".".join(str(b) for b in message[rdata_offset:rdata_end])
    elif type_ == TYPE_NS:
        data, _ = decode_name(message, rdata_offset)
    else:
        data = message[rdata_offset:rdata_end]

    return ({"name": name, "type": type_, "class": class_, "ttl": ttl,
             "data": data}, rdata_end)


def parse_dns_packet(message: bytes) -> Dict[str, Any]:
    header, offset = parse_header(message)
    questions = []
    for _ in range(header["qdcount"]):
        q, offset = parse_question(message, offset)
        questions.append(q)
    answers = []
    for _ in range(header["ancount"]):
        r, offset = parse_record(message, offset)
        answers.append(r)
    authorities = []
    for _ in range(header["nscount"]):
        r, offset = parse_record(message, offset)
        authorities.append(r)
    additionals = []
    for _ in range(header["arcount"]):
        r, offset = parse_record(message, offset)
        additionals.append(r)
    return {"header": header, "questions": questions, "answers": answers,
            "authorities": authorities, "additionals": additionals}


# ---------------------------------------------------------------------------
# Phase 1: digging the useful bits out of a response
# ---------------------------------------------------------------------------

def get_answers(packet: Dict[str, Any], name: str, rtype: int) -> List[str]:
    # list, not one value, since a domain can have several A records
    target = normalize_name(name)
    return [r["data"] for r in packet["answers"]
            if r["type"] == rtype and normalize_name(r["name"]) == target]


def get_glue_ip(packet: Dict[str, Any]) -> Optional[str]:
    """Glue records are A records in the additional section that hand us a
    nameservers IP for free, so we dont have to go look it up separately."""
    for r in packet["additionals"]:
        if r["type"] == TYPE_A:
            return r["data"]
    return None


def get_ns_name(packet: Dict[str, Any]) -> Optional[str]:
    for r in packet["authorities"]:
        if r["type"] == TYPE_NS:
            return normalize_name(r["data"])
    return None


def parent_names(name: str) -> List[str]:
    # www.iana.org -> www.iana.org, iana.org, org, "" (root)
    name = normalize_name(name)
    out = [name] if name else []
    parts = name.split(".") if name else []
    for i in range(1, len(parts)):
        out.append(".".join(parts[i:]))
    out.append("")
    return out


# ---------------------------------------------------------------------------
# ==================== PHASE 2: CACHING (our own work) =====================
# ---------------------------------------------------------------------------

class DNSCache:
    """Cache keyed by (lowercased name, type) that pays attention to TTLs.

    It holds records from any section of a response, and drops them once
    their TTL is up (RFC 1035 sections 3.2.1 and 4.1.3).
    """

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._store: Dict[Tuple[str, int], List[Tuple[Dict[str, Any], float]]] = {}

    def _key(self, name: str, rtype: int) -> Tuple[str, int]:
        return (normalize_name(name), rtype)

    # --- positive caching ---

    def put_record(self, record: Dict[str, Any]) -> None:
        ttl = int(record.get("ttl", 0) or 0)
        if ttl <= 0:
            # a TTL of 0 means dont cache this at all
            return
        key = self._key(record["name"], record["type"])
        expiry = self._clock() + ttl
        bucket = self._store.setdefault(key, [])
        # if we already have this exact record, refresh it instead of adding a dupe
        for i, (rec, _) in enumerate(bucket):
            if rec["data"] == record["data"]:
                bucket[i] = (record, expiry)
                return
        bucket.append((record, expiry))

    def put_packet(self, packet: Dict[str, Any]) -> None:
        # keeping NS and glue is the whole reason a later lookup under the
        # same TLD can skip the root and TLD hops
        for section in ("answers", "authorities", "additionals"):
            for r in packet.get(section, []):
                if r["type"] in (TYPE_A, TYPE_NS):
                    try:
                        self.put_record(r)
                    except Exception:
                        continue

    def lookup(self, name: str, rtype: int) -> List[Dict[str, Any]]:
        key = self._key(name, rtype)
        entries = self._store.get(key)
        if not entries:
            return []
        now = self._clock()
        alive = [(rec, exp) for (rec, exp) in entries if exp > now]
        if not alive:
            del self._store[key]
            return []
        self._store[key] = alive
        return [rec for (rec, _) in alive]

    def lookup_data(self, name: str, rtype: int) -> List[Any]:
        return [r["data"] for r in self.lookup(name, rtype)]

    # --- delegation lookup, the part that saves round trips ---

    def best_nameserver(self, name: str) -> Tuple[Optional[str], str]:
        """Find the deepest zone we already have a nameserver IP for.

        We start at the full name and work up toward the root. At each zone we
        look for a cached NS record, then check if we also have a cached A
        record for that nameserver. The first zone where both are there is as
        far down as we can jump straight to.

        Gives back (nameserver_ip, zone), or (None, "") if we have nothing.
        """
        for zone in parent_names(name):
            for ns_name in self.lookup_data(zone, TYPE_NS):
                ips = self.lookup_data(ns_name, TYPE_A)
                if ips:
                    return ips[0], zone
        return None, ""


GLOBAL_CACHE = DNSCache()


class QueryCounter:
    # counts packets we put on the wire, so tests can prove a cache hit

    def __init__(self) -> None:
        self.count = 0
        self.log: List[Tuple[str, str, int]] = []

    def record(self, server: str, name: str, qtype: int) -> None:
        self.count += 1
        self.log.append((server, name, qtype))


# ---------------------------------------------------------------------------
# The resolver loop
# ---------------------------------------------------------------------------

def resolve(domain_name: str,
            qtype: int = TYPE_A,
            root_servers: Sequence[str] = DEFAULT_ROOT_SERVERS,
            send_parse_func: Optional[Callable[[str, str, int], Dict[str, Any]]] = None,
            cache: Optional[DNSCache] = None,
            counter: Optional[QueryCounter] = None,
            trace: bool = False,
) -> List[str]:
    """Walk the hierarchy and turn a name into a list of IPs.

    Its a list and not a single string because one name can have several A
    records.
    """
    cache = GLOBAL_CACHE if cache is None else cache

    if send_parse_func is None:
        def default_send_parse(srv: str, name: str, qt: int) -> Dict[str, Any]:
            return parse_dns_packet(send_query_raw(srv, name, qt))
        send_parse_func = default_send_parse

    qname = normalize_name(domain_name)

    # Phase 2: if we already have the answer, just hand it back
    cached = cache.lookup_data(qname, qtype)
    if cached:
        if trace:
            print(f"  [cache hit] {qname} -> {cached}")
        return cached

    # Phase 2: start as far down the tree as the cache lets us
    nameserver, zone = cache.best_nameserver(qname)
    if nameserver:
        if trace:
            label = zone if zone else "root"
            print(f"  [cache hit] starting at {nameserver} for zone '{label}'")
    else:
        nameserver = root_servers[0]

    while True:
        if trace:
            print(f"  querying {nameserver} for {qname}")
        if counter is not None:
            counter.record(nameserver, qname, qtype)

        packet = send_parse_func(nameserver, qname, qtype)
        cache.put_packet(packet)

        answers = get_answers(packet, qname, qtype)
        if answers:
            return answers

        glue = get_glue_ip(packet)
        if glue:
            nameserver = glue
            continue

        ns_name = get_ns_name(packet)
        if ns_name:
            # no glue this time, so we have to go resolve the nameservers name
            ns_ips = resolve(ns_name, TYPE_A, root_servers, send_parse_func,
                             cache, counter, trace)
            nameserver = ns_ips[0]
            continue

        raise LookupError(f"could not resolve {domain_name}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if not args or args[0] in ("-h", "--help"):
        print("Usage: python resolver.py <domain> [--trace]")
        print("       python resolver.py <domain> --repeat 2   (show cache behavior)")
        return 0

    domain = args[0]
    trace = "--trace" in args
    repeat = 1
    if "--repeat" in args:
        repeat = int(args[args.index("--repeat") + 1])

    for i in range(repeat):
        counter = QueryCounter()
        if repeat > 1:
            print(f"--- lookup {i + 1} ---")
        try:
            ips = resolve(domain, counter=counter, trace=trace)
            for ip in ips:
                print(ip)
        except (LookupError, socket.timeout, OSError) as e:
            print(f"error: {e}")
            return 1
        if trace or repeat > 1:
            print(f"({counter.count} queries sent)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
