# CS 158A DNS Resolver

**Group 9** - Lu Tun, Matthew Gouyer

This is a DNS resolver written from scratch in Python 3. It starts at a root
server and follows referrals all the way down to the authoritative server
itself, so it never touches the OS resolver, getaddrinfo, or dnspython. The only
things we import are socket and struct.

Phase 1 follows [Implement DNS in a Weekend](https://implement-dns.wizardzines.com/)
by Julia Evans. The Phase 2 cache and the Phase 3 extensions are our own work.

## How to run it

```
python resolver.py example.com
```

That prints one IP per line. There are a few flags:

```
python resolver.py example.com --trace       # print every server we query
python resolver.py example.com --repeat 2    # run it twice so you can see the cache work
python resolver.py --selftest                # offline tests, no network needed
```

The selftest runs everything against a fake zone with a fake clock. That way we
can test TTL expiry without sitting around waiting 20 seconds, and we dont have
to hammer the real root servers every time we want to check something.

## Who did what

Matthew wrote the Phase 1 baseline, so the query building, the binary parser,
and the name compression handling, plus the first version of the cache. Lu
finished the cache so it actually reuses the delegations it learns, and wrote
both Phase 3 extensions and the test suite. The commit history has the details.

## Where the code is

Its all in resolver.py, with comment banners marking each section:

- Phase 1 runs from normalize_name down through parent_names
- Phase 2 is the DNSCache class plus the cache checks at the top of resolve()
- Phase 3 is parse_soa_rdata, get_cname, get_soa, get_glue_ips, the negative caching methods
  on DNSCache, and the CNAME and NXDOMAIN branches inside resolve()

## Phase 1

The resolver builds a query with the recursion-desired bit left at zero, since
were doing the walking ourselves and dont want the server doing it for us. It
sends that over UDP to a root server and parses whatever comes back. If theres
an A record in the answer section were done. If theres a glue record in the
additional section we jump straight to that IP. If we only get a nameserver name
with no glue, we have to go resolve that name first and then keep going.

Name compression is handled in decode_name. When it runs into a byte with the
top two bits set, it treats the next 14 bits as an offset into the message and
jumps there instead. It keeps a set of offsets its already been to, so if a
packet has a pointer aimed back at itself we raise an error instead of looping
forever.

One thing we changed from the guide is that resolve() returns a list of
addresses, not just one. A domain can have several A records and the assignment
asks for a test case with exactly that.

### Test cases

**1. A plain domain, compared against dig**

```
$ python resolver.py example.com
```
```
172.66.147.243
104.20.23.154
```
```
$ nslookup -type=A example.com
```
```
Server:  dns.google
Address:  8.8.8.8

Name:    example.com
Addresses:  172.66.147.243
          104.20.23.154
```
Same two addresses in both, so the parsing is right.

**2. The full walk, with tracing on**

```
$ python resolver.py example.com --trace
```
```
  querying 198.41.0.4 for example.com
  querying 192.41.162.30 for example.com
  querying 108.162.192.162 for example.com
172.66.147.243
104.20.23.154
(3 queries sent)
```

This should be three queries. One to the root at 198.41.0.4, one to a .com gTLD
server, and one to the authoritative server for example.com. Thats what
happened. Each hop came out of a referral in the previous response, so were
walking the tree and not shortcutting anywhere.

**3. A domain with more than one A record**

```
$ python resolver.py google.com
```
```
142.251.219.142
```
```
$ nslookup -type=A google.com
```
```
Server:  dns.google
Address:  8.8.8.8

Name:    google.com
Address:  142.251.219.142
```

**4. A subdomain**

```
$ python resolver.py www.iana.org
```
```
104.18.25.232
104.18.24.232
```
```
$ nslookup -type=A www.iana.org 8.8.8.8
```
```
Server:  dns.google
Address:  8.8.8.8

Name:    www.iana.org.cdn.cloudflare.net
Addresses:  104.18.24.232
          104.18.25.232
Aliases:  www.iana.org
```

Same two addresses. This one turned into a bonus CNAME test as well, since
nslookup shows www.iana.org is an alias for a Cloudflare CDN name and our
resolver followed it without us planning for that.

**5. A different TLD, to make sure nothing about .com is hardcoded**

```
$ python resolver.py sjsu.edu
```
```
130.65.218.11
```
```
$ nslookup -type=A sjsu.edu 8.8.8.8
```
```
Server:  dns.google
Address:  8.8.8.8

Name:    sjsu.edu
Address:  130.65.218.11
```

This one actually caught a bug for us, which is written up as extension 3 below.

**6. A domain that doesnt exist**

```
$ python resolver.py thisdomaindoesnotexist12345.com
```
```
NXDOMAIN: thisdomaindoesnotexist12345.com does not exist
```

The server sends back RCODE 3, so we raise NXDomainError and print a readable
message instead of dumping a traceback at you.

**7. A compression pointer loop**

This one is selftest 9. We hand decode_name a packet where the pointer at offset
12 points right back at offset 12, and it raises a ValueError instead of hanging.

```
$ python resolver.py --selftest
```
```
  [9] self-referencing compression pointer rejected
```

## Phase 2

The cache is keyed by (name, type) with the name lowercased first. DNS is case
insensitive so we didnt want Example.com and example.com ending up in two
different slots.

Every record we get back gets stored along with the time it expires, which is
just now plus the TTL off the record. When we look something up we drop anything
thats already past its expiry, and if nothing survives we delete the key
entirely. Records with a TTL of zero never get cached at all, since a zero TTL
means dont cache this (RFC 1035 §3.2.1, §4.1.3).

The part that took the most thinking was caching the NS and glue records instead
of only the final answers. best_nameserver starts at the full name and works up
toward the root, so for shop.example.com it checks shop.example.com, then
example.com, then com, then the root. At each level it looks for a cached NS
record, and then checks whether we also have a cached A record for that
nameservers name. The first zone where both of those are sitting there is the
deepest point we can jump into, so thats where we start instead of the root.

That last bit is what makes the third test below work. Without it wed have a
cache that stores NS records and then ignores them, and every lookup would still
walk down from the root, which kind of defeats the point.

### Test cases

All of these run under --selftest against a fake zone and a fake clock, so the
TTL timing is exact and it gives the same result every time. Real network
versions are underneath each one.

```
$ python resolver.py --selftest
```
```
  [1] baseline walk returns both A records in 3 queries
  [2] repeat lookup sent 0 new queries
  [3] after TTL expiry the resolver re-queried (1 queries)
  [4] shop.example.com skipped the root, 1 query(s), started at 203.0.113.53
```

**1. Looking up the same name twice**

Selftest 2. The first example.com lookup sends 3 packets. The second sends zero,
and the counter proves it, so we know that answer came out of the cache and not
off the wire.

On the real network:

```
$ python resolver.py example.com --repeat 2
```
```
--- lookup 1 ---
104.20.23.154
172.66.147.243
(3 queries sent)
--- lookup 2 ---
104.20.23.154
172.66.147.243
(0 queries sent)
```

3 queries then 0. Same addresses both times, and the second lookup never touched
the network.

**2. An entry getting re-fetched after its TTL runs out**

Selftest 3. The fake A records have a TTL of 20 seconds. We push the fake clock
forward 25 seconds and ask again, and the query counter goes up, so the expired
entry definitely wasnt served.

It only took 1 query the second time instead of 3, which surprised us at first.
It turns out thats because the A records expired but the NS and glue records had
a much longer TTL and were still good, so the resolver went straight to the
authoritative server. Thats the right behavior and its the same thing thats
happening in the next test.

**3. A different name in the same zone skipping the root and TLD**

Selftest 4. After resolving example.com we ask for shop.example.com. The test
checks that none of those queries went to 198.41.0.4, and the output shows it
started at 203.0.113.53, which is the authoritative server we already knew
about. One query instead of three.

On the real network:

```
$ python resolver.py example.com --trace
$ python resolver.py www.example.com --trace
```

These are two separate processes, so the cache starts empty both times and you
wont see the skip. The --repeat flag runs both lookups in one process,
which is where the cache does its job. Selftest 4 is the cleaner version of this
test anyway, since it can assert on which servers got queried.

## Phase 3

We ended up with three. The first two we planned, and the third one we only
found because a test case failed and we went digging.

### Extension 1: CNAME resolution

The gap is that the baseline only looks for an A record in the answer section.
When a server sends back a CNAME instead, the baseline finds no A record, no
glue, and no NS record, so it falls through to its error case and gives up. The
guide even shows this failing on www.facebook.com in its exercises.

RFC 1034 §3.6.2 says that when a name server runs into a CNAME and the query
type isnt CNAME, it should restart the query at the canonical name. RFC 1035
§3.3.1 has the record format.

Without this a lot of real hostnames just dont work, especially anything sitting
behind a CDN or a load balancer, since those are almost always aliases. Thats a
big chunk of the web that the baseline resolver cant reach at all.

The way we did it, resolve() checks for a direct answer first, then calls
get_cname to look for a CNAME whose owner name matches what we asked for. If it
finds one it calls itself with the canonical name and bumps a depth counter.
MAX_CNAME_DEPTH is 10, so a chain that loops back on itself raises an error
instead of recursing until Python gives up. We also check the cache for a CNAME
on the way in, so an alias weve already seen doesnt cost us a network query.

### Extension 2: Negative caching

The gap here is that our Phase 2 cache only stores answers that worked. A name
that doesnt exist gets no cache entry at all, so every single lookup for it
walks the whole hierarchy from the root again.

RFC 2308 §3 says NXDOMAIN responses should get cached. §5 has the caching rules
and §4 says the TTL to use is whichever is smaller, the SOA records own TTL or
the MINIMUM field inside its rdata.

Without it, typos and dead domains and misconfigured mail servers generate a
constant stream of queries for names that are never going to exist, and all of
that lands on the root and TLD servers. RFC 2308 §7 points out that a big share
of root server traffic is exactly this. Its slow for whoevers doing the lookup
too, since every failure pays for the full walk down from the root.

For the implementation, resolve() now reads the RCODE out of the header. If its
3 we pull the SOA out of the authority section, take min(soa_ttl, soa_minimum),
store a negative entry under (name, type), and raise NXDomainError. Next time
somebody asks for that name the negative check runs before anything else, so we
return right away without touching the network.

The SOA parsing was the annoying part. Its rdata starts with MNAME and RNAME,
which are both variable length names that can use compression pointers, so
theres no fixed offset you can just index to. parse_soa_rdata has to decode both
names to find out where they end, and only then can it unpack the five 32-bit
fields. MINIMUM is the last one.

### Extension 3: try every nameserver in a delegation

We only found this one because sjsu.edu failed while everything else worked.
Tracing it showed the resolver reaching an authoritative server and then giving
up, so we dumped the raw response and saw rcode 2, which is SERVFAIL.

The gap is that the baseline grabbed the first glue record out of the additional
section and treated it as the only nameserver. A zone almost always lists
several, and if the first one is down or refuses to talk to us then the whole
lookup dies even though the other servers would have answered fine.

RFC 1034 section 5.3.3 says a resolver should keep a list of servers for the
zone and work through it rather than depending on one. RFC 2308 section 7.1 also
says SERVFAIL should not be cached as a real answer, since it means the server
had a problem and not that the name is bad.

Without this, any domain whose first listed nameserver is unhealthy just fails,
which is what was happening to us with sjsu.edu. Two of its three
nameservers give us SERVFAIL and only the third answers.

For the fix, get_glue_ips now returns every A record from the additional section
instead of just the first one. The resolve loop keeps that whole list and walks
it, skipping any server that times out or comes back with SERVFAIL or REFUSED,
and only gives up once every one of them has failed.

### Test cases

```
$ python resolver.py --selftest
```
```
  [5] www.example.com followed its CNAME to the A records
  [6] NXDOMAIN cached, second lookup sent 0 queries (neg TTL 30s)
  [7] negative entry expired after 30s and was re-queried
  [8] SOA parser found MINIMUM=45 past both variable-length names
  [10] first nameserver returned SERVFAIL, fell back to the second
```

**CNAME, before and after**

Selftest 5. In the fake zone www.example.com has nothing but a CNAME pointing at
example.com. The baseline raises "could not resolve". With the extension it
follows the alias and comes back with both A records.

On the real network:

```
$ python resolver.py www.github.com --trace
```
```
  querying 198.41.0.4 for www.github.com
  querying 192.41.162.30 for www.github.com
  querying 205.251.193.165 for www.github.com
  www.github.com is a CNAME for github.com, restarting
  [cache hit] github.com -> ['20.29.134.23']
20.29.134.23
(3 queries sent)
```
```
$ nslookup -type=A www.github.com 8.8.8.8
```
```
Server:  dns.google
Address:  8.8.8.8

Name:    github.com
Address:  140.82.116.3
Aliases:  www.github.com
```

The trace shows it finding the CNAME, restarting on github.com, and then hitting
the cache, because the authoritative server had already handed us that A record
in the same response.

Worth noting the address we get back for github.com wont always match what
nslookup gives you. Both are real GitHub addresses. Big sites sit behind CDNs
and hand out different IPs depending on which authoritative server answers and
where the query came from, so an exact match isnt expected here. The CNAME
target being github.com is the part that matters, and that does match.

**CNAME loop protection**

We couldnt find a real domain with a circular CNAME to test against, which makes
sense since nobody wants their own zone broken. The guard is the _depth counter
in resolve(), which raises "CNAME chain too long" past 10 hops instead of
recursing until Python runs out of stack.

**Negative caching, before and after**

Selftests 6 and 7. The first lookup of the made up name walks the hierarchy and
gets NXDOMAIN back with an SOA carrying MINIMUM=30. The second lookup sends zero
packets. Then we push the fake clock 35 seconds past that TTL and the third
lookup goes back out to the network, which is what proves the entry expired
instead of sitting there forever.

On the real network:

```
$ python resolver.py thisdomaindoesnotexist12345.com --repeat 2
```
```
--- lookup 1 ---
NXDOMAIN: thisdomaindoesnotexist12345.com does not exist
(2 queries sent)
--- lookup 2 ---
NXDOMAIN: thisdomaindoesnotexist12345.com does not exist (cached)
(0 queries sent)
```

2 queries then 0, and the second message says cached, so that came out of the
negative cache instead of going back out to the .com servers.

**Nameserver failover, before and after**

Selftest 10 builds a fake zone where the first nameserver returns SERVFAIL and
the second one has the answer. The test checks we actually queried the broken
one and still came back with the right address, so we know the fallback ran and
it wasnt just getting lucky.

On the real network, sjsu.edu is a live example of this. Before the fix:

```
$ python resolver.py sjsu.edu --trace
  querying 198.41.0.4 for sjsu.edu
  querying 192.31.80.30 for sjsu.edu
  querying 128.114.100.100 for sjsu.edu
error: could not resolve sjsu.edu
```

After:

```
$ python resolver.py sjsu.edu --trace
```
```
  querying 198.41.0.4 for sjsu.edu
  querying 192.31.80.30 for sjsu.edu
  querying 128.114.100.100 for sjsu.edu
    128.114.100.100 returned rcode 2, trying the next one
  querying 128.114.100.200 for sjsu.edu
    128.114.100.200 returned rcode 2, trying the next one
  querying 130.65.9.11 for sjsu.edu
130.65.218.11
(5 queries sent)
```

Two of SJSUs nameservers hand us SERVFAIL and the third one answers with
130.65.218.11, which is the same address nslookup gives.

**SOA parsing**

Selftest 8 builds an SOA record by hand with MNAME "ns", RNAME "mail", and
MINIMUM 45, then checks the parser lands on 45. This is the test that would
catch us being off by a few bytes when skipping past the two names.

## Sources

- Julia Evans, Implement DNS in a Weekend, https://implement-dns.wizardzines.com/ for the Phase 1 baseline
- RFC 1034 §3.6.2 for CNAME resolution
- RFC 1035 §3.2.1, §3.3.1, §3.3.13, §4.1.2, §4.1.3, §4.1.4 for the record format, TTLs, SOA layout, name encoding, and compression
- RFC 2308 §3, §4, §5, §7 for negative caching and which TTL to use
