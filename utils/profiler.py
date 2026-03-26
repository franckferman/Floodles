"""
utils/profiler.py
Pre-attack target profiler.

Runs fast recon before launching an attack:
  - TCP port scan (top N ports, connect scan, no root required)
  - ICMP reachability (raw ping if root, else TCP fallback)
  - HTTP banner grab (server header, response time)
  - NTP monlist probe (check if reflector is vulnerable)
  - Basic OS fingerprinting via TCP window size / TTL

Results guide optimal attack module selection.
"""

import socket
import struct
import time
import concurrent.futures
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Top ports to scan (trimmed from nmap top-1000)
# ---------------------------------------------------------------------------

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900,
    8080, 8443, 8888,
]


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    port: int
    open: bool
    banner: str = ""
    latency_ms: float = 0.0


@dataclass
class ProfileResult:
    target: str
    ip: str = ""
    reachable: bool = False
    icmp_latency_ms: float = 0.0
    ttl: int = 0
    os_guess: str = "unknown"
    open_ports: list[PortResult] = field(default_factory=list)
    http_banner: str = ""
    http_latency_ms: float = 0.0
    ntp_vulnerable: bool = False
    recommendations: list[str] = field(default_factory=list)

    def print_summary(self) -> None:
        """Print colored summary to stdout."""
        try:
            from rich.console import Console
            from rich.table import Table
            from rich import box
            console = Console()

            console.print(f"\n[bold cyan]Target Profile: {self.target}[/bold cyan]")
            console.print(f"  IP          : [yellow]{self.ip}[/yellow]")
            console.print(f"  Reachable   : {'[green]YES[/green]' if self.reachable else '[red]NO[/red]'}")
            console.print(f"  ICMP Latency: {self.icmp_latency_ms:.1f} ms")
            console.print(f"  TTL         : {self.ttl}  ->  OS guess: [magenta]{self.os_guess}[/magenta]")
            console.print(f"  HTTP Banner : [dim]{self.http_banner or 'N/A'}[/dim]")
            console.print(f"  NTP vuln    : {'[red]YES (monlist)[/red]' if self.ntp_vulnerable else '[green]No[/green]'}")

            t = Table(box=box.SIMPLE)
            t.add_column("Port", style="cyan")
            t.add_column("State", style="green")
            t.add_column("Latency")
            t.add_column("Banner", style="dim")
            for r in self.open_ports:
                t.add_row(str(r.port), "OPEN", f"{r.latency_ms:.1f}ms", r.banner[:60])
            console.print(t)

            if self.recommendations:
                console.print("[bold yellow]Recommended modules:[/bold yellow]")
                for rec in self.recommendations:
                    console.print(f"  [green]->[/green] {rec}")

        except ImportError:
            # Fallback plain output
            print(f"\nTarget: {self.target} ({self.ip})")
            print(f"  Reachable: {self.reachable}")
            print(f"  TTL: {self.ttl} -> {self.os_guess}")
            print(f"  Open ports: {[r.port for r in self.open_ports]}")
            print(f"  Recommendations: {self.recommendations}")


# ---------------------------------------------------------------------------
# Probe functions
# ---------------------------------------------------------------------------

def _resolve(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


def _tcp_probe(ip: str, port: int, timeout: float = 1.0) -> PortResult:
    """Non-root TCP connect scan."""
    t0 = time.perf_counter()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        latency = (time.perf_counter() - t0) * 1000

        # Try banner grab
        banner = ""
        try:
            s.settimeout(0.5)
            data = s.recv(256)
            banner = data.decode("utf-8", errors="replace").strip()[:80]
        except Exception:
            pass
        s.close()
        return PortResult(port=port, open=True, banner=banner, latency_ms=latency)
    except (socket.error, OSError):
        return PortResult(port=port, open=False)


def _icmp_ping(ip: str, timeout: float = 2.0) -> tuple[bool, float, int]:
    """
    ICMP echo request. Returns (reachable, latency_ms, ttl).
    Requires root. Falls back to TCP 80 probe if PermissionError.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(timeout)

        # Build ICMP echo
        icmp_type = 8
        code = 0
        checksum = 0
        identifier = 0xABCD
        seq = 1
        header = struct.pack("bbHHh", icmp_type, code, checksum, identifier, seq)
        payload = b"floodles_probe"
        checksum = _icmp_checksum(header + payload)
        header = struct.pack("bbHHh", icmp_type, code, checksum, identifier, seq)
        packet = header + payload

        t0 = time.perf_counter()
        s.sendto(packet, (ip, 0))
        data, addr = s.recvfrom(1024)
        latency = (time.perf_counter() - t0) * 1000

        # Extract TTL from IP header
        ttl = data[8] if len(data) >= 9 else 0
        return True, latency, ttl

    except PermissionError:
        # No root: try TCP 80
        r = _tcp_probe(ip, 80, timeout=timeout)
        return r.open, r.latency_ms, 64

    except (socket.error, OSError):
        return False, 0.0, 0


def _icmp_checksum(data: bytes) -> int:
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i]) + ((data[i+1]) << 8)
    if n:
        s += data[-1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _guess_os(ttl: int) -> str:
    """Rough OS guess from initial TTL."""
    if ttl <= 0:
        return "unknown"
    if ttl <= 64:
        return "Linux/Android"
    if ttl <= 128:
        return "Windows"
    if ttl <= 255:
        return "Cisco/BSD/macOS"
    return "unknown"


def _http_banner(ip: str, port: int = 80, https: bool = False, timeout: float = 3.0) -> tuple[str, float]:
    """Grab HTTP Server header and measure response time."""
    scheme = "https" if https else "http"
    url = f"{scheme}://{ip}:{port}/"
    t0 = time.perf_counter()
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx if https else None) as resp:
            latency = (time.perf_counter() - t0) * 1000
            server = resp.headers.get("Server", "")
            powered = resp.headers.get("X-Powered-By", "")
            banner = f"{server} {powered}".strip()
            return banner, latency
    except Exception:
        return "", 0.0


def _ntp_monlist_probe(ip: str, timeout: float = 2.0) -> bool:
    """Check if NTP server responds to monlist (mode 7, code 42)."""
    payload = bytes([0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00])
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(payload, (ip, 123))
        data, _ = s.recvfrom(4096)
        # Vulnerable if response > 8 bytes (actual data returned)
        return len(data) > 8
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main profiler
# ---------------------------------------------------------------------------

def profile(
    target: str,
    ports: Optional[list[int]] = None,
    port_workers: int = 50,
    timeout: float = 1.0,
    check_ntp: bool = False,
) -> ProfileResult:
    """
    Run full target profile.

    Args:
        target       : Hostname or IP.
        ports        : Port list. None = TOP_PORTS.
        port_workers : Thread count for port scan.
        timeout      : Per-probe timeout in seconds.
        check_ntp    : Also probe port 123 for NTP monlist vulnerability.

    Returns:
        ProfileResult with all findings and module recommendations.
    """
    if ports is None:
        ports = TOP_PORTS

    result = ProfileResult(target=target)
    result.ip = _resolve(target)

    # ICMP reachability + TTL
    reachable, latency, ttl = _icmp_ping(result.ip, timeout=timeout * 2)
    result.reachable = reachable
    result.icmp_latency_ms = latency
    result.ttl = ttl
    result.os_guess = _guess_os(ttl)

    if not reachable:
        result.recommendations.append("Target unreachable - verify IP and routing")
        return result

    # TCP port scan (parallel)
    with concurrent.futures.ThreadPoolExecutor(max_workers=port_workers) as ex:
        futures = {ex.submit(_tcp_probe, result.ip, p, timeout): p for p in ports}
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r.open:
                result.open_ports.append(r)

    result.open_ports.sort(key=lambda r: r.port)

    # HTTP banner
    open_port_nums = [r.port for r in result.open_ports]
    if 80 in open_port_nums:
        result.http_banner, result.http_latency_ms = _http_banner(result.ip, 80)
    elif 8080 in open_port_nums:
        result.http_banner, result.http_latency_ms = _http_banner(result.ip, 8080)
    elif 443 in open_port_nums:
        result.http_banner, result.http_latency_ms = _http_banner(result.ip, 443, https=True)

    # NTP probe
    if check_ntp or 123 in open_port_nums:
        result.ntp_vulnerable = _ntp_monlist_probe(result.ip, timeout=timeout)

    # --- Recommendations ---
    if 80 in open_port_nums or 8080 in open_port_nums or 443 in open_port_nums:
        result.recommendations.append("http_flood  (Layer 7, GET/POST flood)")
        result.recommendations.append("slowloris   (socket exhaustion)")

    if 53 in open_port_nums:
        result.recommendations.append("dns_amp     (DNS amplification, check recursion open)")

    if result.ntp_vulnerable:
        result.recommendations.append("ntp_amp     (NTP monlist, amplification factor ~550x)")

    result.recommendations.append("syn_flood   (always applicable on any TCP port)")

    if result.icmp_latency_ms < 10:
        result.recommendations.append("icmp_flood  (low latency = on same LAN, high impact)")

    return result
