"""
cli/dashboard.py
Rich TUI live dashboard for attack monitoring.

Displays in real-time:
  - Attack metadata (module, target, params)
  - Live PPS and Mbps (rolling 2s window)
  - Session totals (packets, bytes, errors)
  - Elapsed time + ETA
  - Per-module specific metrics (sockets open for slowloris, rps for HTTP...)
  - Log file path

Requires: pip install rich
"""

import time
import threading
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.text import Text
    from rich import box
    from rich.progress import Progress, BarColumn, TimeRemainingColumn, SpinnerColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


def _fmt_bytes(b: int) -> str:
    """Human-readable bytes."""
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


def _fmt_bps(bps: float) -> str:
    """Human-readable bits per second."""
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if bps < 1000:
            return f"{bps:.2f} {unit}"
        bps /= 1000
    return f"{bps:.2f} Tbps"


def _bar(value: float, max_val: float, width: int = 20) -> str:
    """Simple ASCII progress bar."""
    if max_val <= 0:
        return "\\[" + " " * width + "]"
    filled = int((value / max_val) * width)
    filled = min(filled, width)
    return "\\[" + "#" * filled + "-" * (width - filled) + "]"


class Dashboard:
    """
    Live Rich dashboard. Call start() then attach an engine.
    Automatically updates every 0.5s.
    """

    def __init__(
        self,
        module: str,
        target: str,
        params: dict,
        duration: int = 0,
        log_path: str = "",
    ) -> None:
        if not RICH_AVAILABLE:
            raise ImportError("rich required: pip install rich")

        self.module = module
        self.target = target
        self.params = params
        self.duration = duration
        self.log_path = log_path
        self.engine = None
        self._live: Optional[Live] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._start_time = time.time()
        self._console = Console()

    def attach(self, engine) -> None:
        self.engine = engine

    def _build_layout(self) -> Panel:
        elapsed = time.time() - self._start_time
        eta = max(0, self.duration - elapsed) if self.duration > 0 else 0.0

        # --- Header ---
        header = Text()
        header.append("  Floodles  ", style="bold white on red")
        header.append(f"  {self.module}  ", style="bold yellow")
        header.append(f"  {self.target}  ", style="cyan")

        # --- Stats table ---
        stats = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        stats.add_column("Key", style="dim")
        stats.add_column("Value", style="bold")

        stats.add_row("Elapsed",  f"{elapsed:.1f}s" + (f"  /  {self.duration}s" if self.duration else ""))
        stats.add_row("ETA",      f"{eta:.1f}s" if self.duration else "manual stop")

        if self.engine and hasattr(self.engine, "metrics"):
            m = self.engine.metrics

            # Detect engine type by available attrs
            if hasattr(m, "packets_sent"):
                # Raw flood metrics
                s = m.summary()
                stats.add_row("Packets",    f"{s['packets']:,}")
                stats.add_row("Bytes",      _fmt_bytes(s['bytes']))
                stats.add_row("Errors",     str(s['errors']))
                stats.add_row("", "")
                stats.add_row("[bold]Live PPS[/bold]",  f"[green]{s['live_pps']:,.1f}[/green]")
                stats.add_row("[bold]Live BPS[/bold]",  f"[green]{_fmt_bps(s['live_mbps'] * 1_000_000)}[/green]")
                stats.add_row("Avg PPS",   f"{s['avg_pps']:,.1f}")
                stats.add_row("Avg BPS",   f"{_fmt_bps(s['avg_mbps'] * 1_000_000)}")

                # Mini bar (live pps vs avg)
                avg = s['avg_pps']
                live = s['live_pps']
                peak = max(avg, live, 1)
                stats.add_row("Rate",  _bar(live, peak * 1.2, 30))

            elif hasattr(m, "requests_sent"):
                # HTTP metrics
                s = m.summary()
                stats.add_row("Requests",   f"{s['requests']:,}")
                stats.add_row("2xx OK",     f"[green]{s['ok_2xx']:,}[/green]")
                stats.add_row("4xx/5xx",    f"[red]{s['err_4xx5xx']:,}[/red]")
                stats.add_row("Timeouts",   f"[yellow]{s['timeouts']:,}[/yellow]")
                stats.add_row("", "")
                stats.add_row("[bold]Avg RPS[/bold]",  f"[green]{s['avg_rps']:,.1f}[/green]")

            elif hasattr(m, "sockets_open"):
                # Slowloris metrics
                s = m.summary()
                stats.add_row("Sockets Open",    f"[green]{s['sockets_open']}[/green]")
                stats.add_row("Sockets Failed",  f"[red]{s['sockets_failed']}[/red]")
                stats.add_row("Expired",         str(s['sockets_expired']))
                stats.add_row("Keepalives Sent", f"{s['keepalives_sent']:,}")

        # --- Params panel ---
        param_text = Text()
        for k, v in self.params.items():
            param_text.append(f"  {k}: ", style="dim")
            param_text.append(f"{v}\n", style="white")

        if self.log_path:
            param_text.append(f"\n  log: ", style="dim")
            param_text.append(self.log_path, style="dim cyan")

        # Layout
        top = Columns([
            Panel(stats, title="[bold]Metrics[/bold]", border_style="red", width=50),
            Panel(param_text, title="[bold]Config[/bold]", border_style="dim", width=34),
        ])

        return Panel(
            top,
            title=header,
            border_style="bold red",
            subtitle="[dim]Ctrl+C to stop[/dim]",
        )

    def _refresh_loop(self) -> None:
        with Live(
            self._build_layout(),
            refresh_per_second=2,
            console=self._console,
        ) as live:
            self._live = live
            while not self._stop.is_set():
                live.update(self._build_layout())
                time.sleep(0.5)

    def start(self) -> None:
        self._start_time = time.time()
        self._thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)


class FallbackDisplay:
    """Plain-text fallback when rich is not installed."""

    def __init__(self, module: str, target: str, **_) -> None:
        self.module = module
        self.target = target
        self.engine = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def attach(self, engine) -> None:
        self.engine = engine

    def _loop(self) -> None:
        bars = ["|", "/", "-", "\\"]
        i = 0
        while not self._stop.is_set():
            time.sleep(1)
            i = (i + 1) % 4
            if self.engine and hasattr(self.engine, "metrics"):
                s = self.engine.metrics.summary()
                keys = list(s.items())
                row = "  ".join(f"{k}={v}" for k, v in keys[:6])
                print(f"\r{bars[i]}  {row}", end="", flush=True)
        print()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


def make_dashboard(module: str, target: str, params: dict,
                   duration: int = 0, log_path: str = ""):
    """Factory: returns Rich dashboard or plain fallback."""
    if RICH_AVAILABLE:
        return Dashboard(module, target, params, duration, log_path)
    return FallbackDisplay(module, target)
