"""
cli/man.py - Built-in manual pages for Floodles attack modules.

Usage:
    floodles man syn
    floodles man dns
    floodles man --list
"""

ATTACKS = {

    # =========================================================================
    # LAYER 3/4 — Network / Transport
    # =========================================================================

    "syn": {
        "title": "SYN Flood",
        "alias": "UFOSYN",
        "layer": "L4 - Transport (TCP)",
        "root": True,
        "amplification": None,
        "summary": "Half-open connection exhaustion via spoofed SYN packets.",
        "mechanism": """\
THE TCP THREE-WAY HANDSHAKE
  Client -> Server  SYN  (seq=X)
  Server -> Client  SYN-ACK  (seq=Y, ack=X+1)   <- server allocates state HERE
  Client -> Server  ACK  (ack=Y+1)               <- connection established

THE VULNERABILITY — STATEFUL ALLOCATION ON SYN
When the server receives a SYN it immediately allocates a TCB (Transmission
Control Block, ~280 bytes on Linux) and adds it to its SYN queue (backlog).
The kernel must wait for the matching ACK before promoting it to ESTABLISHED.

That wait window is the problem. By default:
  net.ipv4.tcp_max_syn_backlog  = 128 to 1024 (depends on distro)
  Half-open entry timeout       = net.ipv4.tcp_synack_retries * RTO
                                  typically ~75 seconds total

THE ATTACK CHAIN
  1. Attacker forges UDP-like SYN packets with random source IPs (spoofing).
  2. Server allocates a TCB and adds it to the SYN queue for each packet.
  3. The spoofed source IPs either do not exist or belong to third parties
     that will respond with RST — but most get dropped by the spoofed host's
     ingress filtering.
  4. No ACK ever arrives. Entries age out only after ~75 seconds.
  5. At sufficient PPS the backlog fills completely.
  6. New legitimate SYN packets receive ECONNREFUSED (closed) or are silently
     dropped — service is unavailable.

KERNEL RESOURCE MATH
  backlog = 512 entries  x  75 seconds timeout
  Attacker needs: 512 / 75 = ~7 SYN/sec to saturate a default backlog.
  In practice much higher PPS is sent to overcome retransmission jitter
  and to account for tcp_synack_retries reducing individual entry lifetime.

SYNCOOKIES — THE MITIGATION
  When tcp_syncookies = 1, the kernel does not allocate a TCB on SYN.
  Instead it encodes the connection parameters (IP, port, MSS, timestamp)
  into the SYN-ACK sequence number using a cryptographic hash.
  When the ACK arrives, the kernel verifies the cookie and only then
  allocates state. The backlog cannot fill because no state is allocated.
  Cost: TCP options like window scaling are lost on the first connection.""",
        "audit": """\
- Check sysctl net.ipv4.tcp_syncookies (must be 1 on exposed servers)
- Measure the actual saturation PPS:
    ss -s | grep SYN-RECV
  Observe at what PPS SYN-RECV count climbs to the backlog limit
- Test whether upstream scrubbing (Cloudflare, Arbor, F5 BIG-IP) absorbs
  the flood before the server sees it
- Verify IDS/IPS generates an alert (Snort: alert tcp any any -> any any
  (flags:S; threshold:type threshold,track by_dst,count 1000,seconds 1;))
- Test with and without syncookies to demonstrate impact difference""",
        "indicators": """\
ATTACK IN PROGRESS
  ss -s                           -> SYN-RECV count climbing
  netstat -s | grep "SYNs to"    -> "X SYNs to LISTEN sockets dropped" rising
  curl --connect-timeout 5 <target>  -> times out or ECONNREFUSED

PROTECTED (syncookies active)
  ss -s                           -> SYN-RECV stays near zero
  sysctl net.ipv4.tcp_syncookies  -> = 1""",
        "defenses": """\
net.ipv4.tcp_syncookies = 1        encode state in seq number, no TCB allocated
net.ipv4.tcp_max_syn_backlog       increase if syncookies cannot be enabled
net.ipv4.tcp_synack_retries = 2    reduce per-entry lifetime (default 5)
net.ipv4.tcp_abort_on_overflow = 1 RST instead of silently dropping
Upstream scrubbing center          Cloudflare Magic Transit, Arbor TMS, F5
BCP38 at ISP                       prevents raw spoofed packet injection""",
        "example": """\
# Progressive escalation — measure saturation point
sudo floodles syn <ip> 80 -t 4 --pps 5000 -d 30     # light probe
sudo floodles syn <ip> 80 -t 8 --pps 50000 -d 30    # medium
sudo floodles syn <ip> 80 -t 32 -d 60               # full load

# Monitor on target during attack (separate terminal)
watch -n1 'ss -s'
watch -n1 'netstat -s | grep -i syn'

# Before vs after syncookies
sysctl -w net.ipv4.tcp_syncookies=0   # disable, run attack -> saturates
sysctl -w net.ipv4.tcp_syncookies=1   # enable,  run attack -> no impact""",
    },

    "ack": {
        "title": "ACK Flood",
        "alias": "UFOACK",
        "layer": "L4 - Transport (TCP)",
        "root": True,
        "amplification": None,
        "summary": "Spoofed ACK packets that expose stateless firewalls and waste server CPU on RST generation.",
        "mechanism": """\
THE DESIGN FLAW — STATELESS VS STATEFUL FIREWALLS
A TCP ACK packet looks like mid-stream traffic. The firewall must decide
whether to pass it. The decision depends on its architecture:

STATEFUL firewall (nf_conntrack / pf / Windows Firewall):
  Maintains a connection table. An ACK arriving for no known connection
  is dropped at the firewall — the server never sees it.

STATELESS firewall (simple ACL: "allow inbound TCP dst-port 80"):
  Sees only the packet header. ACK on port 80 matches the rule. Packet
  forwarded to server.

THE ATTACK CHAIN (against stateless perimeter)
  1. Attacker sends ACK packets with random source IPs, dst port 80.
  2. Stateless firewall passes them — rule matches.
  3. Server receives ACK for a connection that does not exist.
  4. Server walks its TCP state table looking for a matching connection.
     No match found -> server generates RST to the (spoofed) source IP.
  5. At scale: server CPU consumed by state-table lookups and RST generation.
     Bandwidth consumed by bidirectional traffic (inbound ACK + outbound RST).

WHY THIS MATTERS FOR AUDITING
  The primary value is diagnosis, not volumetric damage.
  If the server generates RSTs -> perimeter is stateless (critical finding).
  If no RSTs are generated   -> perimeter is stateful (correct behavior).

  Secondary: even stateful systems can be overloaded if ACK rate exceeds
  conntrack table capacity or hash lookup speed.""",
        "audit": """\
- Send ACK flood and monitor for RST responses on the server side:
    tcpdump -i <iface> 'tcp[tcpflags] & tcp-rst != 0' -n
  RSTs visible -> stateless perimeter -> firewall is misconfigured
- Check iptables/nftables rules for -m state --state ESTABLISHED,RELATED
  Absence of this rule = stateless filtering for that chain
- Test IoT / embedded targets where each state lookup is disproportionately
  expensive relative to the device's CPU budget""",
        "indicators": """\
STATELESS PERIMETER (vulnerable)
  tcpdump on server -> RST packets generated in response to inbound ACKs
  iptables -n -v -L -> packet counters on ACCEPT rules climbing
  Server CPU shows iowait or softirq spike

STATEFUL PERIMETER (correct)
  No RSTs generated; packets dropped at firewall
  conntrack -L | wc -l  -> count stable, flood not creating new entries""",
        "defenses": """\
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  (drop anything not matching an existing connection)
nf_conntrack module loaded and tuned:
  net.netfilter.nf_conntrack_max        (default 65536, increase if needed)
  net.netfilter.nf_conntrack_tcp_timeout_established = 300
BGP RTBH (null route attacking source ranges if not spoofed)""",
        "example": """\
sudo floodles ack <ip> 80 -t 4 --pps 10000 -d 30

# On target: does it generate RSTs?
tcpdump -i eth0 'tcp[tcpflags] & tcp-rst != 0' -n -c 100

# Check conntrack
conntrack -L 2>/dev/null | wc -l
sysctl net.netfilter.nf_conntrack_count""",
    },

    "rst": {
        "title": "RST / FIN Flood",
        "alias": "UFORST",
        "layer": "L4 - Transport (TCP)",
        "root": True,
        "amplification": None,
        "summary": "Forged RST or FIN packets to terminate established TCP sessions.",
        "mechanism": """\
THE PROTOCOL RULE — RESET ACCEPTANCE
RFC 793 states: a RST is accepted and terminates a connection if the
sequence number falls within the current receive window.

Receive window on a typical connection: 64KB to 4MB (with window scaling).
32-bit sequence space: 2^32 = 4,294,967,296 possible values.

BLIND RST — PROBABILITY MATH
  With a 64KB receive window:
    hit probability per packet = 65536 / 4294967296 = ~0.0015%
    At 1,000,000 RST/sec -> ~15 connections terminated per second

  With a 4MB receive window (window scaling enabled):
    hit probability per packet = 4194304 / 4294967296 = ~0.1%
    At 1,000,000 RST/sec -> ~1000 connections terminated per second

TARGETED RST — WITH SEQUENCE SNIFFING
  If the attacker can sniff traffic (MITM, same L2 segment), they can read
  the actual sequence number and forge a perfectly targeted RST.
  Hit probability: 100%. One packet, one severed connection.
  Real-world use: BGP session teardown (CVE-2004-0230, "TCP Reset Attack").
  A BGP session uses seq numbers in a predictable range after establishment.

FIN VARIANT
  FIN triggers graceful shutdown (half-close). The peer sends FIN-ACK then
  enters FIN_WAIT state. Slower than RST but less noisy on some IDS.

WHAT CONNECTIONS ARE VULNERABLE
  Long-lived TCP sessions: SSH tunnels, database connections, BGP peers,
  replication streams, websocket connections. Short HTTP/HTTPS connections
  are recycled fast enough that RST impact is marginal.""",
        "audit": """\
- Test resilience of specific long-lived sessions:
    SSH: does the session drop? Is reconnect automatic?
    Database: does the connection pool recover?
    BGP: does the session drop and require manual reset?
- Check if TCP-MD5 signatures are configured on BGP sessions (RFC 2385)
  Without it, BGP is trivially disrupted from same subnet
- Verify PAWS (Protection Against Wrapped Sequences) is active:
    sysctl net.ipv4.tcp_timestamps  -> must be 1 for PAWS to work""",
        "indicators": """\
ss -t state ESTABLISHED | wc -l   -> count dropping unexpectedly
Application logs: "Connection reset by peer" / "Broken pipe"
BGP: neighbor session flapping in routing daemon logs
SSH: "packet_write_wait: Connection to <ip>: Broken pipe\"""",
        "defenses": """\
net.ipv4.tcp_rfc1337 = 1     ignore RSTs for TIME_WAIT connections
net.ipv4.tcp_timestamps = 1  enables PAWS (reduces valid sequence window)
TCP-MD5 signatures on BGP (RFC 2385): each segment carries HMAC-MD5
  router bgp 65000 / neighbor <x> password <secret>
  Forged RSTs without the MD5 key are silently dropped
Firewall: rate-limit RST per source IP (iptables --tcp-flags RST RST -m limit)""",
        "example": """\
# RST flood on SSH (test session resilience)
sudo floodles rst <ip> 22 --flag R -t 8 -d 30

# FIN flood on HTTP (graceful close test)
sudo floodles rst <ip> 80 --flag F -t 8 -d 30

# Combined RST+FIN
sudo floodles rst <ip> 80 --flag RF -t 8 -d 30

# Monitor on target
watch -n1 'ss -t state ESTABLISHED | wc -l'""",
    },

    "xmas": {
        "title": "XMAS Flood",
        "alias": "XMAS",
        "layer": "L4 - Transport (TCP)",
        "root": True,
        "amplification": None,
        "summary": "All TCP flags set simultaneously. Illegal per RFC 793. IDS detection + OS fingerprinting.",
        "mechanism": """\
THE PROTOCOL VIOLATION
The TCP Finite State Machine defines which flags are valid in each state.
A packet with FIN + SYN + RST + PSH + ACK + URG simultaneously is a
logical impossibility — no valid TCP state produces all flags at once.
RFC 793 does not define behavior for this combination.

PER-OS BEHAVIOR (port closed vs open)
  Linux:
    Closed port -> RST+ACK  (port rejection)
    Open port   -> silently ignored  (no response)
  Windows:
    Always RST+ACK regardless of port state
  BSD (FreeBSD, OpenBSD):
    Always RST  regardless of port state
  Older Cisco IOS / embedded stacks:
    Historically caused kernel panics or crashes (NULL pointer deref
    in TCP flag dispatch logic that never handled this combination)

TWO DISTINCT USES

  1. STEALTH PORT SCAN (nmap -sX)
     Open ports ignore the packet -> no RST in response.
     Closed ports respond RST.
     Inference: no RST = open port. No SYN ever sent = less log visibility.
     Limitation: only works correctly on Linux/BSD; Windows RSTs everything.

  2. IDS DETECTION TEST (flood mode)
     IDS/NIDS should fire on any packet with this flag combination.
     If it does not fire within N seconds -> IDS misconfigured or missing rule.
     Use as baseline: if Snort can't catch XMAS, it probably misses subtler attacks.

VOLUMETRIC COMPONENT
  At high PPS, forces the server to process and discard each malformed packet.
  On embedded targets with limited CPU, this creates a measurable processing load.""",
        "audit": """\
- Confirm IDS/NIPS triggers on XMAS packets:
    Snort: alert tcp any any -> any any (flags:SFRPAUEC; msg:"XMAS scan"; sid:1;)
    Suricata equivalent: flags: FUPRSA
  If no alert after 30s of flood -> rule is missing or IDS is misconfigured
- Test port scan use case: no SYN logged but port enumeration succeeds?
  Check /var/log/auth.log or web server access log for SYN entries
- Probe embedded/IoT targets for crash or instability under XMAS flood
- Verify stateful firewall drops XMAS (packet invalid per connection state)""",
        "indicators": """\
IDS fires within 5-10s    -> detection working correctly
No IDS alert after 60s    -> rule missing or sensor not seeing traffic
tcpdump on target:
  Linux closed port   -> RST+ACK in response to each XMAS
  Linux open port     -> silence (XMAS ignored)
Server crash or hang  -> unpatched embedded TCP stack""",
        "defenses": """\
IDS/IPS signature (Snort SID:1228 or equivalent)
Stateful firewall: XMAS does not match any valid connection state -> DROP
  iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
Modern Linux kernels (2.6+): handle XMAS safely (RST or ignore)
Network device ACL: drop packets with illegal flag combinations at ingress""",
        "example": """\
# IDS detection test
sudo floodles xmas <ip> 80 -t 4 -d 30

# Check if IDS fired (from monitoring system)
tail -f /var/log/snort/alert | grep -i xmas

# Port scan mode (slower, per-port response analysis)
sudo floodles xmas <ip> 80 -t 1 --pps 10 -d 10
# Compare with: nmap -sX <ip> -p 1-1024""",
    },

    "udp": {
        "title": "UDP Flood",
        "alias": "UFOUDP",
        "layer": "L3/L4 - Network / Transport (UDP)",
        "root": True,
        "amplification": None,
        "summary": "Connectionless UDP flood. Saturates bandwidth or CPU via forced ICMP Port Unreachable generation.",
        "mechanism": """\
WHY UDP IS TRIVIALLY SPOOFABLE
TCP requires a 3-way handshake — the source IP must receive the SYN-ACK
to complete it. UDP has no handshake. A UDP packet with a forged source IP
is indistinguishable from a legitimate one at the receiver. The receiver
cannot challenge the sender.

THE KERNEL COST OF RECEIVING UDP ON CLOSED PORTS
When a UDP packet arrives on a port with no listening socket:
  1. Kernel receives packet, copies it to socket buffer
  2. Kernel looks up the port in the socket table -> not found
  3. Kernel generates ICMP Port Unreachable (type 3, code 3) to the source IP
  4. ICMP packet is built, routed, and sent

With a spoofed source: ICMP goes to a random third-party IP.
With a real source: bidirectional traffic (inbound UDP + outbound ICMP).

ICMP rate limiting:
  net.ipv4.icmp_ratelimit (default: 1000 ms between ICMP messages to same dest)
  This limits outbound ICMP generation but does NOT reduce inbound UDP processing.
  The kernel still processes each UDP packet and attempts ICMP generation.

TWO ATTACK STRATEGIES

  Small packets (64 bytes): maximize packet-per-second count.
    Target: kernel interrupt processing, NIC RX queue exhaustion, CPU softirq.
    Effective against devices with low PPS capacity (routers, firewalls).

  Large packets (~1400 bytes, near MTU): maximize bytes per second.
    Target: uplink bandwidth saturation.
    Effective against servers with limited uplink (1G, 10G).

TARGETED PORT FLOODING
  UDP on port 53 -> hits DNS resolver (must parse query before rejecting)
  UDP on port 123 -> hits NTP daemon
  UDP on port 161 -> hits SNMP agent
  Each service pays additional application-layer parse cost before the
  packet is identified as invalid.""",
        "audit": """\
- Establish baseline: what is the target's uplink capacity?
    iperf3 -u -b 1G -> measure max legitimate UDP throughput
- Identify ICMP rate limiting configuration:
    sysctl net.ipv4.icmp_ratelimit
- Flood and measure: at what PPS does CPU softirq > 70%?
    mpstat -P ALL 1 (watch %soft column)
- Test specific ports (53, 123, 161) for additional application-layer overhead
- Check if QoS/traffic shaping de-prioritizes or drops UDP above threshold""",
        "indicators": """\
iftop / nethogs     -> bandwidth climbing to uplink capacity
/proc/net/snmp      -> UdpInErrors count increasing (kernel dropping excess)
mpstat              -> %soft climbing (kernel interrupt overload)
tcpdump             -> ICMP Port Unreachable flood visible if spoofing disabled
sar -n UDP 1        -> UdpInDatagrams per second""",
        "defenses": """\
BCP38 at ISP (ingress source address validation, RFC 2827)
  Prevents spoofed UDP from being injected into the internet
Rate-limit ICMP generation:
  net.ipv4.icmp_ratelimit = 1000  (already default, reduce to 100 if needed)
QoS policer: drop UDP traffic exceeding N Mbps at perimeter
iptables rate limit per source:
  -A INPUT -p udp -m limit --limit 1000/s --limit-burst 2000 -j ACCEPT
  -A INPUT -p udp -j DROP
BGP RTBH: null route attacking source subnets (if not spoofed)""",
        "example": """\
# PPS saturation test (small packets)
sudo floodles udp <ip> -s 64 -t 16 -d 60

# Bandwidth saturation test (large packets)
sudo floodles udp <ip> -s 1400 -t 8 -d 60

# Target DNS resolver specifically
sudo floodles udp <ip> -p 53 -s 512 -t 8 -d 30

# Monitor on target
mpstat -P ALL 1          # CPU per-core, watch %soft
sar -n UDP 1             # UDP stats per second
cat /proc/net/snmp | grep Udp""",
    },

    "icmp": {
        "title": "ICMP Flood",
        "alias": "PINGER",
        "layer": "L3 - Network (ICMP)",
        "root": True,
        "amplification": None,
        "summary": "ICMP echo request flood. Forces kernel to generate equal-size replies. 2x bandwidth consumption.",
        "mechanism": """\
THE PROTOCOL OBLIGATION
RFC 792 mandates that a host respond to ICMP echo request (type 8) with
an ICMP echo reply (type 0) of identical size. This is a kernel-level
obligation — userspace has no say. The kernel must:
  1. Process each incoming ICMP echo request
  2. Build and send an ICMP echo reply of the same payload size
  3. Route the reply to the source IP

THE 2x BANDWIDTH PROBLEM
If attacker sends 500 Mbps of ICMP echo requests:
  Inbound  : 500 Mbps (attacker to target)
  Outbound : 500 Mbps (target's replies to spoofed source IPs)
  Total    : 1 Gbps consumed from the target's uplink

With IP spoofing (random source IPs):
  Replies go to third parties (distributed collateral traffic)
  Target's uplink is still consumed for outbound reply generation

Without spoofing (real source IP):
  All replies return to attacker
  Both ends consume their uplink symmetrically

PACKET SIZE IMPACT
  56-byte payload (default ping): maximizes PPS, tests kernel interrupt capacity
  1400-byte payload (near MTU):   maximizes bandwidth per packet

FIREWALL EXCEPTION EXPOSURE
Many production systems have firewall rules permitting ICMP unrestricted
(for monitoring, path MTU discovery). This makes ICMP a valid flood vector
even when other protocols are rate-limited.""",
        "audit": """\
- Check if ICMP is rate-limited at the perimeter:
    iptables -n -v -L INPUT | grep icmp
    Absence of --limit rule -> ICMP accepted without rate limiting
- Measure round-trip latency degradation during flood:
    ping <target> -i 0.1 -f   (flood ping from second source during test)
    RTT increase = processing load
- Test if path MTU discovery is needed (some VPNs require ICMP type 3 code 4)
    Blocking all ICMP breaks PMTUD -> trade-off to document
- Verify router/switch CPU under ICMP flood (management plane attack vector)""",
        "indicators": """\
ping <target>          -> RTT increasing or packet loss during flood
iftop                  -> bandwidth climbing to uplink capacity
/proc/net/snmp         -> IcmpInMsgs, IcmpOutMsgs both climbing
tcpdump                -> ICMP echo request storm visible
System load            -> softirq CPU usage climbing (mpstat)""",
        "defenses": """\
Rate-limit ICMP at perimeter:
  iptables -A INPUT -p icmp --icmp-type echo-request \
    -m limit --limit 10/s --limit-burst 20 -j ACCEPT
  iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

Block ICMP entirely (trade-off: breaks path MTU discovery):
  iptables -A INPUT -p icmp -j DROP
  Note: keep ICMP type 3 (unreachable) for PMTUD

net.ipv4.icmp_echo_ignore_all = 1  (disable all echo responses)
Upstream scrubbing (Cloudflare, Arbor) absorbs ICMP before the link""",
        "example": """\
# Standard payload — PPS focus
sudo floodles icmp <ip> -s 56 -t 8 -d 30

# Near-MTU — bandwidth focus
sudo floodles icmp <ip> -s 1400 -t 16 -d 60

# Monitor during attack (separate terminal on target)
watch -n1 'cat /proc/net/snmp | grep Icmp'
mpstat -P ALL 1""",
    },

    "tachyon": {
        "title": "SYN-ACK Flood",
        "alias": "TACHYON",
        "layer": "L4 - Transport (TCP)",
        "root": True,
        "amplification": None,
        "summary": "Forged or reflected SYN-ACK packets. Forces RST generation. Bypasses SYN-only firewall filters.",
        "mechanism": """\
WHERE SYN-ACK APPEARS IN THE HANDSHAKE
  Client -> Server  SYN
  Server -> Client  SYN-ACK    <- this is what we forge
  Client -> Server  ACK

THE DIRECT ATTACK
  Attacker sends SYN-ACK packets with forged source IPs to the target.
  Target receives a SYN-ACK but has no pending SYN for that connection.
  Per RFC 793: target must send RST to reject the unexpected SYN-ACK.
  Cost per packet on the target:
    - TCP state table lookup (expensive hash lookup)
    - RST packet built and sent (CPU + bandwidth)
  This is MORE expensive per-packet than SYN processing.

  Firewall bypass: some firewalls only filter SYN floods (flags:S).
  SYN-ACK (flags:SA) matches different rules and may pass unfiltered.

THE REFLECTED ATTACK
  Attacker spoofs the victim's IP as source and sends SYN packets to
  many legitimate servers (reflectors) on port 80/443.
  Each reflector responds with a legitimate SYN-ACK to the victim.
  The victim receives SYN-ACK traffic from thousands of real IP addresses.

  Why this is harder to block:
    - Traffic comes from legitimate server IP addresses (not spoofed junk)
    - Blocking individual source IPs blocks access to legitimate servers
    - No amplification factor, but the traffic is indistinguishable from
      legitimate SYN-ACK responses

  Amplification factor: 1x (SYN and SYN-ACK are similar size)
  But each reflector consumes resources for the half-open connection.""",
        "audit": """\
- Test if perimeter drops unexpected SYN-ACK (stateful inspection):
    Send direct SYN-ACK flood -> RSTs visible on server = stateless perimeter
- Test reflected mode to verify BCP38 at upstream ISP:
    If reflectors can be reached with spoofed source -> ISP does not filter
- Measure RST generation overhead on server under direct flood""",
        "indicators": """\
DIRECT MODE
  tcpdump on target -> SYN-ACK flood arriving, server generating RSTs
  netstat -s | grep "bad" -> TCP bad segments increasing

REFLECTED MODE
  tcpdump -> SYN-ACK traffic from many different legitimate IPs
  ss -s -> TIME_WAIT connections accumulating (server sending RSTs)""",
        "defenses": """\
Stateful firewall (conntrack):
  Drops unexpected SYN-ACK because no matching SYN in conntrack table
  nf_conntrack handles this automatically when --state ESTABLISHED,RELATED is used
BCP38 at ISP level:
  Prevents attacker from injecting SYN packets with spoofed victim IP
  Without BCP38 the reflected mode is always possible
SYN cookies on reflectors:
  Reduces half-open state allocated by reflectors""",
        "example": """\
# Direct mode
sudo floodles tachyon <ip> --port 80 --mode direct -t 8 -d 30

# Reflected mode (uses legit servers as reflectors)
sudo floodles tachyon <ip> --mode reflected -r 1.2.3.4,5.6.7.8 -d 30

# Check RST generation on target
tcpdump -i eth0 'tcp[tcpflags] & tcp-rst != 0' -n -c 200""",
    },

    "frag": {
        "title": "IP Fragmentation Flood",
        "alias": "DROPER",
        "layer": "L3 - Network (IP)",
        "root": True,
        "amplification": None,
        "summary": "Exhausts kernel IP reassembly buffer by sending fragment trains without completing them.",
        "mechanism": """\
IP FRAGMENTATION BACKGROUND
When a packet exceeds the MTU (typically 1500 bytes on Ethernet), it is
split into fragments. Each fragment carries:
  - Original IP header with same identification field (16-bit)
  - Fragment offset (indicating where in the original packet this piece belongs)
  - More Fragments flag (MF=1 on all fragments except the last)

The receiving kernel must buffer all fragments and wait for the final one
(MF=0) before it can reassemble and process the complete packet.

THE REASSEMBLY BUFFER
  net.ipv4.ipfrag_high_thresh  = default 4MB  (max buffer before pruning)
  net.ipv4.ipfrag_low_thresh   = default 3MB  (prune target)
  net.ipv4.ipfrag_time         = default 30s  (per-fragment-train timeout)

THE ATTACK — INCOMPLETE FRAGMENTS
  Attacker sends the first fragment (or multiple middle fragments) but
  never sends the final fragment (MF=0). Each incomplete train occupies:
    - Buffer space proportional to fragments received
    - A timer entry (30 seconds before timeout)

  At sufficient rate: the reassembly buffer fills.
  Impact: the kernel drops ALL new fragments — including legitimate ones.
  Services broken: VPN tunnels (IPsec), large DNS responses, NFS, some HTTPS.

VARIANT — LAST FRAGMENT ONLY
  Sends only the last fragment (fragment offset > 0, MF=0).
  The kernel allocates a reassembly entry waiting for earlier fragments.
  Maximizes reassembly table entries per byte of traffic sent
  because no actual data is buffered, only the entry itself.

WHO IS AFFECTED
  The kernel fragmentation handler runs for all interfaces.
  Not just servers: firewalls, load balancers, and routers that do
  stateful inspection must reassemble fragments before inspecting them.""",
        "audit": """\
- Flood with incomplete fragments and monitor:
    /proc/net/snmp -> ReasmFails increasing
    VPN tunnel drops or packet loss?
    Large DNS responses (DNSSEC) arriving correctly?
- Check current reassembly buffer configuration:
    sysctl net.ipv4.ipfrag_high_thresh
    sysctl net.ipv4.ipfrag_time
- Verify IDS/NIDS alerts on high fragment rates
- Test firewalls: do they reassemble before inspecting (vulnerable)?""",
        "indicators": """\
/proc/net/snmp: grep ReasmFails -> value climbing
VPN tunnel (OpenVPN, IPsec) -> packet loss, higher latency
tcpdump: fragment trains arriving but never completing
cat /proc/net/ip_frag_mem -> reassembly buffer usage""",
        "defenses": """\
Reduce fragment timeout:
  net.ipv4.ipfrag_time = 5  (was 30 — shorter timeout = faster buffer reclaim)
Increase buffer (temporary measure):
  net.ipv4.ipfrag_high_thresh = 16777216  (16MB)
Drop all fragments at perimeter (breaks IPsec/VPN — only if not used):
  iptables -A INPUT -f -j DROP
Separate reassembly limit per peer (custom kernel patch — rarely deployed)""",
        "example": """\
# Flood variant (incomplete first fragments)
sudo floodles frag <ip> --variant flood -t 8 -d 30

# Last-fragment-only variant
sudo floodles frag <ip> --variant last_only -t 8 -d 30

# Monitor on target
watch -n1 'cat /proc/net/snmp | grep Reas'
watch -n1 'cat /proc/net/ip_frag_mem'""",
    },

    "overlap": {
        "title": "Fragment Overlap Attack",
        "alias": "OVERLAP",
        "layer": "L3 - Network (IP)",
        "root": True,
        "amplification": None,
        "summary": "Malformed overlapping fragments to confuse reassembly. Historically caused kernel panics.",
        "mechanism": """\
NORMAL REASSEMBLY
Fragments carry a byte offset. Fragment 1: offset 0, bytes 0-999.
Fragment 2: offset 1000, bytes 1000-1999. No overlap.

OVERLAP ATTACK — THREE VARIANTS

TEARDROP (CVE-1999-0016, historic):
  Fragment 1: offset=0,   length=1480  (bytes 0-1479)
  Fragment 2: offset=24,  length=24    (bytes 24-47)
  Fragment 2's start (byte 24) is INSIDE fragment 1 (bytes 0-1479).
  Vulnerable reassembly code computes:
    copy_length = (offset + length) - (prev_end) = (24+24) - 1480 = NEGATIVE
  This negative value is cast to unsigned -> massive integer -> memcpy overflow.
  Result: kernel panic, NULL pointer dereference, or heap corruption.
  Linux patched in 2.0.32+ / 2.2.8+.

ROSE:
  Fragment offsets chosen so that the reassembled packet would exceed
  the maximum IP packet size (65535 bytes). The kernel allocates a buffer
  for the announced total size, then receives more data than fits.
  Patched in modern kernels but tests reassembly sanity checking.

TINY FRAGMENTS:
  Minimum-size fragments (8-byte payload, the smallest RFC 791 allows).
  A single large packet produces (1480/8) = 185 tiny fragments.
  This maximizes reassembly table entries per unit of bandwidth.
  Not a crash technique — a resource exhaustion technique.
  Also used to split TCP header across fragments to bypass firewalls
  that only inspect the first fragment (port numbers in fragment 2).

WHY STILL RELEVANT
  Modern kernels handle all variants safely. But:
  - IDS signatures should still fire (testing detection)
  - Old embedded systems, SCADA/ICS equipment, custom TCP stacks may be
    running kernel versions from 1999-2010 that are still vulnerable
  - Tiny fragments bypass some network inspection devices even today""",
        "audit": """\
- Send each variant and check for IDS alerts:
    Snort SID:270 (Teardrop), SID:271 (Rose), SID:272 (Tiny fragments)
- Test embedded/IoT/SCADA targets for crash or hang under Teardrop
- Verify kernel version on target (uname -r) and check CVE exposure
- Test fragmented TCP header bypass:
    Fragment so TCP src/dst port is in fragment 2
    Does the firewall inspect fragment 2 or pass blindly?""",
        "indicators": """\
IDS alert fired     -> detection working
No IDS alert        -> signatures missing or inline IPS not seeing traffic
Target crash/hang   -> unpatched embedded system
tcpdump: overlapping fragment offsets visible in packet capture""",
        "defenses": """\
Linux kernel 2.2.8+ / 2.6.x+: all three variants handled safely
IDS signatures: Snort SID 270-272, Suricata equivalent
Drop all fragments at perimeter if fragmented traffic is not needed:
  iptables -A INPUT -f -j DROP
For SCADA/embedded: vendor patch or network-level fragment blocking""",
        "example": """\
sudo floodles overlap <ip> --variant teardrop -d 30
sudo floodles overlap <ip> --variant rose -d 30
sudo floodles overlap <ip> --variant tiny -d 30

# Check IDS alert log
tail -f /var/log/suricata/fast.log | grep -i "frag\|teardrop\|overlap\"""",
    },

    # =========================================================================
    # AMPLIFICATION / DRDoS
    # =========================================================================

    "ntp": {
        "title": "NTP Amplification",
        "alias": "MONLIST",
        "layer": "L3/L4 - UDP (NTP port 123)",
        "root": True,
        "amplification": "~550x",
        "summary": "NTP MONLIST command: 8-byte query triggers up to 4480-byte response. 556x amplification.",
        "mechanism": """\
NTP AND THE MONLIST COMMAND
NTP (Network Time Protocol, RFC 5905) runs over UDP port 123.
UDP is connectionless and spoofable — there is no handshake to validate
the source IP of a request.

The MONLIST command (mode 7, code 42) is a debugging/monitoring feature
that returns a list of the last 600 IP addresses that synchronized with
the NTP server. Each client entry is ~44 bytes.

PACKET SIZES
  MONLIST request  :  ~8 bytes
  MONLIST response : up to 600 entries x 44 bytes = 26,400 bytes
                     Fragmented across multiple UDP datagrams (~4480 bytes each)
  Amplification    : up to 3300x theoretical, ~556x typical per packet

THE ATTACK CHAIN — STEP BY STEP
  1. Attacker identifies an NTP server with MONLIST enabled.
     Test: ntpq -c monlist <server> -> if it returns data, server is vulnerable.
  2. Attacker forges a UDP packet:
       Source IP  = victim's IP address  (spoofed)
       Dst IP     = vulnerable NTP server
       Dst port   = 123
       Payload    = NTP MONLIST request (8 bytes)
  3. NTP server processes the request and sends the response to the "source" —
     which is the victim's IP.
  4. Victim receives 4480 bytes (or multiple packets) it never requested,
     for every 8 bytes the attacker sent.
  5. With multiple NTP reflectors: victim receives hundreds of Gbps of traffic
     from legitimate NTP server IPs — very hard to block by IP.

WHY THE VULNERABILITY EXISTS
  - UDP does not authenticate the source IP (no handshake)
  - NTP MONLIST was designed for monitoring, not for external exposure
  - Many NTP servers are deployed with default configs that expose MONLIST
    to the internet (no access control configured)
  - Common on: older Linux servers, network equipment, printers

STATUS IN 2024
  Most public NTP servers have disabled MONLIST since CVE-2013-5211 was
  publicized. ntpd 4.2.7p26+ disables it by default.
  Still found on: internal corporate NTP servers, older firmware, IoT.""",
        "audit": """\
- Probe each NTP server in scope:
    ntpq -c monlist <server>
    -> data returned: VULNERABLE (disable MONLIST immediately)
    -> "No association ID" or timeout: patched or firewalled
- Calculate business impact: 1 Mbps of attacker traffic = 550 Mbps inbound
- Verify /etc/ntp.conf has: restrict default noquery nopeer nomodify notrap
- Test if UDP 123 is reachable from external IPs (should be blocked if internal)
- Check upstream provider BCP38 compliance (can spoofed UDP 123 leave your network?)""",
        "indicators": """\
ntpq -c monlist <server>  -> returns list of clients: VULNERABLE
ntpq -c monlist <server>  -> times out or error: not vulnerable

During attack on victim:
  tcpdump -n udp port 123  -> high volume NTP responses arriving
  iftop                    -> bandwidth spike from multiple NTP server IPs""",
        "defenses": """\
Server-side (NTP configuration):
  Upgrade ntpd >= 4.2.7p26 (MONLIST disabled by default)
  /etc/ntp.conf: restrict default noquery nopeer nomodify notrap
  Disable mode 7 entirely: ntpd -I (if ntpd supports it)

Network-level:
  Block UDP 123 inbound from internet to internal NTP servers
  Allow only from authorised NTP upstream peers

Victim-side:
  Upstream scrubbing (Cloudflare, Arbor): drops NTP floods at carrier
  BCP38 at ISP: prevents attacker from sending spoofed UDP 123""",
        "example": """\
# Step 1: probe (no attack, just test)
ntpq -c monlist <ntp_server_ip>

# Step 2: attack (requires vulnerable reflectors)
sudo floodles ntp <victim_ip> -r <ntp1>,<ntp2>,<ntp3> -t 8 -d 60

# Monitor victim
tcpdump -i eth0 -n udp port 123 | head -20
iftop -i eth0 -n""",
    },

    "dns": {
        "title": "DNS Amplification",
        "alias": "DNS AMP",
        "layer": "L3/L4 - UDP (DNS port 53)",
        "root": True,
        "amplification": "28x-100x (ANY/DNSKEY query)",
        "summary": "Small DNS query to open resolver triggers large response delivered to spoofed victim IP.",
        "mechanism": """\
DNS AND UDP — THE SPOOFABILITY PROBLEM
DNS queries and responses travel over UDP port 53 (for responses under 512 bytes,
or 4096 bytes with EDNS0). UDP has no handshake. A resolver that receives a
query cannot verify that the source IP is the real sender. It simply sends
its response to whatever IP address is in the query's source field.

THE ANY QUERY — WHY RESPONSES ARE LARGE
A DNS query of type ANY asks the resolver to return every record type
associated with a domain: A, AAAA, MX, NS, SOA, TXT, DNSKEY, RRSIG, etc.

For a DNSSEC-signed domain (e.g., isc.org):
  - DNSKEY records: the zone's signing keys (~200-400 bytes each, multiple keys)
  - RRSIG records: cryptographic signatures for each record type
  - A, AAAA, MX, NS, SOA records
  Total response: 2,000-4,000 bytes

Packet sizes:
  ANY query for isc.org  : ~40-50 bytes
  Full DNSSEC response   : ~2,000-4,000 bytes
  Amplification factor   : 40x-100x

RFC 8482 (2019) recommends resolvers return HINFO "obsolete" to ANY queries.
Many modern authoritative servers comply. But open recursive resolvers (which
forward to authoritative servers and cache results) may still return full ANY
responses from their cache.

THE OPEN RESOLVER — THE CONFIGURATION FLAW
A DNS resolver is "open" if it accepts and answers recursive queries from
ANY source IP — not just its legitimate clients.

Correct configuration: resolver answers recursion only from 192.168.0.0/16
Open resolver:        resolver answers recursion from 0.0.0.0/0

Most ISP and corporate resolvers should be closed (restricted to their clients).
Open resolvers are a misconfiguration. They can be located with:
  Shodan: port:53 "recursion: enabled"
  Masscan + dig: scan for UDP 53 open, then test each with dig recursion flag

THE ATTACK CHAIN — STEP BY STEP
  1. Attacker finds open resolvers (resolvers that answer ANY from any source)
  2. Attacker forges a UDP packet:
       Source IP  = victim's IP  (spoofed)
       Dst IP     = open resolver
       Dst port   = 53
       Payload    = DNS ANY query for isc.org (40 bytes)
  3. Open resolver sends the full DNSSEC response to the "source" — the victim
       victim receives ~3,000 bytes it never requested
  4. Repeat with thousands of open resolvers simultaneously
  5. Victim receives hundreds of Gbps from legitimate DNS server IPs

QUERY ROTATION TO DEFEAT CACHING
If the same query is repeated, the resolver serves it from cache (fast,
same response but no amplification from upstream work). To defeat this:
  Rotate query domains: rand123.isc.org, rand456.isc.org (cache miss each time)
  Rotate query types: ANY, DNSKEY, TXT, MX

AMPLIFICATION VS REFLECTION — BOTH APPLY
  Amplification: small query -> large response (bandwidth multiplication)
  Reflection: traffic appears to come from legitimate DNS server IPs, not attacker
  Both make filtering difficult: the source IPs are real DNS servers.""",
        "audit": """\
- Identify open resolvers in scope:
    dig @<resolver_ip> isc.org ANY +short
    -> returns records: open resolver (VULNERABLE — must be fixed)
    -> REFUSED or SERVFAIL: correctly restricted (only serves its clients)

- Measure amplification factor on a vulnerable resolver:
    dig @<resolver_ip> isc.org ANY | grep "MSG SIZE"
    Query size vs response size ratio

- Test internal resolvers:
    Are corporate DNS servers answering ANY queries from all IPs?
    dig @192.168.1.53 isc.org ANY (from external VLAN or VPN)

- Check Response Rate Limiting (RRL) configuration on BIND/Unbound:
    rndc stats && grep "responses throttled" /var/named/data/named_stats.txt

- Document BCP38 compliance: can spoofed UDP 53 egress your network?
    Send a spoofed packet (requires raw socket) and see if it leaves""",
        "indicators": """\
OPEN RESOLVER DETECTION
  dig @<ip> isc.org ANY       -> data returned: VULNERABLE open resolver
  dig @<ip> isc.org ANY       -> REFUSED: correctly configured

ATTACK IN PROGRESS (on victim)
  tcpdump -n 'udp and src port 53'  -> DNS responses arriving unsolicited
  iftop                              -> bandwidth spike from many DNS server IPs
  Response size >> query size in packet capture""",
        "defenses": """\
ON THE RESOLVER (stop being a reflector):
  BIND: allow-recursion { 192.168.0.0/16; }; (restrict to internal clients only)
  Unbound: access-control: 0.0.0.0/0 refuse
           access-control: 192.168.0.0/16 allow
  Response Rate Limiting:
    BIND: rate-limit { responses-per-second 10; }; (throttle same answer)
    Unbound: ratelimit: 1000

ON THE NETWORK:
  Block UDP 53 inbound from internet to internal resolvers
  BCP38: prevent spoofed UDP from leaving the attacker's network
  Cloudflare/Arbor upstream: DNS flood detection and scrubbing

ON THE VICTIM:
  Upstream scrubbing is the only effective mitigation once under attack""",
        "example": """\
# Step 1: identify open resolver (no attack)
dig @<resolver_ip> isc.org ANY
dig @<resolver_ip> isc.org DNSKEY   # alternative large record type

# Step 2: verify response size
dig @<resolver_ip> isc.org ANY | tail -3
# "MSG SIZE  rcvd: XXXX" -> amplification = XXXX / query_size

# Step 3: attack (requires open resolvers as reflectors)
sudo floodles dns <victim_ip> -r <r1>,<r2>,<r3> --query isc.org --qtype ANY -d 60

# Query rotation to defeat caching
sudo floodles dns <victim_ip> -r <resolvers> --query isc.org --rotate -d 60

# Monitor on victim
tcpdump -i eth0 -n 'udp and src port 53' -c 100""",
    },

    "sniper": {
        "title": "SNMP Reflection Amplification",
        "alias": "SNIPER",
        "layer": "L3/L4 - UDP (SNMP port 161)",
        "root": True,
        "amplification": "~650x",
        "summary": "SNMP GetBulk with community 'public': 60-byte query triggers up to 40KB response.",
        "mechanism": """\
SNMP BACKGROUND
SNMP (Simple Network Management Protocol) is used to monitor and manage
network devices. Agents (on switches, printers, routers, servers) listen
on UDP port 161 and respond to queries from management systems.

SNMPv1/v2c use a "community string" as the only authentication mechanism.
The default community string is "public" (read access) — widely unchanged.
UDP: no handshake, source IP is not verified.

THE GETBULK REQUEST — MAXIMUM AMPLIFICATION
GetBulk is an SNMPv2c operation designed to retrieve large blocks of MIB
data efficiently. Parameters:
  - non-repeaters: 0 (retrieve all OIDs in bulk)
  - max-repetitions: 255 (return up to 255 values per OID)

Request:
  OID: 1.3.6.1.2.1 (the full MIB-II subtree)
  max-repetitions: 255
  Size: ~60 bytes

Response:
  On a well-populated MIB (switch with many interfaces, print jobs, etc.):
  Each OID value: ~40-160 bytes
  255 repetitions x multiple OIDs = 10,000-40,000 bytes
  Amplification: up to 650x

THE ATTACK CHAIN
  1. Attacker finds SNMP agent accessible from internet with community 'public':
       snmpwalk -v2c -c public <agent_ip>
       -> returns MIB data: VULNERABLE reflector
  2. Attacker forges UDP packet:
       Source IP = victim's IP (spoofed)
       Dst IP    = SNMP agent
       Dst port  = 161
       Payload   = GetBulk request (60 bytes)
  3. SNMP agent sends 40KB response to the "source" — the victim
  4. Victim receives 40KB per 60-byte query: 650x amplification
  5. At 1 Mbps of attacker traffic: 650 Mbps inbound to victim

WHERE SNMP AGENTS EXIST
  Network switches and routers (public community frequently default)
  Printers (very common — almost always SNMP-enabled with community 'public')
  UPS (APC, Eaton, Liebert — management cards with SNMP)
  Old servers with net-snmp default config
  Shodan query: port:161 "sysDescr" -> finds internet-exposed SNMP agents""",
        "audit": """\
- Enumerate SNMP agents in scope:
    nmap -sU -p 161 <subnet> --open
    snmpwalk -v2c -c public <ip>   -> data: vulnerable reflector
                                   -> timeout: restricted or firewalled

- Test other community strings (not just 'public'):
    onesixtyone -c /usr/share/doc/onesixtyone/dict.txt <ip>

- Check SNMPv3 deployment status:
    snmpget -v3 -l authPriv -u <user> -a SHA -x AES ...
    SNMPv3 uses per-session auth -> cannot be used as reflector

- Verify UDP 161 is blocked at perimeter from external IPs
- Measure amplification factor: query size vs snmpwalk output size""",
        "indicators": """\
snmpwalk -v2c -c public <agent>  -> data returned: VULNERABLE open reflector
snmpwalk -v2c -c public <agent>  -> timeout or authError: not vulnerable

During attack on victim:
  tcpdump -n 'udp and src port 161'  -> SNMP responses arriving
  iftop                               -> bandwidth spike from many UDP:161 sources""",
        "defenses": """\
ON THE SNMP AGENT:
  Migrate from SNMPv2c to SNMPv3 (authentication + privacy):
    auth: HMAC-SHA or HMAC-MD5 (per-session key, cannot be replayed/spoofed)
    priv: AES or DES encryption
    SNMPv3 responses cannot be delivered to spoofed source (no shared key)

  Restrict access by IP (view-based access control):
    /etc/snmp/snmpd.conf:
      rocommunity public 192.168.1.0/24  (only management VLAN)

  Change default community strings (public/private are well-known)

NETWORK LEVEL:
  Block UDP 161 inbound from internet at perimeter firewall
  Allow only from known management stations
  Block UDP 161 outbound (prevents responses leaving via internet)""",
        "example": """\
# Step 1: enumerate (no attack)
nmap -sU -p 161 <subnet> --open -oG snmp_hosts.txt

# Step 2: verify community string and measure response
snmpwalk -v2c -c public <agent_ip> | wc -c   # response size in bytes

# Step 3: attack
sudo floodles sniper <victim_ip> -r <agent1>,<agent2> --max-repetitions 255 -t 8 -d 60

# Monitor victim
tcpdump -i eth0 -n 'udp and src port 161' -c 100
iftop -i eth0 -n""",
    },

    "smurf": {
        "title": "Smurf Attack",
        "alias": "SMURF",
        "layer": "L3 - Network (ICMP broadcast)",
        "root": True,
        "amplification": "Nx (N = live hosts on segment)",
        "summary": "ICMP echo to broadcast address with victim as source. Every host on the segment replies to victim.",
        "mechanism": """\
IP BROADCAST ADDRESSES
Each IPv4 subnet has a broadcast address (last address: e.g. 10.0.0.255 for 10.0.0.0/24).
A packet sent to the broadcast address is delivered to every host on the subnet.
This is a L3 "directed broadcast" (different from link-layer broadcast FF:FF:FF:FF:FF:FF).

THE DESIGN FLAW
RFC 919 (1984) defines directed broadcast. ICMP echo requests sent to a
broadcast address should trigger ICMP echo replies from every listening host.
This behavior is correct for network diagnostics. But combined with IP spoofing,
it becomes an amplification weapon.

THE ATTACK CHAIN
  1. Attacker finds a network segment that:
     a. Forwards directed broadcasts (router does not block them), AND
     b. Has many active hosts (N > 50 for meaningful amplification)
  2. Attacker forges an ICMP echo request:
       Source IP  = victim's IP (spoofed)
       Dst IP     = subnet broadcast address (10.0.0.255)
       Payload    = ICMP echo request
  3. Router forwards the broadcast to all N hosts on the segment
  4. Every host generates an ICMP echo reply to the "source" — the victim
  5. Victim receives N ICMP replies per single request sent
  6. Amplification = number of live hosts on the broadcast domain

AMPLIFICATION CALCULATION
  Attacker sends  : 1 ICMP request, 60 bytes
  Victim receives : N replies, N x 60 bytes
  /24 with 200 hosts: 200 x 60 = 12,000 bytes received per 60 bytes sent = 200x

  At 1 Mbps attacker bandwidth: up to 200 Mbps inbound to victim
  Traffic arrives from many different legitimate host IPs -> hard to filter

HISTORICAL CONTEXT
Smurf was the dominant DDoS technique in 1997-2000 (before BCP38, before
directed broadcast was disabled by default). ISPs still occasionally find
misconfigured internal segments.

MODERN RELEVANCE
  OT/ICS networks: often running legacy configs, directed broadcast enabled
  Internal segments: misconfigured routers, forgotten broadcast forwarding
  Legacy enterprise: Cisco IOS had "ip directed-broadcast" enabled before IOS 12.0""",
        "audit": """\
- From within the target network segment, test if broadcast responds:
    ping -b 10.0.1.255   (Linux: requires -b flag for broadcast)
    -> multiple replies from distinct IPs: directed broadcast is forwarded (vuln)
    -> no reply: kernel drops (icmp_echo_ignore_broadcasts=1) or router blocks

- Check all routers:
    Cisco: show running-config | include directed-broadcast
    -> "ip directed-broadcast" present on interface: VULNERABLE
    -> "no ip directed-broadcast" (or absent, IOS 12.0+ default): protected

- Check host-level:
    sysctl net.ipv4.icmp_echo_ignore_broadcasts
    -> 1: host ignores broadcast pings (correct)
    -> 0: host responds to broadcast pings (vulnerable)""",
        "indicators": """\
ping -b <broadcast_addr>  -> multiple replies from different IPs: vulnerable

On victim during attack:
  tcpdump -n icmp  -> ICMP echo replies flooding from many distinct source IPs
  iftop            -> bandwidth spike from many /32 sources""",
        "defenses": """\
ON ALL HOSTS:
  net.ipv4.icmp_echo_ignore_broadcasts = 1  (default on modern Linux)
  This prevents the host from replying to ICMP sent to broadcast addresses

ON ROUTERS (most critical):
  Cisco IOS: "no ip directed-broadcast" on every interface (default since IOS 12.0)
  Juniper: "no directed-broadcast" in interface config
  This prevents the router from forwarding directed broadcasts

NETWORK LEVEL:
  BCP38 (source address validation): prevents attacker from injecting spoofed
  ICMP with victim source IP — makes Smurf impossible if deployed upstream""",
        "example": """\
# Test from within the network segment (authorized lab only)
ping -b 10.0.1.255 -c 5

# Attack (if broadcast forwarding is present in lab)
sudo floodles smurf <victim_ip> -b 10.0.1.255,10.0.2.255 -t 4 -d 30

# Verify host config on each segment host
sysctl net.ipv4.icmp_echo_ignore_broadcasts

# Verify router config
# Cisco: ssh to router -> show running-config | include directed""",
    },

    "fraggle": {
        "title": "Fraggle Attack",
        "alias": "FRAGGLE",
        "layer": "L3/L4 - Network / Transport (UDP broadcast)",
        "root": True,
        "amplification": "Nx (N = hosts with UDP echo/chargen enabled)",
        "summary": "UDP echo or chargen to broadcast address with victim as source. UDP variant of Smurf.",
        "mechanism": """\
THE SAME BROADCAST MECHANISM AS SMURF — DIFFERENT PROTOCOL
Fraggle uses the same directed broadcast technique as Smurf (same design flaw)
but targets UDP services instead of ICMP:

UDP PORT 7 — ECHO SERVICE
  Any data sent to UDP:7 is echoed back verbatim to the sender.
  RFC 862 defines this as a diagnostic service.
  Attack: send UDP data to broadcast:7 with victim as source IP.
  Every host with echo service enabled echoes the data to the victim.
  Victim also receives responses from UDP:7 — a port it may have open.

UDP PORT 19 — CHARGEN SERVICE (CHARACTER GENERATOR)
  RFC 864: server generates and sends a continuous stream of ASCII characters
  to whoever connects. Each byte received triggers a byte stream response.
  Attack: one UDP packet to broadcast:19 with victim source IP.
  Every host with chargen enabled sends a character stream to the victim.
  If victim also has chargen open: chargen <-> chargen loop (infinite traffic).

LOOPING ATTACK (bonus)
  If the victim has chargen enabled, and a reflector has echo enabled:
    victim chargen -> sends characters to echo service
    echo service -> sends characters back to victim chargen
    chargen -> responds again -> infinite loop
  This was a real denial-of-service technique against Unix systems in the 1990s.

WHERE THESE SERVICES STILL EXIST
  Network printers (especially HP JetDirect, Canon): UDP echo often enabled
  Embedded devices: old firmware with inetd services compiled in
  Legacy Unix systems: inetd.conf with echo and chargen uncommented
  Some network equipment management ports""",
        "audit": """\
- Scan for UDP echo and chargen in scope:
    nmap -sU -p 7,19 <subnet> -n --open
    -> ports open: services enabled (vulnerable reflectors)

- Test echo service:
    echo "test" | nc -u <ip> 7
    -> receives "test" back: echo enabled

- Test chargen:
    nc -u <ip> 19 & sleep 2; kill %1
    -> receives character stream: chargen enabled

- Test broadcast response:
    echo "test" | nc -u <broadcast_addr> 7
    -> multiple replies from distinct IPs: directed broadcast + echo enabled""",
        "indicators": """\
nmap -sU -p 7,19 <host>  -> open: UDP echo/chargen enabled (vulnerable)

On victim during attack:
  tcpdump -n 'udp src port 7 or udp src port 19'  -> flood from many IPs""",
        "defenses": """\
Disable UDP echo and chargen (they are legacy diagnostic services, not needed):
  Linux (inetd): comment out echo and chargen lines in /etc/inetd.conf
  Linux (xinetd): disable = yes in /etc/xinetd.d/echo and chargen
  Printers: disable via web interface or telnet management

Block at perimeter firewall:
  iptables -A INPUT -p udp --dport 7 -j DROP
  iptables -A INPUT -p udp --dport 19 -j DROP

Disable directed broadcast on routers (see Smurf defenses)
BCP38 prevents source IP spoofing""",
        "example": """\
# Enumerate (no attack)
nmap -sU -p 7,19 <subnet> --open

# Test echo service
echo "probe" | nc -u <target_ip> 7

# Attack (echo broadcast)
sudo floodles fraggle <victim_ip> -b 10.0.1.255 --port 7 -t 4 -d 30

# Attack (chargen broadcast)
sudo floodles fraggle <victim_ip> -b 10.0.1.255 --port 19 -t 4 -d 30""",
    },

    "spray": {
        "title": "Multi-Vector DRDoS",
        "alias": "SPRAY",
        "layer": "L3/L4 - Multiple protocols simultaneously",
        "root": True,
        "amplification": "Varies per vector (NTP ~550x, SNMP ~650x, DNS ~60x)",
        "summary": "Simultaneous NTP + DNS + SNMP amplification floods from independent reflector pools.",
        "mechanism": """\
THE PROBLEM WITH SINGLE-VECTOR ATTACKS
Modern DDoS scrubbing centers (Cloudflare Magic Transit, Arbor TMS, F5 AFM)
are tuned for single-protocol floods. A 100 Gbps NTP flood triggers a
specific NTP-scrubbing policy. The attacker's 100 Gbps is blocked.

THE MULTI-VECTOR APPROACH
Spray launches multiple amplification vectors in parallel:
  Thread pool A: NTP monlist flood (UDP:123, ~550x amplification)
  Thread pool B: DNS ANY flood (UDP:53, ~60x amplification)
  Thread pool C: SNMP GetBulk flood (UDP:161, ~650x amplification)

All vectors aim at the same victim simultaneously, from different reflector pools.

WHY THIS IS HARDER TO MITIGATE
  1. Protocol diversity: blocking UDP:123 doesn't help when UDP:53 and UDP:161
     are still delivering traffic. Scrubbers must apply rules per-protocol
     simultaneously — operationally complex.

  2. Traffic source diversity: each vector uses different reflectors (NTP servers,
     DNS resolvers, SNMP agents) — thousands of distinct source IPs per protocol.
     IP-based blocking is impractical.

  3. Response speed: scrubbing policies take minutes to deploy under attack.
     Three simultaneous vectors require three independent policy decisions.

  4. Aggregate bandwidth: even if each vector individually is sub-threshold
     for scrubbing detection, combined bandwidth may saturate the uplink before
     any individual vector triggers a mitigation response.

YAML PROFILE STRUCTURE
  victim: <target_ip>
  vectors:
    - type: ntp
      reflectors: [<ntp1>, <ntp2>]
      threads: 4
    - type: dns
      reflectors: [<resolver1>, <resolver2>]
      query: isc.org
      threads: 4
    - type: snmp
      reflectors: [<agent1>, <agent2>]
      threads: 4""",
        "audit": """\
- Use after single-vector tests have been successfully mitigated:
    If NTP flood is scrubbed within 30s -> test multi-vector to see if
    combined traffic evades or delays mitigation response
- Measure individual vs combined mitigation response time
- Test if scrubbing center can simultaneously apply NTP + DNS + SNMP policies
- Demonstrate combined amplification potential in client report:
    NTP pool:  8 servers x 550x = 4.4 Gbps per 1 Mbps sent
    DNS pool:  20 resolvers x 60x = 1.2 Gbps per 1 Mbps sent
    SNMP pool: 5 agents x 650x = 3.25 Gbps per 1 Mbps sent
    Combined: 8.85 Gbps inbound per 3 Mbps of attacker traffic""",
        "indicators": """\
iftop on victim -> simultaneous traffic spikes:
  UDP:123 (NTP responses)
  UDP:53  (DNS responses)
  UDP:161 (SNMP responses)
  All arriving from different source IPs simultaneously""",
        "defenses": """\
Per-protocol upstream mitigation:
  Each protocol requires its own scrubbing rule (see individual module defenses)
BGP Flowspec: push per-protocol rate-limit rules to upstream routers instantly
Anycast routing: distribute victim IP across multiple PoPs (dilute flood)
Pre-configured mitigation playbooks per protocol combination""",
        "example": """\
# Generate example profile
floodles gen spray profile.yaml

# Edit profile: add your reflectors (from prior recon)
nano profile.yaml

# Run multi-vector flood
sudo floodles spray <victim_ip> -c profile.yaml -d 60

# Monitor all protocols simultaneously
tcpdump -i eth0 -n 'udp port 123 or udp port 53 or udp port 161' | \\
  awk '{print $NF}' | sort | uniq -c | sort -rn | head -20""",
    },

    # =========================================================================
    # LAYER 7 — Application
    # =========================================================================

    "http": {
        "title": "HTTP Flood",
        "alias": "LOIC L7",
        "layer": "L7 - Application (HTTP/HTTPS)",
        "root": False,
        "amplification": None,
        "summary": "High-volume valid HTTP requests via Go goroutines. Bypasses L3/L4 scrubbing entirely.",
        "mechanism": """\
WHY L7 FLOODS ARE DIFFERENT FROM L3/L4 FLOODS
A SYN flood can be defeated by syncookies. A volumetric UDP flood can be
blocked by upstream scrubbing on bandwidth thresholds. These work because
the packets are malformed or easy to classify.

An HTTP flood sends complete, valid HTTP requests that complete the full
TCP handshake and produce valid HTTP traffic. The server must:
  1. Complete TCP handshake (3-way)
  2. Receive and parse the complete HTTP request headers
  3. Route the request (URL matching, virtual host)
  4. Execute application logic (PHP, Python, Node.js)
     -> Database queries (SELECT, JOIN, full-text search)
     -> Template rendering, session lookup, auth check
  5. Send a complete HTTP response
  6. Close or keep-alive the connection

EACH REQUEST CONSUMES REAL SERVER RESOURCES
The attacker's cost: one coroutine, negligible CPU.
The server's cost: full application stack execution + DB query.
This asymmetry is the vulnerability.

CACHE BYPASS
CDNs and reverse proxies cache GET responses. If the URL is cached,
the attack is absorbed by the CDN. Cache busting techniques:
  Rotate query strings: /?x=random  (each URL is unique -> cache miss)
  Target non-cacheable endpoints: /login, /search, /api/v1/data
  POST requests: POST bodies are never cached

TLS OVERHEAD
Each new HTTPS connection requires a TLS handshake:
  RSA 2048 key exchange: ~10ms on server
  ECDHE: ~2ms on server
  Session resumption: ~0.5ms (attacker avoids session reuse)
At 10,000 new connections/sec -> 100% of server CPU on TLS alone if RSA.
TLS 1.3 with ECDHE reduces this but still meaningful overhead.

TARGETING EXPENSIVE ENDPOINTS
Not all pages are equal. A static file returns in 1ms. A search query
with full-text indexing may take 500ms and consume 100MB of memory.
Targeting /search, /api, /checkout concentrates resource consumption.
Database connection pool exhaustion (default: 50-100 connections) crashes
the application even when the server has spare CPU.""",
        "audit": """\
- Establish RPS (requests/second) saturation threshold:
    Apache ab -n 100000 -c 100 http://target/
    Increase -c until response time > 5s or errors appear
- Identify expensive endpoints:
    /search: full-text queries
    /login: auth logic, session creation, rate-limit checks
    /api/: database-backed JSON responses
    /admin/: complex privilege checks
- Test CDN cache hit rate: flood and check CDN origin pull metrics
    High origin pull rate = cache bypass working -> CDN not absorbing
- Test with and without cache busting:
    Static URL -> CDN absorbs completely
    Rotating ?x=rand -> CDN misses, origin hit every time
- Verify WAF rate limiting triggers:
    At what RPS does the WAF start blocking?
    Per-IP? Per-session? Across source IPs?""",
        "indicators": """\
HTTP 429 Too Many Requests appearing    -> rate limiting active
HTTP 503 Service Unavailable            -> server or upstream proxy overloaded
HTTP 504 Gateway Timeout                -> application too slow, LB times out
Application logs: "connection pool exhausted", "too many connections to DB"
Response time climbing > 2-3s for normal requests during flood
CDN origin pull rate climbing (dashboard)""",
        "defenses": """\
WAF rate limiting (per IP, per session, per endpoint):
  Cloudflare: Rate Limiting rules (N req/min per IP)
  nginx: limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
  ModSecurity: SecAction, SecRule REQUEST_URI -> rate control

CDN caching (absorbs GET flood if cache hit rate is high):
  Only effective if requests hit cached content
  Cache busting defeats this -> use WAF fingerprinting instead

Application-level rate limiting:
  Token bucket per session/IP at the load balancer
  Return 429 before request reaches application

CAPTCHA / JS challenge on suspicious clients (Cloudflare Turnstile, hCaptcha)
  Bots cannot complete JS challenges -> legitimate traffic passes

Database connection pool protection:
  Configure max connections, queue overflow behavior, circuit breakers""",
        "example": """\
# Basic GET flood (no root needed)
floodles http http://target.com/ -c 512 -d 60

# Cache busting (random query string per request)
floodles http http://target.com/ -c 512 --cache-bust -d 60

# Target expensive endpoint
floodles http http://target.com/search?q=test -c 256 -d 60

# POST flood (never cached)
floodles http http://target.com/api/login -m POST -c 128 -d 60

# HTTPS (TLS overhead)
floodles http https://target.com/ -c 1024 -d 60

# Monitor on server during test
watch -n1 'ss -s'                          # connection counts
tail -f /var/log/nginx/access.log | grep 499  # client closed before response""",
    },

    "slow": {
        "title": "Slowloris",
        "alias": "LORIS",
        "layer": "L7 - Application (HTTP)",
        "root": False,
        "amplification": None,
        "summary": "Partial HTTP headers keep worker threads occupied. Exhausts connection pool with ~10 Kbps.",
        "mechanism": """\
THE HTTP REQUEST PARSING PROBLEM
A web server must read a complete HTTP request before it can respond.
An HTTP request ends with a blank line (\\r\\n\\r\\n) after the headers.
The server cannot know how many headers will arrive — it must wait.

HOW SLOWLORIS WORKS
  1. Attacker opens a TCP connection to the server on port 80/443.
  2. Attacker sends a valid HTTP request line:
       GET / HTTP/1.1\\r\\n
       Host: target.com\\r\\n
  3. But does NOT send the final blank line (\\r\\n) that signals end of headers.
  4. Every N seconds (e.g. every 10 seconds), attacker sends one more header:
       X-a: b\\r\\n
       X-b: c\\r\\n
     (arbitrary junk headers — server accepts them and keeps waiting)
  5. The server's worker thread is occupied waiting for the complete request.
     It cannot serve other clients while blocked on this connection.
  6. Repeat with 200-300 connections.

THE APACHE VULNERABILITY
Apache HTTP (prefork and worker MPM) uses a thread/process per connection.
MaxRequestWorkers (formerly MaxClients, default: 256) is the upper limit.

With 256 Slowloris sockets, every worker is occupied.
New legitimate connections queue up, then time out: service unavailable.
Bandwidth consumed: ~10 Kbps for 200 connections. Invisible to volumetric detection.
The traffic looks like legitimate slow clients (mobile on bad signal, etc.).

WHY NGINX IS DIFFERENT
Nginx uses an event-driven architecture (epoll). A single worker process
handles thousands of connections concurrently without a thread per connection.
A partial header does not block the worker — it just adds an entry to the
event loop. The worker continues handling other connections.
nginx is NOT vulnerable to Slowloris in default configuration.

THE TIMEOUT QUESTION
mod_reqtimeout (Apache module) kills connections with incomplete headers
after a timeout (default: 20 seconds). If mod_reqtimeout is loaded and
configured, Slowloris must send a header every <timeout> seconds to stay alive.
A fully configured Apache with mod_reqtimeout is resistant but not immune —
if the timeout is generous and connections are cheap, Slowloris may still work.

HTTPS/SSL
Slowloris works over SSL. The TLS handshake completes normally.
The partial headers follow over the encrypted channel.
Overhead per connection increases (TLS state), but the attack still works.""",
        "audit": """\
- Check if Apache is configured with mod_reqtimeout:
    apache2ctl -M | grep reqtimeout
    grep RequestReadTimeout /etc/apache2/apache2.conf
    If absent: server fully vulnerable to Slowloris

- Check MaxRequestWorkers:
    grep MaxRequestWorkers /etc/apache2/mpm_prefork.conf
    Default 256 -> test if 256 connections exhausts the pool

- Run the attack and observe:
    floodles slow target.com -s 200 -d 60
    From another terminal: curl --connect-timeout 5 http://target.com/
    -> times out: attack successful
    -> responds: server protected (nginx, mod_reqtimeout, or LB timeout)

- Verify if a WAF or load balancer is in front:
    LB typically enforces a header timeout (haproxy: timeout http-request 5s)
    If LB is present, Apache may be protected even without mod_reqtimeout""",
        "indicators": """\
APACHE (vulnerable without mod_reqtimeout):
  ss -nt state ESTABLISHED dst <target>  -> connection count climbing to MaxRequestWorkers
  curl from external: connection timeout
  Apache access log: many requests with no response logged (connection closed)
  netstat on server: many ESTABLISHED connections from attacker IP(s)

NGINX (not vulnerable):
  ss -s  -> ESTABLISHED count climbs but requests still served
  curl   -> still responds normally during flood""",
        "defenses": """\
APACHE (choose one or combine):
  mod_reqtimeout:
    RequestReadTimeout header=20-40,minrate=500
    (drop connection if headers not complete within 20-40s)
  Reduce MaxRequestWorkers + use async MPM (event MPM instead of prefork)
  Timeout directive: Timeout 30 (global socket timeout)

NGINX (already resistant — no action needed for basic config):
  client_header_timeout 10s  (set conservatively as extra hardening)

WAF / Load Balancer:
  haproxy: timeout http-request 5s  (drop if headers not received in 5s)
  nginx upstream: proxy_read_timeout 5s
  Per-IP connection limit:
    iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 20 -j REJECT

Detection:
  fail2ban rule matching many open connections per IP with no completed request""",
        "example": """\
# Basic attack on Apache (no root needed)
floodles slow target.com --port 80 --sockets 200 --interval 10 -d 120

# HTTPS
floodles slow target.com --port 443 --ssl --sockets 150 -d 120

# Verify effect from separate terminal
curl --connect-timeout 5 http://target.com/
watch -n1 'ss -nt state ESTABLISHED | grep :80 | wc -l'

# Apache: check MaxRequestWorkers impact
grep -r MaxRequestWorkers /etc/apache2/
apache2ctl status""",
    },

    "slowpost": {
        "title": "Slow POST / RUDY",
        "alias": "RUDY — R-U-Dead-Yet",
        "layer": "L7 - Application (HTTP POST)",
        "root": False,
        "amplification": None,
        "summary": "Valid POST headers with Content-Length, then body delivered at 1 byte/10s. Workers stall for hours.",
        "mechanism": """\
THE DIFFERENCE FROM SLOWLORIS
Slowloris keeps headers incomplete (never sends the final \\r\\n).
mod_reqtimeout's header timeout catches this.

RUDY (R-U-Dead-Yet) exploits a different phase of the request:
the POST body. Headers are COMPLETE and valid. The body is sent at
a deliberately slow rate.

THE ATTACK
  1. Send a complete, valid HTTP POST request with headers:
       POST /api/login HTTP/1.1
       Host: target.com
       Content-Type: application/x-www-form-urlencoded
       Content-Length: 10000000           <- 10 million bytes declared
       \\r\\n                               <- headers COMPLETE
  2. Then send the POST body at 1 byte every 10 seconds.
  3. The server accepts the connection: headers are valid, Content-Length set.
  4. The server's worker must read 10,000,000 bytes before processing the request.
     At 1 byte/10s -> 10,000,000 bytes = 1,388 hours to complete.
  5. Worker is occupied for as long as the connection remains open.

WHY THIS BYPASSES mod_reqtimeout HEADER TIMEOUT
mod_reqtimeout has two phases:
  header=20-40: time to receive complete headers -> RUDY completes headers fast
  body=10,minrate=500: time to receive body at minimum rate

If the body directive is not configured (many Apache setups only configure
the header directive), RUDY workers can stall indefinitely.

Even with body=10,minrate=500 (drop if body < 500 B/s):
  Attacker sends exactly 500 B/s to stay alive (5 bytes every 10ms)
  Worker still occupied, just at a slightly higher rate

TARGET SELECTION
POST endpoints are better targets than GET:
  /login: auth processing, session creation
  /upload: file write to disk, virus scanning, image processing
  /api/v1/data: database INSERT or UPDATE operations
  /comment, /submit: write-heavy application logic
  Advantage: POST is never cached, always hits the application""",
        "audit": """\
- Check Apache body timeout configuration:
    grep RequestReadTimeout /etc/apache2/mods-enabled/reqtimeout.conf
    Look for "body=N,minrateM" -> if absent, body has no timeout: VULNERABLE

- Check nginx:
    grep client_body_timeout /etc/nginx/nginx.conf
    Default is 60s -> body must be received within 60s (reasonable protection)

- Test POST endpoints directly:
    floodles slowpost target.com --port 80 --sockets 100 -d 120
    From another terminal: curl -X POST http://target.com/login -d "test=1"
    -> times out: POST endpoints exhausted
    -> responds: protected by body timeout

- Compare GET vs POST availability during attack:
    If GET responses continue but POST times out: POST worker pool exhausted""",
        "indicators": """\
Worker threads stuck in read state (visible in Apache server-status)
POST endpoints return 503 or time out
GET requests still served normally (different worker pools sometimes)
ss -nt: many ESTABLISHED connections with slow data transfer
/server-status: all workers in "Reading Request" state""",
        "defenses": """\
APACHE:
  RequestReadTimeout body=10,minrate=500
    (drop if body transfer rate < 500 bytes/sec)
  mod_reqtimeout must be loaded AND the body directive must be configured

NGINX:
  client_body_timeout 10s;   (disconnect if no body data for 10s)
  client_max_body_size 10m;  (limit POST body size)

WAF / LB:
  haproxy: timeout http-request 5s (includes body read time)
  Enforce minimum POST transmission rate at WAF level
  Block abnormally large Content-Length values from untrusted sources

APPLICATION:
  Limit maximum POST body size in application config
  Async body reading (non-blocking I/O) reduces per-connection worker cost""",
        "example": """\
# Basic slow POST attack
floodles slowpost target.com --port 80 --sockets 150 --interval 10 -d 120

# HTTPS
floodles slowpost target.com --port 443 --ssl --sockets 100 -d 120

# Large Content-Length declaration
floodles slowpost target.com --port 80 --cl 10000000 --sockets 100 -d 120

# Verify: GET still works, POST times out?
curl -G http://target.com/            # GET — should respond
curl -X POST http://target.com/login  # POST — should time out if attack works""",
    },

    "nuke": {
        "title": "TCP Starvation",
        "alias": "NUKE",
        "layer": "L7 - Application (TCP)",
        "root": False,
        "amplification": None,
        "summary": "Fills server connection table via stalled TCP sessions. Three variants: hold, window0, persist.",
        "mechanism": """\
THE SHARED RESOURCE: CONNECTION TABLE
Every OS maintains a table of active TCP connections. Maximum connections
are bounded by file descriptors (ulimit -n), socket buffers, and memory.
A typical server allows 65,535 to 1,000,000+ simultaneous connections.
Applications impose additional limits: MaxRequestWorkers, thread pool size,
DB connection pool (typically 50-100 connections).

If the connection table fills, new connections are rejected.
The goal: keep connections alive as long as possible with minimal traffic.

VARIANT 1 — HOLD (READ STALL)
  1. Complete TCP 3-way handshake (connection ESTABLISHED)
  2. Send a complete, valid HTTP GET request
  3. Server processes request and begins sending the response
  4. Attacker advertises a non-zero window but never reads from the socket
  5. Server sends response into the socket buffer until it fills
  6. Socket buffer full -> server stalls waiting for attacker to read
  7. Connection held open until server-side send/idle timeout

  The server has a completed HTTP transaction in flight but cannot
  finish it. Worker thread blocked in write() waiting for socket buffer.

VARIANT 2 — WINDOW ZERO (WRITE STALL)
  1. Complete TCP handshake
  2. Send HTTP GET request
  3. Immediately send TCP window update: receive window = 0
  4. Server cannot send any data (receiver window is zero)
  5. Server sends TCP zero-window probes (ZWP) at increasing intervals:
     initial RTO (~200ms), doubling each time, up to ~120s between probes
  6. Server maintains the connection indefinitely, sending probes
  7. Attacker responds to probes with window=0 to keep connection alive

  Advantage: very little traffic. Probes are tiny (~40 bytes every 30-120s).
  Difficult to distinguish from a legitimate client with a full receive buffer.
  Worker thread blocked in write() or writev().

VARIANT 3 — PERSIST (TIMER EXHAUSTION)
  Similar to window0 but attacker uses TCP persist timer behavior.
  The persist timer fires when the server's send buffer is blocked.
  Attacker periodically resets the persist timer by sending zero-window updates.
  Server never gives up — the timer is always extended.
  Each connection consumes a kernel timer entry and socket state.

CONNECTION TABLE MATH
  1000 stalled connections x MaxRequestWorkers 256 = table exhaustion at 256
  A single machine can open 1000 connections easily (ephemeral port range)
  The server runs out of workers at 256 -> new clients get 503 or queue""",
        "audit": """\
- Measure current connection limits:
    ulimit -n  (file descriptors per process)
    ss -s  (total socket counts)
    /proc/sys/net/ipv4/tcp_max_orphans

- Test hold variant:
    floodles nuke <ip> --port 80 --sockets 500 --variant hold -d 120
    Watch: ss -s -> ESTABLISHED count climbing
    From external: new connections refused or queued?

- Test window0 variant (stealthiest):
    floodles nuke <ip> --port 80 --sockets 300 --variant window0 -d 120
    Watch: zero-window probes in tcpdump -> server stuck waiting

- Verify timeout configuration:
    nginx: send_timeout (time waiting to send to client)
    Apache: TimeOut directive
    LB: idle connection timeout""",
        "indicators": """\
ss -s -> ESTABLISHED + CLOSE_WAIT count climbing steadily
New connections returning 503 or timing out
Server-status (Apache): many workers in "Sending Reply" state with no progress
tcpdump: TCP zero-window packets from server, window=0 from attacker
FIN_WAIT2 count climbing (server sent FIN, attacker never responds)""",
        "defenses": """\
NGINX:
  send_timeout 10s;            (close connection if no byte sent to client in 10s)
  keepalive_timeout 30s;       (close idle keepalive connections)
  lingering_timeout 5s;        (time to wait for client data before closing)

APACHE:
  TimeOut 30                   (all socket operations: read, send)
  KeepAliveTimeout 5           (close keepalive if idle > 5s)

FIREWALL (per-IP connection limit):
  iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 50 -j REJECT
  (reject new connections if IP already has > 50 open)

KERNEL:
  net.ipv4.tcp_keepalive_time    = 60   (start keepalive probes after 60s idle)
  net.ipv4.tcp_keepalive_intvl   = 10   (probe every 10s)
  net.ipv4.tcp_keepalive_probes  = 5    (drop after 5 failed probes)
  net.ipv4.tcp_fin_timeout       = 15   (FIN_WAIT2 timeout, default 60s)

Load balancer idle timeout:
  haproxy: timeout client 30s, timeout server 30s""",
        "example": """\
# Hold variant (attacker receives, never reads)
floodles nuke <ip> --port 80 --sockets 500 --variant hold -d 120

# Window zero (attacker sets receive window to 0)
floodles nuke <ip> --port 80 --sockets 300 --variant window0 -d 120

# Persist timer exhaustion
floodles nuke <ip> --port 443 --ssl --sockets 200 --variant persist -d 120

# Monitor on target
watch -n2 'ss -s'
tcpdump -i eth0 -n 'tcp and tcp[14:2] = 0'   # zero-window packets
watch -n2 'ss -nt state FIN-WAIT-2 | wc -l'""",
    },
}

# Aliases for common alternate names
ALIASES = {
    "synflood": "syn",
    "syn_flood": "syn",
    "ack_flood": "ack",
    "ackflood": "ack",
    "udpflood": "udp",
    "udp_flood": "udp",
    "icmpflood": "icmp",
    "icmp_flood": "icmp",
    "slowloris": "slow",
    "loris": "slow",
    "rudy": "slowpost",
    "slow_post": "slowpost",
    "httpflood": "http",
    "http_flood": "http",
    "teardrop": "overlap",
    "monlist": "ntp",
    "dnsamp": "dns",
    "dns_amp": "dns",
    "snmp": "sniper",
}


def render(module: str) -> None:
    """Render the man page for a given module using Rich."""
    key = ALIASES.get(module.lower(), module.lower())
    entry = ATTACKS.get(key)

    if entry is None:
        available = ", ".join(sorted(ATTACKS.keys()))
        print(f"[!] Unknown module: '{module}'\nAvailable: {available}")
        return

    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text
        from rich.rule import Rule
        from rich import box
        c = Console()
    except ImportError:
        _render_plain(entry)
        return

    amp = f"  •  Amplification: {entry['amplification']}" if entry['amplification'] else ""
    root_str = "root required" if entry['root'] else "no root required"

    # Header
    c.print()
    c.print(Panel(
        f"[bold white]{entry['title']}[/bold white]  [dim]({entry['alias']})[/dim]\n"
        f"[yellow]{entry['layer']}[/yellow]  •  [cyan]{root_str}[/cyan]{amp}\n\n"
        f"[italic]{entry['summary']}[/italic]",
        border_style="bold red",
        title="[bold red]floodles man[/bold red]",
        title_align="left",
    ))

    sections = [
        ("MECHANISM",  "mechanism",  "cyan"),
        ("AUDIT USE",  "audit",      "yellow"),
        ("INDICATORS", "indicators", "green"),
        ("DEFENSES",   "defenses",   "dim"),
        ("EXAMPLE",    "example",    "white"),
    ]

    for label, key_name, color in sections:
        c.print(Rule(f"[bold {color}]{label}[/bold {color}]", style=color))
        if key_name == "example":
            c.print(f"[{color}]{entry[key_name]}[/{color}]")
        else:
            c.print(f"[{color}]{entry[key_name]}[/{color}]")
        c.print()


def _render_plain(entry: dict) -> None:
    """Plain text fallback when Rich is not available."""
    print(f"\n{'='*60}")
    print(f"  {entry['title']} ({entry['alias']})")
    print(f"  {entry['layer']}")
    print(f"{'='*60}")
    for section in ("mechanism", "audit", "indicators", "defenses", "example"):
        print(f"\n-- {section.upper()} --")
        print(entry[section])
    print()


def list_modules() -> None:
    """Print a table of all available modules."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
        c = Console()
        t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        t.add_column("Module", style="cyan", width=12)
        t.add_column("Title", width=26)
        t.add_column("Layer", width=22)
        t.add_column("Root", width=5)
        t.add_column("Amp", width=8)
        for k, v in sorted(ATTACKS.items()):
            t.add_row(
                k,
                v["title"],
                v["layer"].split(" - ")[1] if " - " in v["layer"] else v["layer"],
                "[red]yes[/red]" if v["root"] else "[green]no[/green]",
                v["amplification"] or "-",
            )
        c.print()
        c.print(t)
        c.print(f"[dim]Usage: floodles man <module>[/dim]\n")
    except ImportError:
        for k, v in sorted(ATTACKS.items()):
            print(f"  {k:<14} {v['title']}")
