// native/rust/src/lib.rs
// Zero-copy packet builder exposed as C-compatible shared library.
//
// Compile:
//   cargo build --release
//   -> target/release/libfloodles_packets.so
//
// Why Rust here:
//   - Stack-allocated packet buffers (no heap allocation per packet)
//   - SIMD-accelerated checksum via compiler auto-vectorization
//   - Memory safety: no buffer overflows, no UB (unlike C)
//   - Same performance as C with compile-time guarantees

use std::net::Ipv4Addr;

// ============================================================================
// Packet buffer - fixed-size, stack allocated
// ============================================================================

const MAX_PKT: usize = 1500;

#[repr(C)]
pub struct PacketBuf {
    pub data: [u8; MAX_PKT],
    pub len:  u32,
}

impl PacketBuf {
    #[inline]
    fn new() -> Self {
        PacketBuf { data: [0u8; MAX_PKT], len: 0 }
    }
}

// ============================================================================
// Fast PRNG - xorshift64, no heap, thread-local
// ============================================================================

use std::cell::Cell;

thread_local! {
    static RNG: Cell<u64> = Cell::new(
        // Seed from thread id hash + const
        0xDEAD_BEEF_CAFE_1337u64
    );
}

#[inline(always)]
fn fast_rand() -> u64 {
    RNG.with(|r| {
        let mut x = r.get();
        if x == 0 { x = 0xDEAD_BEEF_CAFE_1337; }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        r.set(x);
        x
    })
}

#[inline(always)]
fn rand_u16() -> u16 { fast_rand() as u16 }

#[inline(always)]
fn rand_u32() -> u32 { fast_rand() as u32 }

fn rand_ip() -> u32 {
    loop {
        let ip = rand_u32();
        let a = (ip >> 24) as u8;
        let b = ((ip >> 16) & 0xFF) as u8;
        // Skip private/reserved
        if a == 10 || a == 127 || a == 0 || a >= 224 { continue; }
        if a == 172 && (16..=31).contains(&b)         { continue; }
        if a == 192 && b == 168                        { continue; }
        return ip;
    }
}

fn rand_port() -> u16 {
    1024 + (fast_rand() % 64511) as u16
}

// ============================================================================
// Checksum (RFC 1071)
// Compiler will auto-vectorize this with -O3 on x86_64
// ============================================================================

#[inline]
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i+1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// TCP pseudo-header for checksum calculation
fn tcp_checksum(src: u32, dst: u32, tcp_bytes: &[u8]) -> u16 {
    let tcp_len = tcp_bytes.len() as u16;
    let mut pseudo = Vec::with_capacity(12 + tcp_bytes.len());
    pseudo.extend_from_slice(&src.to_be_bytes());
    pseudo.extend_from_slice(&dst.to_be_bytes());
    pseudo.push(0u8);
    pseudo.push(6u8);  // IPPROTO_TCP
    pseudo.extend_from_slice(&tcp_len.to_be_bytes());
    pseudo.extend_from_slice(tcp_bytes);
    checksum(&pseudo)
}

// ============================================================================
// IP header builder (writes into slice)
// ============================================================================

fn write_ip_header(buf: &mut [u8], proto: u8, src: u32, dst: u32, total_len: u16) {
    buf[0]  = 0x45;                         // version=4, ihl=5
    buf[1]  = 0x00;                         // DSCP/ECN
    buf[2..4].copy_from_slice(&total_len.to_be_bytes());
    buf[4..6].copy_from_slice(&rand_u16().to_be_bytes()); // id
    buf[6]  = 0x00;                         // flags
    buf[7]  = 0x00;                         // frag offset
    buf[8]  = 64 + (fast_rand() & 63) as u8; // TTL 64-127
    buf[9]  = proto;
    buf[10] = 0x00;                         // checksum placeholder
    buf[11] = 0x00;
    buf[12..16].copy_from_slice(&src.to_be_bytes());
    buf[16..20].copy_from_slice(&dst.to_be_bytes());
    // Compute and write checksum
    let cksum = checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&cksum.to_be_bytes());
}

// ============================================================================
// Packet builders - each returns PacketBuf (stack allocated)
// ============================================================================

fn build_tcp_packet(dst_ip: u32, dst_port: u16, flags: u8, spoof: bool) -> PacketBuf {
    let mut pkt = PacketBuf::new();
    let ip_len: usize = 20;
    let tcp_len: usize = 20;
    let total = (ip_len + tcp_len) as u16;

    let src_ip = if spoof { rand_ip() } else { 0u32 };
    let src_port = rand_port();
    let seq  = rand_u32();
    let ack  = rand_u32();

    // TCP header (offset 20)
    let t = &mut pkt.data[ip_len..ip_len + tcp_len];
    t[0..2].copy_from_slice(&src_port.to_be_bytes());
    t[2..4].copy_from_slice(&dst_port.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 0x50;    // data offset = 5 (20 bytes), reserved = 0
    t[13] = flags;   // TCP flags byte
    t[14..16].copy_from_slice(&8192u16.to_be_bytes()); // window
    // checksum placeholder t[16..18] = 0
    // urgent pointer t[18..20] = 0

    // TCP checksum
    let cksum = tcp_checksum(src_ip, dst_ip, &pkt.data[ip_len..ip_len + tcp_len]);
    pkt.data[ip_len + 16..ip_len + 18].copy_from_slice(&cksum.to_be_bytes());

    // IP header
    write_ip_header(&mut pkt.data[..ip_len], 6, src_ip, dst_ip, total);

    pkt.len = total as u32;
    pkt
}

fn build_udp_packet(dst_ip: u32, dst_port: u16, payload_size: usize, spoof: bool) -> PacketBuf {
    let mut pkt = PacketBuf::new();
    let ip_len:  usize = 20;
    let udp_len: usize = 8 + payload_size;
    let total = (ip_len + udp_len) as u16;

    let src_ip   = if spoof { rand_ip() } else { 0u32 };
    let src_port = rand_port();

    // UDP header
    let u = &mut pkt.data[ip_len..ip_len + 8];
    u[0..2].copy_from_slice(&src_port.to_be_bytes());
    u[2..4].copy_from_slice(&dst_port.to_be_bytes());
    u[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // checksum = 0 (optional for IPv4)

    // Random payload
    for i in 0..payload_size {
        pkt.data[ip_len + 8 + i] = fast_rand() as u8;
    }

    write_ip_header(&mut pkt.data[..ip_len], 17, src_ip, dst_ip, total);
    pkt.len = total as u32;
    pkt
}

fn build_icmp_packet(dst_ip: u32, payload_size: usize, spoof: bool) -> PacketBuf {
    let mut pkt = PacketBuf::new();
    let ip_len:   usize = 20;
    let icmp_len: usize = 8 + payload_size;
    let total = (ip_len + icmp_len) as u16;

    let src_ip = if spoof { rand_ip() } else { 0u32 };

    // ICMP header
    pkt.data[ip_len]     = 8;  // type: echo request
    pkt.data[ip_len + 1] = 0;  // code
    // id + seq
    let id  = rand_u16();
    let seq = rand_u16();
    pkt.data[ip_len + 4..ip_len + 6].copy_from_slice(&id.to_be_bytes());
    pkt.data[ip_len + 6..ip_len + 8].copy_from_slice(&seq.to_be_bytes());
    // payload
    for i in 0..payload_size {
        pkt.data[ip_len + 8 + i] = fast_rand() as u8;
    }
    // checksum
    let cksum = checksum(&pkt.data[ip_len..ip_len + icmp_len]);
    pkt.data[ip_len + 2..ip_len + 4].copy_from_slice(&cksum.to_be_bytes());

    write_ip_header(&mut pkt.data[..ip_len], 1, src_ip, dst_ip, total);
    pkt.len = total as u32;
    pkt
}

// ============================================================================
// C-compatible FFI exports
// ============================================================================

/// TCP flags constants (matching C sender)
pub const FLAG_SYN:  u8 = 0x02;
pub const FLAG_ACK:  u8 = 0x10;
pub const FLAG_RST:  u8 = 0x04;
pub const FLAG_FIN:  u8 = 0x01;
pub const FLAG_PSH:  u8 = 0x08;
pub const FLAG_URG:  u8 = 0x20;
pub const FLAG_XMAS: u8 = FLAG_FIN | FLAG_PSH | FLAG_URG;  // 0x29

#[no_mangle]
pub extern "C" fn build_syn(dst_ip: u32, dst_port: u16, spoof: i32) -> PacketBuf {
    build_tcp_packet(dst_ip, dst_port, FLAG_SYN, spoof != 0)
}

#[no_mangle]
pub extern "C" fn build_ack(dst_ip: u32, dst_port: u16, spoof: i32) -> PacketBuf {
    build_tcp_packet(dst_ip, dst_port, FLAG_ACK, spoof != 0)
}

#[no_mangle]
pub extern "C" fn build_rst(dst_ip: u32, dst_port: u16, spoof: i32) -> PacketBuf {
    build_tcp_packet(dst_ip, dst_port, FLAG_RST, spoof != 0)
}

#[no_mangle]
pub extern "C" fn build_xmas(dst_ip: u32, dst_port: u16, spoof: i32) -> PacketBuf {
    build_tcp_packet(dst_ip, dst_port, FLAG_XMAS, spoof != 0)
}

#[no_mangle]
pub extern "C" fn build_udp(dst_ip: u32, dst_port: u16,
                             payload_size: u32, spoof: i32) -> PacketBuf {
    build_udp_packet(dst_ip, dst_port, payload_size as usize, spoof != 0)
}

#[no_mangle]
pub extern "C" fn build_icmp(dst_ip: u32, payload_size: u32, spoof: i32) -> PacketBuf {
    build_icmp_packet(dst_ip, payload_size as usize, spoof != 0)
}

// ============================================================================
// Cargo.toml (embedded as doc, create separately)
// ============================================================================
//
// [package]
// name = "floodles_packets"
// version = "0.1.0"
// edition = "2021"
//
// [lib]
// crate-type = ["cdylib"]
//
// [profile.release]
// opt-level = 3
// lto = true
// codegen-units = 1
// panic = "abort"
