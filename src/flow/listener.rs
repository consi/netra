use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use arc_swap::ArcSwap;
use socket2::{Domain, Protocol, Socket, Type};

use super::ipfix::IpfixCache;
use super::v9::V9Cache;
use super::{ExtractedFlow, ipfix, v5, v9};
use crate::asn::AsnDb;
use crate::pipeline::WindowManager;

/// Receive mode detected at startup.
#[derive(Debug, Clone, Copy)]
pub enum ReceiveMode {
    RecvMmsg,
    RecvFrom, // fallback if recvmmsg unavailable (shouldn't happen on Linux)
}

impl std::fmt::Display for ReceiveMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiveMode::RecvMmsg => write!(f, "recvmmsg (batch, up to {BATCH_SIZE} per syscall)"),
            ReceiveMode::RecvFrom => write!(f, "recv_from (single datagram)"),
        }
    }
}

const BATCH_SIZE: usize = 32;
const SLOT_SIZE: usize = 2048; // NetFlow/IPFIX packets are always <1500 bytes

/// Detect the best available receive mode.
pub fn detect_mode() -> ReceiveMode {
    // recvmmsg is available on all Linux kernels >= 2.6.33, which is everything we target.
    // Probe just to be safe.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return ReceiveMode::RecvFrom;
    }
    // Try a zero-timeout recvmmsg on unbound socket — will fail with EAGAIN/EINVAL, not ENOSYS
    let mut hdr: libc::mmsghdr = unsafe { std::mem::zeroed() };
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ret = unsafe { libc::recvmmsg(sock, &mut hdr, 1, libc::MSG_DONTWAIT as _, &mut ts) };
    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    unsafe { libc::close(sock) };
    // ENOSYS means the syscall doesn't exist
    if ret < 0 && err == libc::ENOSYS {
        return ReceiveMode::RecvFrom;
    }
    ReceiveMode::RecvMmsg
}

/// Spawn N OS threads, each with its own SO_REUSEPORT UDP socket on the given port.
/// Template caches and sampling rates are shared across all threads so that a template
/// learned on one thread is visible to data packets arriving on any other thread.
pub fn spawn_listeners(
    count: usize,
    mode: ReceiveMode,
    port: u16,
    asn_db: Arc<ArcSwap<AsnDb>>,
    windows: Arc<WindowManager>,
) -> Vec<std::thread::JoinHandle<()>> {
    let v9_cache = Arc::new(V9Cache::new());
    let ipfix_cache = Arc::new(IpfixCache::new());

    (0..count)
        .map(|i| {
            let asn_db = asn_db.clone();
            let windows = windows.clone();
            let v9_cache = v9_cache.clone();
            let ipfix_cache = ipfix_cache.clone();
            std::thread::Builder::new()
                .name(format!("udp-listener-{i}"))
                .spawn(move || match mode {
                    ReceiveMode::RecvMmsg => {
                        listener_loop_recvmmsg(port, asn_db, windows, v9_cache, ipfix_cache)
                    }
                    ReceiveMode::RecvFrom => {
                        listener_loop_single(port, asn_db, windows, v9_cache, ipfix_cache)
                    }
                })
                .expect("failed to spawn UDP listener thread")
        })
        .collect()
}

/// Process a single packet: version detection → parse → ASN lookup → window attribution.
#[inline]
pub(crate) fn process_packet(
    data: &[u8],
    src_ip: IpAddr,
    v9_parser: &mut v9::V9Parser,
    ipfix_parser: &mut ipfix::IpfixParser,
    flows: &mut Vec<ExtractedFlow>,
    db: &AsnDb,
    current: &crate::pipeline::window::LiveWindow,
) {
    if data.len() < 2 {
        return;
    }

    let version = u16::from_be_bytes([data[0], data[1]]);
    flows.clear();
    let result = match version {
        5 => v5::parse_into(data, flows),
        9 => v9_parser.parse_into(data, src_ip, flows),
        10 => ipfix_parser.parse_into(data, src_ip, flows),
        _ => return,
    };

    if result.is_err() || flows.is_empty() {
        return;
    }

    for flow in flows.iter() {
        // Drop flows without a usable L3 address — L2-only/MAC-only records
        // can't contribute to ASN attribution.
        if flow.dst_ip.is_unspecified() && flow.src_ip.is_unspecified() {
            continue;
        }

        let dst_asn = db.lookup_asn(flow.dst_ip);
        let src_asn = db.lookup_asn(flow.src_ip);

        crate::pipeline::attribute_flow_dual(
            flow.vlan_id,
            dst_asn,
            src_asn,
            flow.byte_count,
            flow.packet_count,
            flow.flow_start_ms,
            flow.flow_end_ms,
            |_epoch, vlan, dst, src, bytes, packets, count| {
                current.record_upload(vlan, dst, bytes, packets, count);
                current.record_download(vlan, src, bytes, packets, count);
            },
        );
    }
}

// --- recvmmsg batch receive (primary path) ---

fn listener_loop_recvmmsg(
    port: u16,
    asn_db: Arc<ArcSwap<AsnDb>>,
    windows: Arc<WindowManager>,
    v9_cache: Arc<V9Cache>,
    ipfix_cache: Arc<IpfixCache>,
) {
    let sock = create_socket(port).expect("failed to create UDP socket");
    let fd = sock.as_raw_fd();

    let mut v9_parser = v9::V9Parser::new(v9_cache);
    let mut ipfix_parser = ipfix::IpfixParser::new(ipfix_cache);
    let mut flows: Vec<ExtractedFlow> = Vec::with_capacity(64);

    // Pre-allocate receive buffers and headers
    let mut bufs = vec![0u8; BATCH_SIZE * SLOT_SIZE];
    let mut iovecs: [libc::iovec; BATCH_SIZE] = unsafe { std::mem::zeroed() };
    let mut addrs: [libc::sockaddr_in; BATCH_SIZE] = unsafe { std::mem::zeroed() };
    let mut hdrs: [libc::mmsghdr; BATCH_SIZE] = unsafe { std::mem::zeroed() };

    // Wire up iovecs → buffer slots, and hdrs → iovecs + addrs
    for i in 0..BATCH_SIZE {
        iovecs[i].iov_base = bufs[i * SLOT_SIZE..].as_mut_ptr() as *mut libc::c_void;
        iovecs[i].iov_len = SLOT_SIZE;
        hdrs[i].msg_hdr.msg_iov = &mut iovecs[i];
        hdrs[i].msg_hdr.msg_iovlen = 1;
        hdrs[i].msg_hdr.msg_name = &mut addrs[i] as *mut _ as *mut libc::c_void;
        hdrs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
    }

    loop {
        // MSG_WAITFORONE: block for first datagram, return immediately with any additional
        let n = unsafe {
            libc::recvmmsg(
                fd,
                hdrs.as_mut_ptr(),
                BATCH_SIZE as _,
                libc::MSG_WAITFORONE as _,
                std::ptr::null_mut(),
            )
        };

        if n <= 0 {
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::Interrupted {
                    tracing::warn!("recvmmsg error: {err}");
                }
            }
            continue;
        }

        let db = asn_db.load();
        let current = windows.current.load();

        for i in 0..n as usize {
            let len = hdrs[i].msg_len as usize;
            if len == 0 {
                continue;
            }
            let data = &bufs[i * SLOT_SIZE..i * SLOT_SIZE + len];
            let src_ip = sockaddr_to_ip(&addrs[i]);

            // Reset namelen for next recvmmsg call
            hdrs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;

            process_packet(
                data,
                src_ip,
                &mut v9_parser,
                &mut ipfix_parser,
                &mut flows,
                &db,
                &current,
            );
        }
    }
}

fn sockaddr_to_ip(addr: &libc::sockaddr_in) -> IpAddr {
    let octets = addr.sin_addr.s_addr.to_ne_bytes();
    IpAddr::V4(std::net::Ipv4Addr::new(
        octets[0], octets[1], octets[2], octets[3],
    ))
}

// --- Single recv_from fallback ---

fn listener_loop_single(
    port: u16,
    asn_db: Arc<ArcSwap<AsnDb>>,
    windows: Arc<WindowManager>,
    v9_cache: Arc<V9Cache>,
    ipfix_cache: Arc<IpfixCache>,
) {
    let sock = create_socket(port).expect("failed to create UDP socket");

    let mut v9_parser = v9::V9Parser::new(v9_cache);
    let mut ipfix_parser = ipfix::IpfixParser::new(ipfix_cache);
    let mut buf = [0u8; 65535];
    let mut flows: Vec<ExtractedFlow> = Vec::with_capacity(64);

    loop {
        let (len, src) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("UDP recv error: {e}");
                continue;
            }
        };

        let db = asn_db.load();
        let current = windows.current.load();

        process_packet(
            &buf[..len],
            src.ip(),
            &mut v9_parser,
            &mut ipfix_parser,
            &mut flows,
            &db,
            &current,
        );
    }
}

fn create_socket(port: u16) -> std::io::Result<std::net::UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_port(true)?;
    sock.set_recv_buffer_size(8 * 1024 * 1024)?; // 8MB kernel buffer
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    sock.bind(&addr.into())?;
    Ok(sock.into())
}
