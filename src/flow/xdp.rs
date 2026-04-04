//! AF_XDP zero-copy receive path.
//!
//! Bypasses the kernel network stack by attaching a minimal XDP/BPF program
//! that redirects UDP port 2055 packets into AF_XDP sockets via shared memory
//! ring buffers. One thread per NIC RX queue.
//!
//! Requirements:
//!   - Linux kernel >= 5.4 (>= 5.10 for shared UMEM)
//!   - CAP_NET_ADMIN + CAP_BPF (or root)
//!   - NIC with XDP driver support (i40e, ice, ixgbe, mlx5, ena, virtio)
//!   - `clang` at build time (compiles the BPF filter)
//!   - NETRA_XDP_IFACE=<interface> environment variable
//!
//! Non-matching traffic (anything other than UDP/2055) passes through the
//! normal kernel stack unaffected.

mod imp {
    use aya::Ebpf;
    use aya::maps::XskMap;
    use aya::programs::{Xdp, XdpFlags};
    use std::sync::Arc;

    use arc_swap::ArcSwap;

    use crate::asn::AsnDb;
    use crate::flow::{ExtractedFlow, ipfix, v9};
    use crate::pipeline::WindowManager;

    // AF_XDP constants (from linux/if_xdp.h)
    const AF_XDP: i32 = 44;
    const SOL_XDP: i32 = 283;
    const XDP_UMEM_REG: i32 = 1;
    const XDP_UMEM_FILL_RING: i32 = 3;
    const XDP_UMEM_COMPLETION_RING: i32 = 4;
    const XDP_RX_RING: i32 = 2;
    const XDP_MMAP_OFFSETS: i32 = 1;

    const XDP_PGOFF_RX_RING: u64 = 0;
    const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x100000000;

    const FRAME_SIZE: usize = 2048;
    const NUM_FRAMES: usize = 4096;
    const FILL_RING_SIZE: u32 = 2048;
    const COMP_RING_SIZE: u32 = 2048;
    const RX_RING_SIZE: u32 = 2048;

    // Frame parser constants are at module level (for testability)

    #[repr(C)]
    struct XdpUmemReg {
        addr: u64,
        len: u64,
        chunk_size: u32,
        headroom: u32,
        flags: u32,
    }

    #[repr(C)]
    struct SockaddrXdp {
        sxdp_family: u16,
        sxdp_flags: u16,
        sxdp_ifindex: u32,
        sxdp_queue_id: u32,
        sxdp_shared_umem_fd: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct XdpRingOffset {
        producer: u64,
        consumer: u64,
        desc: u64,
        flags: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct XdpMmapOffsets {
        rx: XdpRingOffset,
        tx: XdpRingOffset,
        fr: XdpRingOffset, // fill ring
        cr: XdpRingOffset, // completion ring
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct XdpDesc {
        addr: u64,
        len: u32,
        options: u32,
    }

    /// A single AF_XDP socket with its UMEM and rings.
    struct XskSocket {
        fd: i32,
        umem: *mut u8,
        umem_size: usize,
        // Ring pointers (mmap'd)
        rx_producer: *mut u32,
        rx_consumer: *mut u32,
        rx_ring: *mut XdpDesc,
        rx_ring_mask: u32,
        fill_producer: *mut u32,
        _fill_consumer: *mut u32,
        fill_ring: *mut u64,
        fill_ring_mask: u32,
    }

    // Safety: XskSocket is used within a single thread
    unsafe impl Send for XskSocket {}

    impl XskSocket {
        fn create(ifindex: u32, queue_id: u32) -> Result<Self, Box<dyn std::error::Error>> {
            unsafe {
                // Create AF_XDP socket
                let fd = libc::socket(AF_XDP, libc::SOCK_RAW, 0);
                if fd < 0 {
                    return Err(
                        format!("socket(AF_XDP): {}", std::io::Error::last_os_error()).into(),
                    );
                }

                // Allocate UMEM (page-aligned)
                let umem_size = NUM_FRAMES * FRAME_SIZE;
                let umem = libc::mmap(
                    std::ptr::null_mut(),
                    umem_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                    -1,
                    0,
                ) as *mut u8;
                if umem == libc::MAP_FAILED as *mut u8 {
                    libc::close(fd);
                    return Err("mmap UMEM failed".into());
                }

                // Register UMEM
                let reg = XdpUmemReg {
                    addr: umem as u64,
                    len: umem_size as u64,
                    chunk_size: FRAME_SIZE as u32,
                    headroom: 0,
                    flags: 0,
                };
                if libc::setsockopt(
                    fd,
                    SOL_XDP,
                    XDP_UMEM_REG,
                    &reg as *const _ as *const libc::c_void,
                    std::mem::size_of::<XdpUmemReg>() as u32,
                ) < 0
                {
                    libc::munmap(umem as *mut libc::c_void, umem_size);
                    libc::close(fd);
                    return Err(format!(
                        "setsockopt XDP_UMEM_REG: {}",
                        std::io::Error::last_os_error()
                    )
                    .into());
                }

                // Set ring sizes
                let fill_size = FILL_RING_SIZE;
                let comp_size = COMP_RING_SIZE;
                let rx_size = RX_RING_SIZE;
                for (opt, val) in [
                    (XDP_UMEM_FILL_RING, &fill_size),
                    (XDP_UMEM_COMPLETION_RING, &comp_size),
                    (XDP_RX_RING, &rx_size),
                ] {
                    if libc::setsockopt(fd, SOL_XDP, opt, val as *const _ as *const libc::c_void, 4)
                        < 0
                    {
                        libc::munmap(umem as *mut libc::c_void, umem_size);
                        libc::close(fd);
                        return Err(format!(
                            "setsockopt ring size (opt={opt}): {}",
                            std::io::Error::last_os_error()
                        )
                        .into());
                    }
                }

                // Get mmap offsets
                let mut offsets: XdpMmapOffsets = std::mem::zeroed();
                let mut optlen = std::mem::size_of::<XdpMmapOffsets>() as u32;
                if libc::getsockopt(
                    fd,
                    SOL_XDP,
                    XDP_MMAP_OFFSETS,
                    &mut offsets as *mut _ as *mut libc::c_void,
                    &mut optlen,
                ) < 0
                {
                    libc::munmap(umem as *mut libc::c_void, umem_size);
                    libc::close(fd);
                    return Err(format!(
                        "getsockopt XDP_MMAP_OFFSETS: {}",
                        std::io::Error::last_os_error()
                    )
                    .into());
                }

                // mmap fill ring
                let fill_ring_size = offsets.fr.desc + FILL_RING_SIZE as u64 * 8;
                let fill_mmap = libc::mmap(
                    std::ptr::null_mut(),
                    fill_ring_size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_POPULATE,
                    fd,
                    XDP_UMEM_PGOFF_FILL_RING as i64,
                );
                if fill_mmap == libc::MAP_FAILED {
                    libc::munmap(umem as *mut libc::c_void, umem_size);
                    libc::close(fd);
                    return Err("mmap fill ring failed".into());
                }
                let fill_producer =
                    (fill_mmap as *mut u8).add(offsets.fr.producer as usize) as *mut u32;
                let fill_consumer =
                    (fill_mmap as *mut u8).add(offsets.fr.consumer as usize) as *mut u32;
                let fill_ring = (fill_mmap as *mut u8).add(offsets.fr.desc as usize) as *mut u64;

                // mmap RX ring
                let rx_ring_size =
                    offsets.rx.desc + RX_RING_SIZE as u64 * std::mem::size_of::<XdpDesc>() as u64;
                let rx_mmap = libc::mmap(
                    std::ptr::null_mut(),
                    rx_ring_size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_POPULATE,
                    fd,
                    XDP_PGOFF_RX_RING as i64,
                );
                if rx_mmap == libc::MAP_FAILED {
                    libc::munmap(umem as *mut libc::c_void, umem_size);
                    libc::close(fd);
                    return Err("mmap rx ring failed".into());
                }
                let rx_producer =
                    (rx_mmap as *mut u8).add(offsets.rx.producer as usize) as *mut u32;
                let rx_consumer =
                    (rx_mmap as *mut u8).add(offsets.rx.consumer as usize) as *mut u32;
                let rx_ring = (rx_mmap as *mut u8).add(offsets.rx.desc as usize) as *mut XdpDesc;

                // Pre-fill the fill ring with frame addresses
                for i in 0..FILL_RING_SIZE {
                    *fill_ring.add(i as usize) = (i as u64) * FRAME_SIZE as u64;
                }
                std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
                *fill_producer = FILL_RING_SIZE;

                // Bind to interface + queue
                let addr = SockaddrXdp {
                    sxdp_family: AF_XDP as u16,
                    sxdp_flags: 0, // XDP_COPY mode if zero-copy not supported
                    sxdp_ifindex: ifindex,
                    sxdp_queue_id: queue_id,
                    sxdp_shared_umem_fd: 0,
                };
                if libc::bind(
                    fd,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<SockaddrXdp>() as u32,
                ) < 0
                {
                    libc::munmap(umem as *mut libc::c_void, umem_size);
                    libc::close(fd);
                    return Err(format!(
                        "bind AF_XDP queue {queue_id}: {}",
                        std::io::Error::last_os_error()
                    )
                    .into());
                }

                Ok(XskSocket {
                    fd,
                    umem,
                    umem_size,
                    rx_producer,
                    rx_consumer,
                    rx_ring,
                    rx_ring_mask: RX_RING_SIZE - 1,
                    fill_producer,
                    _fill_consumer: fill_consumer,
                    fill_ring,
                    fill_ring_mask: FILL_RING_SIZE - 1,
                })
            }
        }

        /// Receive packets from the RX ring, returning (frame_addr, frame_len) pairs.
        /// Caller must call `complete_rx` after processing to return frames to the fill ring.
        fn poll_rx(&self, batch: &mut Vec<(u64, u32)>) {
            batch.clear();
            unsafe {
                std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
                let prod = *self.rx_producer;
                let cons = *self.rx_consumer;
                let available = prod.wrapping_sub(cons);
                if available == 0 {
                    return;
                }
                let n = available.min(64);
                for i in 0..n {
                    let idx = (cons.wrapping_add(i)) & self.rx_ring_mask;
                    let desc = *self.rx_ring.add(idx as usize);
                    batch.push((desc.addr, desc.len));
                }
                std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
                *self.rx_consumer = cons.wrapping_add(n);
            }
        }

        /// Return processed frames to the fill ring so the kernel can reuse them.
        fn complete_rx(&self, frames: &[(u64, u32)]) {
            unsafe {
                std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
                let prod = *self.fill_producer;
                for (i, &(addr, _)) in frames.iter().enumerate() {
                    let idx = (prod.wrapping_add(i as u32)) & self.fill_ring_mask;
                    *self.fill_ring.add(idx as usize) = addr;
                }
                std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
                *self.fill_producer = prod.wrapping_add(frames.len() as u32);
            }
        }

        /// Get a slice of UMEM at the given address.
        fn frame_data(&self, addr: u64, len: u32) -> &[u8] {
            unsafe { std::slice::from_raw_parts(self.umem.add(addr as usize), len as usize) }
        }
    }

    impl Drop for XskSocket {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
                libc::munmap(self.umem as *mut libc::c_void, self.umem_size);
            }
        }
    }

    // parse_frame is defined at module level for testability

    /// Get the number of RX queues for a network interface.
    fn get_rx_queue_count(ifname: &str) -> Result<u32, Box<dyn std::error::Error>> {
        let path = format!("/sys/class/net/{ifname}/queues");
        let mut count = 0u32;
        for entry in std::fs::read_dir(&path)? {
            let name = entry?.file_name();
            if name.to_string_lossy().starts_with("rx-") {
                count += 1;
            }
        }
        if count == 0 {
            return Err(format!("no RX queues found for {ifname} at {path}").into());
        }
        Ok(count)
    }

    /// Get the interface index from name.
    fn ifindex(ifname: &str) -> Result<u32, Box<dyn std::error::Error>> {
        let c_name = std::ffi::CString::new(ifname)?;
        let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if idx == 0 {
            return Err(format!("interface {ifname} not found").into());
        }
        Ok(idx)
    }

    /// Set up and spawn AF_XDP listener threads.
    pub fn spawn_xdp_listeners(
        ifname: &str,
        flow_port: u16,
        asn_db: Arc<ArcSwap<AsnDb>>,
        windows: Arc<WindowManager>,
    ) -> Result<Vec<std::thread::JoinHandle<()>>, Box<dyn std::error::Error + Send + Sync>> {
        let if_idx = ifindex(ifname).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("interface lookup: {e}").into()
        })?;
        let queue_count = get_rx_queue_count(ifname).map_err(
            |e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("queue detection: {e}").into()
            },
        )?;

        tracing::info!("AF_XDP: interface {ifname} (index {if_idx}), {queue_count} RX queues");

        // Load the BPF program
        let bpf_bytes = load_bpf_bytes()?;
        let mut bpf =
            Ebpf::load(&bpf_bytes).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("BPF load: {e}").into()
            })?;

        // Attach XDP program to the interface
        let program: &mut Xdp = bpf
            .program_mut("xdp_redirect_udp2055")
            .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
                "BPF program 'xdp_redirect_udp2055' not found".into()
            })?
            .try_into()
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("XDP program cast: {e}").into()
            })?;

        program
            .load()
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("XDP program load: {e}").into()
            })?;

        // Try native XDP first, fall back to SKB (generic) mode
        let attach_result = program.attach(ifname, XdpFlags::default()).or_else(|_| {
            tracing::warn!("AF_XDP: native XDP attach failed, trying SKB (generic) mode");
            program.attach(ifname, XdpFlags::SKB_MODE)
        });
        let _link_id = attach_result.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("XDP attach to {ifname}: {e}").into()
        })?;

        tracing::info!("AF_XDP: XDP program attached to {ifname}");

        // Write the target port into the BPF map
        {
            use aya::maps::Array;
            let mut port_map: Array<_, u16> =
                Array::try_from(bpf.map_mut("target_port").ok_or_else(
                    || -> Box<dyn std::error::Error + Send + Sync> {
                        "target_port map not found in BPF".into()
                    },
                )?)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("target_port Array: {e}").into()
                })?;
            port_map.set(0, flow_port, 0).map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("target_port set: {e}").into()
                },
            )?;
            tracing::info!("AF_XDP: target port set to {flow_port}");
        }

        // Create XSK sockets and register them in the XskMap
        let mut xsk_map = XskMap::try_from(bpf.map_mut("xsks_map").ok_or_else(
            || -> Box<dyn std::error::Error + Send + Sync> { "xsks_map not found in BPF".into() },
        )?)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("XskMap: {e}").into()
        })?;

        let mut handles = Vec::with_capacity(queue_count as usize);

        for queue_id in 0..queue_count {
            let xsk = XskSocket::create(if_idx, queue_id).map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("XSK queue {queue_id}: {e}").into()
                },
            )?;

            // Register this socket's FD in the BPF map so the XDP program can redirect to it
            xsk_map.set(queue_id, xsk.fd, 0).map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("xsk_map.set({queue_id}): {e}").into()
                },
            )?;

            tracing::info!("AF_XDP: XSK socket created for queue {queue_id}");

            let asn_db = asn_db.clone();
            let windows = windows.clone();
            let handle = std::thread::Builder::new()
                .name(format!("xdp-listener-{queue_id}"))
                .spawn(move || xdp_listener_loop(xsk, asn_db, windows))
                .expect("failed to spawn XDP listener thread");
            handles.push(handle);
        }

        // Leak the BPF object so the program stays attached
        std::mem::forget(bpf);

        Ok(handles)
    }

    mod bpf_embedded {
        include!(concat!(env!("OUT_DIR"), "/bpf_bytes.rs"));
    }

    fn load_bpf_bytes() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        bpf_embedded::BPF_BYTES
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| {
                "BPF program was not compiled into this binary. \
                 Ensure clang is installed at build time."
                    .into()
            })
    }

    fn xdp_listener_loop(xsk: XskSocket, asn_db: Arc<ArcSwap<AsnDb>>, windows: Arc<WindowManager>) {
        let mut v9_parser = v9::V9Parser::new();
        let mut ipfix_parser = ipfix::IpfixParser::new();
        let mut flows: Vec<ExtractedFlow> = Vec::with_capacity(64);
        let mut batch: Vec<(u64, u32)> = Vec::with_capacity(64);

        // Set up poll fd for blocking when no packets
        let mut pollfd = libc::pollfd {
            fd: xsk.fd,
            events: libc::POLLIN,
            revents: 0,
        };

        loop {
            // Poll with 100ms timeout to avoid busy spinning
            let ret = unsafe { libc::poll(&mut pollfd, 1, 100) };
            if ret <= 0 {
                continue;
            }

            xsk.poll_rx(&mut batch);
            if batch.is_empty() {
                continue;
            }

            let db = asn_db.load();
            let current = windows.current.load();

            for &(addr, len) in &batch {
                let frame = xsk.frame_data(addr, len);
                if let Some((payload, src_ip)) = crate::flow::xdp::parse_frame(frame) {
                    crate::flow::listener::process_packet(
                        payload,
                        src_ip,
                        &mut v9_parser,
                        &mut ipfix_parser,
                        &mut flows,
                        &db,
                        &current,
                    );
                }
            }

            // Return frames to fill ring
            xsk.complete_rx(&batch);
        }
    }
}

// --- Frame parser (used by AF_XDP receive path, testable independently) ---

const ETH_HLEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_8021Q: u16 = 0x8100;

/// Parse Ethernet+IP+UDP headers from a raw frame.
/// Returns the UDP payload (NetFlow data) and the source IP address.
fn parse_frame(frame: &[u8]) -> Option<(&[u8], std::net::IpAddr)> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    if frame.len() < ETH_HLEN + 20 + 8 {
        return None;
    }

    let mut offset = ETH_HLEN;
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    // Skip VLAN tag (802.1Q)
    if ethertype == ETH_P_8021Q {
        if frame.len() < offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }

    let src_ip;
    match ethertype {
        ETH_P_IP => {
            if frame.len() < offset + 20 {
                return None;
            }
            let ihl = (frame[offset] & 0x0F) as usize * 4;
            src_ip = IpAddr::V4(Ipv4Addr::new(
                frame[offset + 12],
                frame[offset + 13],
                frame[offset + 14],
                frame[offset + 15],
            ));
            offset += ihl;
        }
        ETH_P_IPV6 => {
            if frame.len() < offset + 40 {
                return None;
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&frame[offset + 8..offset + 24]);
            src_ip = IpAddr::V6(Ipv6Addr::from(addr));
            offset += 40;
        }
        _ => return None,
    }

    // Skip UDP header (8 bytes)
    if frame.len() < offset + 8 {
        return None;
    }
    offset += 8;

    Some((&frame[offset..], src_ip))
}

// --- Public API ---

/// Check if the kernel supports AF_XDP sockets.
pub fn probe_af_xdp() -> bool {
    let fd = unsafe { libc::socket(44, libc::SOCK_RAW, 0) };
    if fd >= 0 {
        unsafe { libc::close(fd) };
        true
    } else {
        false
    }
}

/// Get the XDP interface from environment, if configured.
pub fn xdp_interface() -> Option<String> {
    std::env::var("NETRA_XDP_IFACE")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Log AF_XDP availability and configuration status at startup.
pub fn log_xdp_status() {
    let kernel_support = probe_af_xdp();
    let interface = xdp_interface();

    if kernel_support {
        tracing::info!("AF_XDP: kernel support detected");
    } else {
        tracing::info!("AF_XDP: not supported (need root/CAP_NET_ADMIN + kernel >= 5.4)");
    }

    match interface {
        Some(ref iface) if kernel_support => {
            tracing::info!("AF_XDP: NETRA_XDP_IFACE={iface}, will attempt AF_XDP mode");
        }
        Some(ref iface) => {
            tracing::warn!(
                "AF_XDP: NETRA_XDP_IFACE={iface} set but kernel support unavailable, \
                 will fall back to recvmmsg"
            );
        }
        None => {
            tracing::info!("AF_XDP: not configured (set NETRA_XDP_IFACE=<iface> to enable)");
        }
    }
}

/// Try to spawn AF_XDP listeners. Returns Ok(handles) on success, Err on failure.
pub fn try_spawn_xdp(
    ifname: &str,
    flow_port: u16,
    asn_db: std::sync::Arc<arc_swap::ArcSwap<crate::asn::AsnDb>>,
    windows: std::sync::Arc<crate::pipeline::WindowManager>,
) -> Result<Vec<std::thread::JoinHandle<()>>, Box<dyn std::error::Error + Send + Sync>> {
    imp::spawn_xdp_listeners(ifname, flow_port, asn_db, windows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Build a minimal Ethernet + IPv4 + UDP frame with the given payload.
    fn build_ipv4_udp_frame(src_ip: Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        // Ethernet: dst(6) + src(6) + ethertype(2)
        frame.extend_from_slice(&[0xffu8; 6]); // dst mac
        frame.extend_from_slice(&[0x00u8; 6]); // src mac
        frame.extend_from_slice(&ETH_P_IP.to_be_bytes()); // ethertype

        // IPv4 header (20 bytes, IHL=5)
        let total_len = 20u16 + 8 + payload.len() as u16;
        frame.push(0x45); // version=4, ihl=5
        frame.push(0); // tos
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0; 4]); // id, flags, frag
        frame.push(64); // ttl
        frame.push(17); // protocol = UDP
        frame.extend_from_slice(&[0; 2]); // checksum
        frame.extend_from_slice(&src_ip.octets()); // src ip
        frame.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets()); // dst ip

        // UDP header (8 bytes)
        frame.extend_from_slice(&12345u16.to_be_bytes()); // src port
        frame.extend_from_slice(&dst_port.to_be_bytes()); // dst port
        let udp_len = 8u16 + payload.len() as u16;
        frame.extend_from_slice(&udp_len.to_be_bytes());
        frame.extend_from_slice(&[0; 2]); // checksum

        frame.extend_from_slice(payload);
        frame
    }

    fn build_ipv6_udp_frame(src_ip: Ipv6Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        // Ethernet
        frame.extend_from_slice(&[0xff; 6]); // dst mac
        frame.extend_from_slice(&[0x00; 6]); // src mac
        frame.extend_from_slice(&ETH_P_IPV6.to_be_bytes());

        // IPv6 header (40 bytes)
        frame.extend_from_slice(&[0x60, 0, 0, 0]); // version + flow label
        let payload_len = 8u16 + payload.len() as u16;
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.push(17); // next header = UDP
        frame.push(64); // hop limit
        frame.extend_from_slice(&src_ip.octets()); // src
        frame.extend_from_slice(&Ipv6Addr::LOCALHOST.octets()); // dst

        // UDP header
        frame.extend_from_slice(&12345u16.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        let udp_len = 8u16 + payload.len() as u16;
        frame.extend_from_slice(&udp_len.to_be_bytes());
        frame.extend_from_slice(&[0; 2]);

        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn parse_ipv4_udp_frame() {
        let payload = b"hello netflow";
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let frame = build_ipv4_udp_frame(src, 2055, payload);

        let (data, ip) = parse_frame(&frame).expect("should parse");
        assert_eq!(ip, IpAddr::V4(src));
        assert_eq!(data, payload);
    }

    #[test]
    fn parse_ipv6_udp_frame() {
        let payload = b"hello ipfix";
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let frame = build_ipv6_udp_frame(src, 2055, payload);

        let (data, ip) = parse_frame(&frame).expect("should parse");
        assert_eq!(ip, IpAddr::V6(src));
        assert_eq!(data, payload);
    }

    #[test]
    fn parse_vlan_tagged_frame() {
        let payload = b"vlan data";
        let src = Ipv4Addr::new(10, 0, 0, 5);
        let inner = build_ipv4_udp_frame(src, 2055, payload);

        // Replace ethertype with 802.1Q and insert VLAN tag
        let mut frame = Vec::new();
        frame.extend_from_slice(&inner[..12]); // dst + src mac
        frame.extend_from_slice(&ETH_P_8021Q.to_be_bytes()); // 802.1Q
        frame.extend_from_slice(&[0x00, 0x64]); // VLAN TCI (VLAN 100)
        frame.extend_from_slice(&inner[12..]); // original ethertype + rest

        let (data, ip) = parse_frame(&frame).expect("should parse VLAN frame");
        assert_eq!(ip, IpAddr::V4(src));
        assert_eq!(data, payload);
    }

    #[test]
    fn parse_too_short_returns_none() {
        assert!(parse_frame(&[0; 10]).is_none());
    }

    #[test]
    fn parse_non_ip_returns_none() {
        let mut frame = vec![0u8; 60];
        // Set ethertype to ARP (0x0806)
        frame[12] = 0x08;
        frame[13] = 0x06;
        assert!(parse_frame(&frame).is_none());
    }

    #[test]
    fn parse_extracts_correct_payload_offset() {
        // Verify the payload starts right after the 8-byte UDP header
        let payload = b"NETFLOW_DATA_HERE";
        let frame = build_ipv4_udp_frame(Ipv4Addr::new(1, 2, 3, 4), 2055, payload);
        let (data, _) = parse_frame(&frame).unwrap();
        assert_eq!(data.len(), payload.len());
        assert_eq!(&data[..7], b"NETFLOW");
    }
}
