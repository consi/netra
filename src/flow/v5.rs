use std::net::{IpAddr, Ipv4Addr};

use super::{ExtractedFlow, ParseError, read_u16, read_u32};

const HEADER_LEN: usize = 24;
const RECORD_LEN: usize = 48;

/// Parse a NetFlow v5 datagram, appending extracted flows into an existing Vec.
pub fn parse_into(data: &[u8], flows: &mut Vec<ExtractedFlow>) -> Result<(), ParseError> {
    if data.len() < HEADER_LEN {
        return Err(ParseError::TooShort);
    }

    let version = read_u16(data, 0);
    if version != 5 {
        return Err(ParseError::BadVersion(version));
    }

    let count = read_u16(data, 2) as usize;
    let sys_uptime = read_u32(data, 4) as u64; // ms since device boot
    let unix_secs = read_u32(data, 8) as u64;
    let unix_nsecs = read_u32(data, 12) as u64;

    let expected_len = HEADER_LEN + count * RECORD_LEN;
    if data.len() < expected_len {
        return Err(ParseError::Truncated);
    }

    // Wall-clock time in ms, then subtract uptime to get boot epoch in ms.
    let wall_ms = unix_secs * 1000 + unix_nsecs / 1_000_000;
    let boot_epoch_ms = wall_ms.wrapping_sub(sys_uptime);

    flows.reserve(count);

    for i in 0..count {
        let base = HEADER_LEN + i * RECORD_LEN;

        // src_addr at record offset 0
        let src_ip = Ipv4Addr::new(data[base], data[base + 1], data[base + 2], data[base + 3]);

        // dst_addr at record offset 4
        let dst_ip = Ipv4Addr::new(
            data[base + 4],
            data[base + 5],
            data[base + 6],
            data[base + 7],
        );

        let packet_count = read_u32(data, base + 16) as u64;
        let byte_count = read_u32(data, base + 20) as u64;
        let first_switched = read_u32(data, base + 24) as u64;
        let last_switched = read_u32(data, base + 28) as u64;

        // Handle uptime counter wrap: if first > last, treat as zero duration.
        let (start_ms, end_ms) = if first_switched > last_switched {
            (boot_epoch_ms + last_switched, boot_epoch_ms + last_switched)
        } else {
            (
                boot_epoch_ms + first_switched,
                boot_epoch_ms + last_switched,
            )
        };

        flows.push(ExtractedFlow {
            dst_ip: IpAddr::V4(dst_ip),
            src_ip: IpAddr::V4(src_ip),
            vlan_id: 1,
            byte_count,
            packet_count,
            flow_start_ms: start_ms,
            flow_end_ms: end_ms,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_v5_packet(
        count: u16,
        sys_uptime: u32,
        unix_secs: u32,
        unix_nsecs: u32,
        records: &[V5Record],
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&5u16.to_be_bytes()); // version
        pkt.extend_from_slice(&count.to_be_bytes()); // count
        pkt.extend_from_slice(&sys_uptime.to_be_bytes()); // sys_uptime
        pkt.extend_from_slice(&unix_secs.to_be_bytes()); // unix_secs
        pkt.extend_from_slice(&unix_nsecs.to_be_bytes()); // unix_nsecs
        pkt.extend_from_slice(&0u32.to_be_bytes()); // flow_sequence
        pkt.push(0); // engine_type
        pkt.push(0); // engine_id
        pkt.extend_from_slice(&0u16.to_be_bytes()); // sampling
        assert_eq!(pkt.len(), HEADER_LEN);

        for r in records {
            let rec_start = pkt.len();
            pkt.extend_from_slice(&r.src_addr.octets()); // 0: src_addr
            pkt.extend_from_slice(&r.dst_addr.octets()); // 4: dst_addr
            pkt.extend_from_slice(&[0u8; 4]); // 8: nexthop
            pkt.extend_from_slice(&0u16.to_be_bytes()); // 12: input
            pkt.extend_from_slice(&0u16.to_be_bytes()); // 14: output
            pkt.extend_from_slice(&r.d_pkts.to_be_bytes()); // 16: dPkts
            pkt.extend_from_slice(&r.d_octets.to_be_bytes()); // 20: dOctets
            pkt.extend_from_slice(&r.first.to_be_bytes()); // 24: first
            pkt.extend_from_slice(&r.last.to_be_bytes()); // 28: last
            pkt.extend_from_slice(&0u16.to_be_bytes()); // 32: src_port
            pkt.extend_from_slice(&0u16.to_be_bytes()); // 34: dst_port
            pkt.push(0); // 36: pad1
            pkt.push(0); // 37: tcp_flags
            pkt.push(6); // 38: prot (TCP)
            pkt.push(0); // 39: tos
            pkt.extend_from_slice(&0u16.to_be_bytes()); // 40: src_as
            pkt.extend_from_slice(&0u16.to_be_bytes()); // 42: dst_as
            pkt.push(0); // 44: src_mask
            pkt.push(0); // 45: dst_mask
            pkt.extend_from_slice(&0u16.to_be_bytes()); // 46: pad2
            assert_eq!(pkt.len() - rec_start, RECORD_LEN);
        }
        pkt
    }

    struct V5Record {
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
        d_pkts: u32,
        d_octets: u32,
        first: u32,
        last: u32,
    }

    #[test]
    fn test_parse_single_record() {
        let pkt = build_v5_packet(
            1,
            10_000,        // sys_uptime: 10s
            1_700_000_000, // unix_secs
            0,             // unix_nsecs
            &[V5Record {
                src_addr: Ipv4Addr::new(10, 0, 0, 1),
                dst_addr: Ipv4Addr::new(192, 168, 1, 1),
                d_pkts: 100,
                d_octets: 50_000,
                first: 5_000, // 5s after boot
                last: 9_000,  // 9s after boot
            }],
        );

        let mut flows = Vec::new();
        parse_into(&pkt, &mut flows).unwrap();
        assert_eq!(flows.len(), 1);

        let f = &flows[0];
        assert_eq!(f.dst_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(f.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(f.vlan_id, 1);
        assert_eq!(f.byte_count, 50_000);

        // boot_epoch_ms = 1_700_000_000_000 - 10_000 = 1_699_999_990_000
        // flow_start = boot_epoch_ms + 5000 = 1_699_999_995_000
        // flow_end   = boot_epoch_ms + 9000 = 1_699_999_999_000
        assert_eq!(f.flow_start_ms, 1_699_999_995_000);
        assert_eq!(f.flow_end_ms, 1_699_999_999_000);
    }

    #[test]
    fn test_too_short() {
        assert!(parse_into(&[0; 10], &mut Vec::new()).is_err());
    }

    #[test]
    fn test_bad_version() {
        let mut pkt = vec![0u8; HEADER_LEN];
        pkt[0] = 0;
        pkt[1] = 7; // version 7
        match parse_into(&pkt, &mut Vec::new()) {
            Err(ParseError::BadVersion(7)) => {}
            other => panic!("expected BadVersion(7), got {other:?}"),
        }
    }

    #[test]
    fn test_truncated() {
        // Header says 1 record but no record data follows
        let pkt = build_v5_packet(0, 0, 0, 0, &[]);
        // Manually set count to 1 to trigger truncation
        let mut pkt = pkt;
        pkt[2] = 0;
        pkt[3] = 1;
        match parse_into(&pkt, &mut Vec::new()) {
            Err(ParseError::Truncated) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn test_uptime_wrap() {
        // first > last → treat as zero-duration
        let pkt = build_v5_packet(
            1,
            60_000,
            1_700_000_000,
            0,
            &[V5Record {
                src_addr: Ipv4Addr::new(10, 0, 0, 1),
                dst_addr: Ipv4Addr::new(10, 0, 0, 2),
                d_pkts: 1,
                d_octets: 100,
                first: 50_000,
                last: 10_000, // wrapped
            }],
        );
        let mut flows = Vec::new();
        parse_into(&pkt, &mut flows).unwrap();
        assert_eq!(flows[0].flow_start_ms, flows[0].flow_end_ms);
    }
}
