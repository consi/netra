use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{ExtractedFlow, ParseError, read_u16, read_u32};

const SFLOW_VERSION: u32 = 5;
const ADDR_IPV4: u32 = 1;
const ADDR_IPV6: u32 = 2;

/// Compact flow sample (enterprise 0, format 1).
const SAMPLE_FLOW: u32 = 1;
/// Expanded flow sample (enterprise 0, format 3). What the live exporters send.
const SAMPLE_FLOW_EXPANDED: u32 = 3;

/// Raw packet header.
const REC_HEADER: u32 = 1;
/// Extended switch data: src/dst VLAN.
const REC_SWITCH: u32 = 1001;

const HDR_ETHERNET: u32 = 1;
const HDR_IPV4: u32 = 11;
const HDR_IPV6: u32 = 12;

/// Parse an sFlow v5 datagram, appending one [`ExtractedFlow`] per sampled packet.
///
/// Counter samples are skipped. Bytes and packets are scaled by the sample's
/// sampling rate so the window sees estimated wire volume, matching NetFlow's
/// sampling multiplier. Layer-3 length comes from the IP header.
///
/// Switches that sample both ingress and egress (Nexus and similar) export two
/// samples of the same traffic. The egress sample is dropped when the ingress
/// port is known, so each packet is counted once.
pub fn parse_into(data: &[u8], flows: &mut Vec<ExtractedFlow>) -> Result<(), ParseError> {
    if data.len() < 8 {
        return Err(ParseError::TooShort);
    }
    let version = read_u32(data, 0);
    if version != SFLOW_VERSION {
        return Err(ParseError::BadVersion(version.min(u16::MAX as u32) as u16));
    }

    let addr_type = read_u32(data, 4);
    let addr_len = match addr_type {
        ADDR_IPV4 => 4,
        ADDR_IPV6 => 16,
        _ => return Err(ParseError::MalformedTemplate),
    };
    // version + addr type + agent address + sub-agent + seq + uptime + num samples
    let header_len = 8 + addr_len + 16;
    if data.len() < header_len {
        return Err(ParseError::Truncated);
    }

    let num_samples = read_u32(data, header_len - 4) as usize;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let mut offset = header_len;
    for _ in 0..num_samples {
        if data.len() < offset + 8 {
            break;
        }
        let tag = read_u32(data, offset);
        let sample_len = read_u32(data, offset + 4) as usize;
        offset += 8;
        if data.len() < offset + sample_len {
            break;
        }
        let sample = &data[offset..offset + sample_len];
        offset += sample_len;

        let enterprise = tag >> 12;
        let format = tag & 0xfff;
        if enterprise != 0 {
            continue;
        }
        if format == SAMPLE_FLOW || format == SAMPLE_FLOW_EXPANDED {
            parse_flow_sample(sample, format, now_ms, flows);
        }
    }

    Ok(())
}

/// Egress sample of a packet whose ingress port is also known.
/// The ingress sample accounts for that packet; counting this one too doubles it.
fn is_egress_duplicate(
    source_type: u32,
    source_index: u32,
    in_fmt: u32,
    in_val: u32,
    out_fmt: u32,
    out_val: u32,
) -> bool {
    source_type == 0
        && in_fmt == 0
        && out_fmt == 0
        && in_val != 0
        && source_index == out_val
        && source_index != in_val
}

fn parse_flow_sample(sample: &[u8], format: u32, now_ms: u64, flows: &mut Vec<ExtractedFlow>) {
    // Compact: 8×u32, sampling rate at byte 8, records follow byte 32.
    // Expanded: 11×u32, sampling rate at byte 12, records follow byte 44.
    let (rate_off, records_off, source_type, source_index, in_fmt, in_val, out_fmt, out_val) =
        match format {
            SAMPLE_FLOW => {
                if sample.len() < 32 {
                    return;
                }
                let source = read_u32(sample, 4);
                let input = read_u32(sample, 20);
                let output = read_u32(sample, 24);
                (
                    8,
                    32,
                    source >> 24,
                    source & 0x00ff_ffff,
                    input >> 30,
                    input & 0x3fff_ffff,
                    output >> 30,
                    output & 0x3fff_ffff,
                )
            }
            SAMPLE_FLOW_EXPANDED => {
                if sample.len() < 44 {
                    return;
                }
                (
                    12,
                    44,
                    read_u32(sample, 4),
                    read_u32(sample, 8),
                    read_u32(sample, 24),
                    read_u32(sample, 28),
                    read_u32(sample, 32),
                    read_u32(sample, 36),
                )
            }
            _ => return,
        };

    if is_egress_duplicate(source_type, source_index, in_fmt, in_val, out_fmt, out_val) {
        return;
    }

    let sampling_rate = read_u32(sample, rate_off);
    let rate = if sampling_rate == 0 {
        1
    } else {
        sampling_rate as u64
    };
    let nrec = read_u32(sample, records_off - 4) as usize;

    let mut src_ip = None;
    let mut dst_ip = None;
    let mut vlan_id = 0u16;
    let mut l3_len = 0u64;

    let mut off = records_off;
    for _ in 0..nrec {
        if sample.len() < off + 8 {
            return;
        }
        let tag = read_u32(sample, off);
        let rec_len = read_u32(sample, off + 4) as usize;
        off += 8;
        if sample.len() < off + rec_len {
            return;
        }
        let rec = &sample[off..off + rec_len];
        off += rec_len;

        if tag >> 12 != 0 {
            continue;
        }
        match tag & 0xfff {
            REC_HEADER => {
                if src_ip.is_some() {
                    continue;
                }
                if let Some(parsed) = parse_header(rec) {
                    src_ip = Some(parsed.src);
                    dst_ip = Some(parsed.dst);
                    l3_len = parsed.l3_len;
                    if parsed.vlan_id != 0 {
                        vlan_id = parsed.vlan_id;
                    }
                }
            }
            REC_SWITCH if vlan_id == 0 && rec.len() >= 4 => {
                vlan_id = (read_u32(rec, 0) & 0x0fff) as u16;
            }
            _ => {}
        }
    }

    let (Some(src_ip), Some(dst_ip)) = (src_ip, dst_ip) else {
        return;
    };
    if l3_len == 0 {
        return;
    }

    flows.push(ExtractedFlow {
        dst_ip,
        src_ip,
        vlan_id,
        byte_count: l3_len.saturating_mul(rate),
        packet_count: rate,
        flow_start_ms: now_ms,
        flow_end_ms: now_ms,
    });
}

struct ParsedHeader {
    src: IpAddr,
    dst: IpAddr,
    vlan_id: u16,
    l3_len: u64,
}

fn parse_header(rec: &[u8]) -> Option<ParsedHeader> {
    if rec.len() < 16 {
        return None;
    }
    let protocol = read_u32(rec, 0);
    let header_len = read_u32(rec, 12) as usize;
    if rec.len() < 16 + header_len {
        return None;
    }
    let header = &rec[16..16 + header_len];

    let (src, dst, vlan_id, l3_len) = match protocol {
        HDR_ETHERNET => parse_ethernet(header)?,
        HDR_IPV4 => {
            let (s, d, l) = parse_ipv4(header)?;
            (s, d, 0, l)
        }
        HDR_IPV6 => {
            let (s, d, l) = parse_ipv6(header)?;
            (s, d, 0, l)
        }
        _ => return None,
    };

    Some(ParsedHeader {
        src,
        dst,
        vlan_id,
        l3_len,
    })
}

fn parse_ethernet(header: &[u8]) -> Option<(IpAddr, IpAddr, u16, u64)> {
    if header.len() < 14 {
        return None;
    }
    let mut offset = 12;
    let mut ethertype = read_u16(header, offset);
    offset += 2;
    let mut vlan_id = 0u16;

    // 802.1Q / QinQ. Keep the outermost tag; that is the VLAN the exporter stamped.
    for _ in 0..2 {
        if !matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
            break;
        }
        if header.len() < offset + 4 {
            return None;
        }
        let tci = read_u16(header, offset);
        if vlan_id == 0 {
            vlan_id = tci & 0x0fff;
        }
        ethertype = read_u16(header, offset + 2);
        offset += 4;
    }

    let (src, dst, l3_len) = match ethertype {
        0x0800 => parse_ipv4(&header[offset..])?,
        0x86DD => parse_ipv6(&header[offset..])?,
        _ => return None,
    };
    Some((src, dst, vlan_id, l3_len))
}

fn parse_ipv4(header: &[u8]) -> Option<(IpAddr, IpAddr, u64)> {
    if header.len() < 20 || header[0] >> 4 != 4 {
        return None;
    }
    let total_len = read_u16(header, 2) as u64;
    if total_len < 20 {
        return None;
    }
    let src = IpAddr::V4(Ipv4Addr::new(
        header[12], header[13], header[14], header[15],
    ));
    let dst = IpAddr::V4(Ipv4Addr::new(
        header[16], header[17], header[18], header[19],
    ));
    Some((src, dst, total_len))
}

fn parse_ipv6(header: &[u8]) -> Option<(IpAddr, IpAddr, u64)> {
    if header.len() < 40 || header[0] >> 4 != 6 {
        return None;
    }
    let payload_len = read_u16(header, 4) as u64;
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&header[8..24]);
    dst.copy_from_slice(&header[24..40]);
    Some((
        IpAddr::V6(Ipv6Addr::from(src)),
        IpAddr::V6(Ipv6Addr::from(dst)),
        payload_len + 40,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Ethernet + 802.1Q + IPv4 header, the shape seen on UDP/6343.
    fn ethernet_ipv4_header(vlan: u16, src: [u8; 4], dst: [u8; 4], ip_len: u16) -> Vec<u8> {
        let mut h = vec![0u8; 12];
        h.extend_from_slice(&0x8100u16.to_be_bytes());
        h.extend_from_slice(&vlan.to_be_bytes());
        h.extend_from_slice(&0x0800u16.to_be_bytes());
        h.push(0x45);
        h.push(0);
        h.extend_from_slice(&ip_len.to_be_bytes());
        h.extend_from_slice(&[0u8; 8]);
        h.extend_from_slice(&src);
        h.extend_from_slice(&dst);
        h
    }

    fn header_record(header: &[u8]) -> Vec<u8> {
        let mut rec = Vec::new();
        push_u32(&mut rec, HDR_ETHERNET);
        push_u32(&mut rec, header.len() as u32);
        push_u32(&mut rec, 4);
        push_u32(&mut rec, header.len() as u32);
        rec.extend_from_slice(header);
        let pad = (4 - header.len() % 4) % 4;
        rec.extend(std::iter::repeat_n(0, pad));
        rec
    }

    fn expanded_sample_on(
        rate: u32,
        source: u32,
        input: u32,
        output: u32,
        records: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut sample = Vec::new();
        push_u32(&mut sample, 1); // sequence
        push_u32(&mut sample, 0); // source id type
        push_u32(&mut sample, source);
        push_u32(&mut sample, rate);
        push_u32(&mut sample, 0); // pool
        push_u32(&mut sample, 0); // drops
        push_u32(&mut sample, 0); // input format
        push_u32(&mut sample, input);
        push_u32(&mut sample, 0); // output format
        push_u32(&mut sample, output);
        push_u32(&mut sample, records.len() as u32);
        for rec in records {
            push_u32(&mut sample, REC_HEADER);
            push_u32(&mut sample, rec.len() as u32);
            sample.extend_from_slice(rec);
        }
        sample
    }

    fn expanded_sample(rate: u32, records: &[Vec<u8>]) -> Vec<u8> {
        // Ingress sample: source is the input port.
        expanded_sample_on(rate, 1, 1, 2, records)
    }

    fn datagram(samples: &[Vec<u8>]) -> Vec<u8> {
        let mut pkt = Vec::new();
        push_u32(&mut pkt, SFLOW_VERSION);
        push_u32(&mut pkt, ADDR_IPV4);
        pkt.extend_from_slice(&[192, 0, 2, 10]);
        push_u32(&mut pkt, 100); // sub-agent
        push_u32(&mut pkt, 1); // sequence
        push_u32(&mut pkt, 1_000); // uptime
        push_u32(&mut pkt, samples.len() as u32);
        for sample in samples {
            push_u32(&mut pkt, SAMPLE_FLOW_EXPANDED);
            push_u32(&mut pkt, sample.len() as u32);
            pkt.extend_from_slice(sample);
        }
        pkt
    }

    #[test]
    fn expanded_sample_scales_bytes_and_keeps_vlan() {
        let header = ethernet_ipv4_header(100, [192, 0, 2, 1], [198, 51, 100, 1], 1440);
        let rec = header_record(&header);
        let sample = expanded_sample(4096, &[rec]);
        let pkt = datagram(&[sample]);

        let mut flows = Vec::new();
        parse_into(&pkt, &mut flows).unwrap();

        assert_eq!(flows.len(), 1);
        let flow = &flows[0];
        assert_eq!(flow.src_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));
        assert_eq!(flow.vlan_id, 100);
        assert_eq!(flow.byte_count, 1440 * 4096);
        assert_eq!(flow.packet_count, 4096);
        assert_eq!(flow.flow_start_ms, flow.flow_end_ms);
    }

    #[test]
    fn counter_sample_is_ignored() {
        let header = ethernet_ipv4_header(200, [1, 2, 3, 4], [5, 6, 7, 8], 100);
        let flow_sample = expanded_sample(1, &[header_record(&header)]);
        let mut counter = Vec::new();
        push_u32(&mut counter, 0); // sequence
        push_u32(&mut counter, 1); // source id type
        push_u32(&mut counter, 1); // source id
        push_u32(&mut counter, 0); // records

        let mut pkt = Vec::new();
        push_u32(&mut pkt, SFLOW_VERSION);
        push_u32(&mut pkt, ADDR_IPV4);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        push_u32(&mut pkt, 1);
        push_u32(&mut pkt, 1);
        push_u32(&mut pkt, 1);
        push_u32(&mut pkt, 2);
        push_u32(&mut pkt, 4); // expanded counter sample
        push_u32(&mut pkt, counter.len() as u32);
        pkt.extend_from_slice(&counter);
        push_u32(&mut pkt, SAMPLE_FLOW_EXPANDED);
        push_u32(&mut pkt, flow_sample.len() as u32);
        pkt.extend_from_slice(&flow_sample);

        let mut flows = Vec::new();
        parse_into(&pkt, &mut flows).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].vlan_id, 200);
        assert_eq!(flows[0].byte_count, 100);
    }

    #[test]
    fn switch_record_supplies_vlan_when_frame_is_untagged() {
        let mut header = vec![0u8; 12];
        header.extend_from_slice(&0x0800u16.to_be_bytes());
        header.push(0x45);
        header.push(0);
        header.extend_from_slice(&60u16.to_be_bytes());
        header.extend_from_slice(&[0u8; 8]);
        header.extend_from_slice(&[8, 8, 8, 8]);
        header.extend_from_slice(&[9, 9, 9, 9]);

        let rec = header_record(&header);
        let mut switch_rec = Vec::new();
        push_u32(&mut switch_rec, 300); // src vlan
        push_u32(&mut switch_rec, 0);
        push_u32(&mut switch_rec, 300);
        push_u32(&mut switch_rec, 0);

        let mut sample = Vec::new();
        push_u32(&mut sample, 1);
        push_u32(&mut sample, 0);
        push_u32(&mut sample, 1);
        push_u32(&mut sample, 10);
        push_u32(&mut sample, 0);
        push_u32(&mut sample, 0);
        push_u32(&mut sample, 0);
        push_u32(&mut sample, 1);
        push_u32(&mut sample, 0);
        push_u32(&mut sample, 2);
        push_u32(&mut sample, 2);
        push_u32(&mut sample, REC_HEADER);
        push_u32(&mut sample, rec.len() as u32);
        sample.extend_from_slice(&rec);
        push_u32(&mut sample, REC_SWITCH);
        push_u32(&mut sample, switch_rec.len() as u32);
        sample.extend_from_slice(&switch_rec);

        let pkt = datagram(&[sample]);
        let mut flows = Vec::new();
        parse_into(&pkt, &mut flows).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].vlan_id, 300);
        assert_eq!(flows[0].packet_count, 10);
        assert_eq!(flows[0].byte_count, 60 * 10);
    }

    #[test]
    fn egress_sample_is_not_counted_twice() {
        let header = ethernet_ipv4_header(200, [1, 1, 1, 1], [2, 2, 2, 2], 1000);
        let rec = header_record(&header);
        let ingress = expanded_sample_on(100, 10, 10, 20, &[rec.clone()]);
        let egress = expanded_sample_on(100, 20, 10, 20, &[rec]);
        let pkt = datagram(&[ingress, egress]);

        let mut flows = Vec::new();
        parse_into(&pkt, &mut flows).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].byte_count, 1000 * 100);
        assert_eq!(flows[0].vlan_id, 200);
    }

    #[test]
    fn rejects_short_datagram() {
        let err = parse_into(&[0, 0, 0, 5], &mut Vec::new()).unwrap_err();
        assert!(matches!(err, ParseError::TooShort));
    }
}
