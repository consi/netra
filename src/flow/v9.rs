use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{ExtractedFlow, ParseError, read_u16, read_u32, read_uint};

const HEADER_LEN: usize = 20;

// Field type IDs we care about.
const IN_BYTES: u16 = 1;
const IN_PACKETS: u16 = 2;
const IPV4_SRC_ADDR: u16 = 8;
const IPV4_DST_ADDR: u16 = 12;
const IPV6_SRC_ADDR: u16 = 27;
const IPV6_DST_ADDR: u16 = 28;
const LAST_SWITCHED: u16 = 21;
const FIRST_SWITCHED: u16 = 22;
const SAMPLING_INTERVAL: u16 = 34;
const SAMPLER_ID: u16 = 48;
const SAMPLER_RANDOM_INTERVAL: u16 = 50;
const SRC_VLAN: u16 = 58;
const DST_VLAN: u16 = 59;
const SELECTOR_ID: u16 = 302;
const SAMPLING_PACKET_INTERVAL: u16 = 305;
const SAMPLING_PACKET_SPACE: u16 = 306;

#[derive(Clone, Debug)]
struct FieldLoc {
    offset: usize,
    length: usize,
}

#[derive(Clone, Debug)]
struct ResolvedTemplate {
    record_len: usize,
    src_ipv4: Option<FieldLoc>,
    src_ipv6: Option<FieldLoc>,
    dst_ipv4: Option<FieldLoc>,
    dst_ipv6: Option<FieldLoc>,
    in_bytes: Option<FieldLoc>,
    in_packets: Option<FieldLoc>,
    first_switched: Option<FieldLoc>,
    last_switched: Option<FieldLoc>,
    src_vlan: Option<FieldLoc>,
    dst_vlan: Option<FieldLoc>,
    sampling_interval: Option<FieldLoc>,
    /// samplerId (48) or selectorId (302) — used to look up per-sampler rate.
    sampler_id: Option<FieldLoc>,
}

/// Describes the layout of an options template for extracting sampling interval.
#[derive(Clone, Debug)]
struct OptionsTemplate {
    record_len: usize,
    sampling_interval: Option<FieldLoc>,
    sampler_id: Option<FieldLoc>,
    sampling_packet_space: Option<FieldLoc>,
}

pub struct V9Parser {
    templates: HashMap<(IpAddr, u32, u16), ResolvedTemplate>,
    options_templates: HashMap<(IpAddr, u32, u16), OptionsTemplate>,
    /// Per-(exporter, source_id, sampler_id) sampling rate learned from options data.
    /// sampler_id=0 is the global/default rate.
    sampling_rates: HashMap<(IpAddr, u32, u64), u64>,
}

impl V9Parser {
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
            options_templates: HashMap::new(),
            sampling_rates: HashMap::new(),
        }
    }

    /// Parse a NetFlow v9 datagram, appending flows into an existing Vec.
    pub fn parse_into(
        &mut self,
        data: &[u8],
        exporter: IpAddr,
        flows: &mut Vec<ExtractedFlow>,
    ) -> Result<(), ParseError> {
        if data.len() < HEADER_LEN {
            return Err(ParseError::TooShort);
        }

        let version = read_u16(data, 0);
        if version != 9 {
            return Err(ParseError::BadVersion(version));
        }

        let _count = read_u16(data, 2); // number of records (across all flowsets)
        let sys_uptime = read_u32(data, 4) as u64;
        let unix_secs = read_u32(data, 8) as u64;
        let _sequence = read_u32(data, 12);
        let source_id = read_u32(data, 16);

        let wall_ms = unix_secs * 1000;
        let boot_epoch_ms = wall_ms.wrapping_sub(sys_uptime);

        let mut cursor = HEADER_LEN;

        while cursor + 4 <= data.len() {
            let flowset_id = read_u16(data, cursor);
            let flowset_length = read_u16(data, cursor + 2) as usize;

            // flowset_length includes the 4-byte header
            if flowset_length < 4 || cursor + flowset_length > data.len() {
                break; // malformed or truncated, stop processing
            }

            let flowset_end = cursor + flowset_length;

            match flowset_id {
                0 => {
                    // Template FlowSet
                    self.parse_template_flowset(
                        data,
                        cursor + 4,
                        flowset_end,
                        exporter,
                        source_id,
                    )?;
                }
                1 => {
                    // Options Template FlowSet
                    self.parse_options_template_flowset(
                        data,
                        cursor + 4,
                        flowset_end,
                        exporter,
                        source_id,
                    )?;
                }
                id if id >= 256 => {
                    // Data FlowSet — could be flow data or options data
                    let key = (exporter, source_id, id);
                    if let Some(opts_tmpl) = self.options_templates.get(&key).cloned() {
                        self.parse_options_data_flowset(
                            data,
                            cursor + 4,
                            flowset_end,
                            &opts_tmpl,
                            exporter,
                            source_id,
                        );
                    } else if let Some(tmpl) = self.templates.get(&key).cloned() {
                        self.parse_data_flowset(
                            data,
                            cursor + 4,
                            flowset_end,
                            &tmpl,
                            boot_epoch_ms,
                            exporter,
                            source_id,
                            flows,
                        );
                    }
                    // If template not found, silently skip.
                }
                _ => {
                    // Reserved flowset IDs 2-255: skip
                }
            }

            cursor = flowset_end;
        }

        Ok(())
    }

    fn parse_options_template_flowset(
        &mut self,
        data: &[u8],
        mut pos: usize,
        end: usize,
        exporter: IpAddr,
        source_id: u32,
    ) -> Result<(), ParseError> {
        // v9 Options Template format:
        //   template_id (2), option_scope_length (2), option_length (2)
        //   then scope fields (option_scope_length bytes of type/len pairs)
        //   then option fields (option_length bytes of type/len pairs)
        while pos + 6 <= end {
            let template_id = read_u16(data, pos);
            let scope_length = read_u16(data, pos + 2) as usize;
            let option_length = read_u16(data, pos + 4) as usize;
            pos += 6;

            let total_fields_bytes = scope_length + option_length;
            if pos + total_fields_bytes > end {
                return Err(ParseError::MalformedTemplate);
            }

            let mut sampling_loc: Option<FieldLoc> = None;
            let mut sampler_id_loc: Option<FieldLoc> = None;
            let mut sampling_space_loc: Option<FieldLoc> = None;
            let mut offset = 0usize;

            // Parse all fields (scope + option) as type(2)/length(2) pairs
            let fields_end = pos + total_fields_bytes;
            while pos + 4 <= fields_end {
                let field_type = read_u16(data, pos);
                let field_len = read_u16(data, pos + 2) as usize;
                pos += 4;

                let loc = FieldLoc {
                    offset,
                    length: field_len,
                };
                match field_type {
                    SAMPLING_INTERVAL | SAMPLING_PACKET_INTERVAL | SAMPLER_RANDOM_INTERVAL => {
                        sampling_loc = Some(loc);
                    }
                    SAMPLER_ID | SELECTOR_ID => {
                        sampler_id_loc = Some(loc);
                    }
                    SAMPLING_PACKET_SPACE => {
                        sampling_space_loc = Some(loc);
                    }
                    _ => {}
                }

                offset += field_len;
            }

            self.options_templates.insert(
                (exporter, source_id, template_id),
                OptionsTemplate {
                    record_len: offset,
                    sampling_interval: sampling_loc,
                    sampler_id: sampler_id_loc,
                    sampling_packet_space: sampling_space_loc,
                },
            );
        }

        Ok(())
    }

    fn parse_options_data_flowset(
        &mut self,
        data: &[u8],
        start: usize,
        end: usize,
        tmpl: &OptionsTemplate,
        exporter: IpAddr,
        source_id: u32,
    ) {
        if tmpl.record_len == 0 {
            return;
        }

        let mut pos = start;
        while pos + tmpl.record_len <= end {
            let rec = &data[pos..pos + tmpl.record_len];

            if let Some(loc) = &tmpl.sampling_interval {
                let mut rate = read_uint(rec, loc.offset, loc.length);

                if let Some(space_loc) = &tmpl.sampling_packet_space {
                    let space = read_uint(rec, space_loc.offset, space_loc.length);
                    if rate > 0 {
                        rate = (rate + space) / rate;
                    }
                }

                if rate > 1 {
                    let sampler_id = tmpl
                        .sampler_id
                        .as_ref()
                        .map(|loc| read_uint(rec, loc.offset, loc.length))
                        .unwrap_or(0);
                    self.sampling_rates
                        .insert((exporter, source_id, sampler_id), rate);
                }
            }

            pos += tmpl.record_len;
        }
    }

    fn parse_template_flowset(
        &mut self,
        data: &[u8],
        mut pos: usize,
        end: usize,
        exporter: IpAddr,
        source_id: u32,
    ) -> Result<(), ParseError> {
        while pos + 4 <= end {
            let template_id = read_u16(data, pos);
            let field_count = read_u16(data, pos + 2) as usize;
            pos += 4;

            let fields_bytes = field_count * 4;
            if pos + fields_bytes > end {
                return Err(ParseError::MalformedTemplate);
            }

            let mut tmpl = ResolvedTemplate {
                record_len: 0,
                src_ipv4: None,
                src_ipv6: None,
                dst_ipv4: None,
                dst_ipv6: None,
                in_bytes: None,
                in_packets: None,
                first_switched: None,
                last_switched: None,
                src_vlan: None,
                dst_vlan: None,
                sampling_interval: None,
                sampler_id: None,
            };

            let mut offset = 0usize;
            for _ in 0..field_count {
                let field_type = read_u16(data, pos);
                let field_len = read_u16(data, pos + 2) as usize;
                pos += 4;

                let loc = FieldLoc {
                    offset,
                    length: field_len,
                };

                match field_type {
                    IN_BYTES => tmpl.in_bytes = Some(loc),
                    IN_PACKETS => tmpl.in_packets = Some(loc),
                    IPV4_SRC_ADDR => tmpl.src_ipv4 = Some(loc),
                    IPV4_DST_ADDR => tmpl.dst_ipv4 = Some(loc),
                    IPV6_SRC_ADDR => tmpl.src_ipv6 = Some(loc),
                    IPV6_DST_ADDR => tmpl.dst_ipv6 = Some(loc),
                    FIRST_SWITCHED => tmpl.first_switched = Some(loc),
                    LAST_SWITCHED => tmpl.last_switched = Some(loc),
                    SRC_VLAN => tmpl.src_vlan = Some(loc),
                    DST_VLAN => tmpl.dst_vlan = Some(loc),
                    SAMPLING_INTERVAL | SAMPLING_PACKET_INTERVAL | SAMPLER_RANDOM_INTERVAL => {
                        tmpl.sampling_interval = Some(loc)
                    }
                    SAMPLER_ID | SELECTOR_ID => tmpl.sampler_id = Some(loc),
                    _ => {}
                }

                offset += field_len;
            }

            tmpl.record_len = offset;
            self.templates
                .insert((exporter, source_id, template_id), tmpl);
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_data_flowset(
        &self,
        data: &[u8],
        start: usize,
        end: usize,
        tmpl: &ResolvedTemplate,
        boot_epoch_ms: u64,
        exporter: IpAddr,
        source_id: u32,
        flows: &mut Vec<ExtractedFlow>,
    ) {
        if tmpl.record_len == 0 {
            return;
        }

        let global_sampling = self
            .sampling_rates
            .get(&(exporter, source_id, 0))
            .copied()
            .unwrap_or(1)
            .max(1);

        let mut pos = start;
        while pos + tmpl.record_len <= end {
            let rec = &data[pos..pos + tmpl.record_len];

            // Destination IP: prefer IPv6 if present, else IPv4, else skip.
            let dst_ip = if let Some(loc) = &tmpl.dst_ipv6 {
                if loc.length == 16 {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&rec[loc.offset..loc.offset + 16]);
                    Some(IpAddr::V6(Ipv6Addr::from(octets)))
                } else {
                    None
                }
            } else if let Some(loc) = &tmpl.dst_ipv4 {
                if loc.length == 4 {
                    Some(IpAddr::V4(Ipv4Addr::new(
                        rec[loc.offset],
                        rec[loc.offset + 1],
                        rec[loc.offset + 2],
                        rec[loc.offset + 3],
                    )))
                } else {
                    None
                }
            } else {
                None
            };

            let dst_ip = match dst_ip {
                Some(ip) => ip,
                None => {
                    pos += tmpl.record_len;
                    continue;
                }
            };

            // Source IP: prefer IPv6 if present, else IPv4, else unspecified.
            let src_ip = if let Some(loc) = &tmpl.src_ipv6 {
                if loc.length == 16 {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&rec[loc.offset..loc.offset + 16]);
                    IpAddr::V6(Ipv6Addr::from(octets))
                } else {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                }
            } else if let Some(loc) = &tmpl.src_ipv4 {
                if loc.length == 4 {
                    IpAddr::V4(Ipv4Addr::new(
                        rec[loc.offset],
                        rec[loc.offset + 1],
                        rec[loc.offset + 2],
                        rec[loc.offset + 3],
                    ))
                } else {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                }
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            };

            let byte_count = tmpl
                .in_bytes
                .as_ref()
                .map(|loc| read_uint(rec, loc.offset, loc.length))
                .unwrap_or(0);

            let packet_count = tmpl
                .in_packets
                .as_ref()
                .map(|loc| read_uint(rec, loc.offset, loc.length))
                .unwrap_or(0);

            let first_ms = tmpl
                .first_switched
                .as_ref()
                .map(|loc| read_uint(rec, loc.offset, loc.length))
                .unwrap_or(0);

            let last_ms = tmpl
                .last_switched
                .as_ref()
                .map(|loc| read_uint(rec, loc.offset, loc.length))
                .unwrap_or(0);

            // Handle uptime wrap.
            let (start_abs, end_abs) = if first_ms > last_ms {
                let t = boot_epoch_ms + last_ms;
                (t, t)
            } else {
                (boot_epoch_ms + first_ms, boot_epoch_ms + last_ms)
            };

            // Resolve sampling rate: inline field > per-sampler options rate > global options rate.
            let sampling_rate = if let Some(loc) = &tmpl.sampling_interval {
                let v = read_uint(rec, loc.offset, loc.length);
                if v > 1 { v } else { global_sampling }
            } else if let Some(loc) = &tmpl.sampler_id {
                let sid = read_uint(rec, loc.offset, loc.length);
                self.sampling_rates
                    .get(&(exporter, source_id, sid))
                    .copied()
                    .unwrap_or(global_sampling)
                    .max(1)
            } else {
                global_sampling
            };

            let byte_count = byte_count * sampling_rate;
            let packet_count = packet_count * sampling_rate;

            let vlan_id = tmpl
                .dst_vlan
                .as_ref()
                .or(tmpl.src_vlan.as_ref())
                .map(|loc| read_uint(rec, loc.offset, loc.length) as u16)
                .unwrap_or(1);

            flows.push(ExtractedFlow {
                dst_ip,
                src_ip,
                vlan_id,
                byte_count,
                packet_count,
                flow_start_ms: start_abs,
                flow_end_ms: end_abs,
            });

            pos += tmpl.record_len;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a v9 packet with one template flowset and one data flowset.
    fn build_v9_packet() -> Vec<u8> {
        let mut pkt = Vec::new();

        let sys_uptime: u32 = 60_000; // 60s
        let unix_secs: u32 = 1_700_000_000;
        let source_id: u32 = 1;

        // --- Header (20 bytes) ---
        pkt.extend_from_slice(&9u16.to_be_bytes()); // version
        pkt.extend_from_slice(&1u16.to_be_bytes()); // count (1 data record)
        pkt.extend_from_slice(&sys_uptime.to_be_bytes());
        pkt.extend_from_slice(&unix_secs.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // sequence
        pkt.extend_from_slice(&source_id.to_be_bytes());

        // --- Template FlowSet ---
        // Template: id=256, fields: IPV4_SRC_ADDR(4), IPV4_DST_ADDR(4), IN_BYTES(4), FIRST_SWITCHED(4), LAST_SWITCHED(4), DST_VLAN(2)
        let field_count: u16 = 6;
        let tmpl_fields_len = (field_count as usize) * 4; // 20 bytes of fields
        let tmpl_record_len = 4 + tmpl_fields_len; // template_id(2) + field_count(2) + fields
        let flowset_len = 4 + tmpl_record_len; // flowset header(4) + template record
        // Pad to 4-byte boundary
        let flowset_len_padded = (flowset_len + 3) & !3;

        pkt.extend_from_slice(&0u16.to_be_bytes()); // flowset_id = 0 (template)
        pkt.extend_from_slice(&(flowset_len_padded as u16).to_be_bytes()); // length

        pkt.extend_from_slice(&256u16.to_be_bytes()); // template_id
        pkt.extend_from_slice(&field_count.to_be_bytes()); // field_count

        // Fields: (type, length)
        pkt.extend_from_slice(&8u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes()); // IPV4_SRC_ADDR
        pkt.extend_from_slice(&12u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes()); // IPV4_DST_ADDR
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes()); // IN_BYTES
        pkt.extend_from_slice(&22u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes()); // FIRST_SWITCHED
        pkt.extend_from_slice(&21u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes()); // LAST_SWITCHED
        pkt.extend_from_slice(&59u16.to_be_bytes());
        pkt.extend_from_slice(&2u16.to_be_bytes()); // DST_VLAN

        // Pad template flowset
        while pkt.len() < 20 + flowset_len_padded {
            pkt.push(0);
        }

        // --- Data FlowSet ---
        // Record: src_ip(4) + dst_ip(4) + in_bytes(4) + first(4) + last(4) + vlan(2) = 22 bytes
        let record_len = 22;
        let data_flowset_len = 4 + record_len;
        let data_flowset_len_padded = (data_flowset_len + 3) & !3;

        pkt.extend_from_slice(&256u16.to_be_bytes()); // flowset_id = 256
        pkt.extend_from_slice(&(data_flowset_len_padded as u16).to_be_bytes()); // length

        // Record data:
        pkt.extend_from_slice(&Ipv4Addr::new(192, 168, 1, 1).octets()); // src_ip
        pkt.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets()); // dst_ip
        pkt.extend_from_slice(&1500u32.to_be_bytes()); // in_bytes
        pkt.extend_from_slice(&30_000u32.to_be_bytes()); // first_switched (30s after boot)
        pkt.extend_from_slice(&55_000u32.to_be_bytes()); // last_switched (55s after boot)
        pkt.extend_from_slice(&100u16.to_be_bytes()); // dst_vlan

        // Pad data flowset
        while pkt.len() < 20 + flowset_len_padded + data_flowset_len_padded {
            pkt.push(0);
        }

        pkt
    }

    #[test]
    fn test_parse_template_and_data() {
        let pkt = build_v9_packet();
        let exporter = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let mut parser = V9Parser::new();
        let mut flows = Vec::new();
        parser.parse_into(&pkt, exporter, &mut flows).unwrap();

        assert_eq!(flows.len(), 1);
        let f = &flows[0];
        assert_eq!(f.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(f.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(f.byte_count, 1500);
        assert_eq!(f.vlan_id, 100);

        // boot_epoch_ms = 1_700_000_000_000 - 60_000 = 1_699_999_940_000
        // flow_start = boot + 30_000 = 1_699_999_970_000
        // flow_end   = boot + 55_000 = 1_699_999_995_000
        let start = f.flow_start_ms as u128;
        let end = f.flow_end_ms as u128;
        assert_eq!(start, 1_699_999_970_000);
        assert_eq!(end, 1_699_999_995_000);
    }

    #[test]
    fn test_data_before_template() {
        // Send data flowset referencing unknown template → should return empty.
        let exporter = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut parser = V9Parser::new();

        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&9u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&60_000u32.to_be_bytes());
        pkt.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());
        // Data flowset with unknown template 300
        let data_fs_len: u16 = 8; // header(4) + 4 bytes padding
        pkt.extend_from_slice(&300u16.to_be_bytes());
        pkt.extend_from_slice(&data_fs_len.to_be_bytes());
        pkt.extend_from_slice(&[0u8; 4]);

        let mut flows = Vec::new();
        parser.parse_into(&pkt, exporter, &mut flows).unwrap();
        assert!(flows.is_empty());
    }

    #[test]
    fn test_too_short() {
        let mut parser = V9Parser::new();
        let exporter = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(
            parser
                .parse_into(&[0; 10], exporter, &mut Vec::new())
                .is_err()
        );
    }

    #[test]
    fn test_bad_version() {
        let mut parser = V9Parser::new();
        let exporter = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut pkt = vec![0u8; HEADER_LEN];
        pkt[1] = 5; // version 5 instead of 9
        match parser.parse_into(&pkt, exporter, &mut Vec::new()) {
            Err(ParseError::BadVersion(5)) => {}
            other => panic!("expected BadVersion(5), got {other:?}"),
        }
    }

    /// Build a v9 header with the given sequence and source_id.
    fn build_v9_header(
        pkt: &mut Vec<u8>,
        count: u16,
        sys_uptime: u32,
        unix_secs: u32,
        sequence: u32,
        source_id: u32,
    ) {
        pkt.extend_from_slice(&9u16.to_be_bytes());
        pkt.extend_from_slice(&count.to_be_bytes());
        pkt.extend_from_slice(&sys_uptime.to_be_bytes());
        pkt.extend_from_slice(&unix_secs.to_be_bytes());
        pkt.extend_from_slice(&sequence.to_be_bytes());
        pkt.extend_from_slice(&source_id.to_be_bytes());
    }

    /// Regression test: template and data arrive in separate packets with different
    /// sequence numbers (as Cisco devices do in practice). The v9 header has the
    /// sequence number at offset 12 and source_id at offset 16 — reading the wrong
    /// field causes every packet to get a unique cache key, so data-only packets
    /// never find their template.
    #[test]
    fn test_template_and_data_in_separate_packets() {
        let exporter = IpAddr::V4(Ipv4Addr::new(172, 16, 40, 1));
        let mut parser = V9Parser::new();
        let source_id: u32 = 768;
        let sys_uptime: u32 = 60_000;
        let unix_secs: u32 = 1_700_000_000;

        // --- Packet 1: template only (sequence = 100) ---
        let mut tmpl_pkt = Vec::new();
        build_v9_header(&mut tmpl_pkt, 0, sys_uptime, unix_secs, 100, source_id);

        let field_count: u16 = 6;
        let tmpl_fields_len = (field_count as usize) * 4;
        let tmpl_record_len = 4 + tmpl_fields_len;
        let flowset_len = 4 + tmpl_record_len;
        let flowset_len_padded = (flowset_len + 3) & !3;

        tmpl_pkt.extend_from_slice(&0u16.to_be_bytes()); // template flowset
        tmpl_pkt.extend_from_slice(&(flowset_len_padded as u16).to_be_bytes());
        tmpl_pkt.extend_from_slice(&256u16.to_be_bytes()); // template_id
        tmpl_pkt.extend_from_slice(&field_count.to_be_bytes());

        // Fields: SRC_ADDR, DST_ADDR, IN_BYTES, FIRST_SWITCHED, LAST_SWITCHED, DST_VLAN
        for &(ftype, flen) in &[(8, 4), (12, 4), (1, 4), (22, 4), (21, 4), (59, 2)] {
            tmpl_pkt.extend_from_slice(&(ftype as u16).to_be_bytes());
            tmpl_pkt.extend_from_slice(&(flen as u16).to_be_bytes());
        }
        while tmpl_pkt.len() < 20 + flowset_len_padded {
            tmpl_pkt.push(0);
        }

        let mut flows = Vec::new();
        parser.parse_into(&tmpl_pkt, exporter, &mut flows).unwrap();
        assert!(
            flows.is_empty(),
            "template-only packet should produce no flows"
        );

        // --- Packet 2: data only (sequence = 101, same source_id) ---
        let mut data_pkt = Vec::new();
        build_v9_header(&mut data_pkt, 1, sys_uptime, unix_secs, 101, source_id);

        let record_len = 22; // 4+4+4+4+4+2
        let data_flowset_len = 4 + record_len;
        let data_flowset_len_padded = (data_flowset_len + 3) & !3;

        data_pkt.extend_from_slice(&256u16.to_be_bytes()); // flowset_id = template 256
        data_pkt.extend_from_slice(&(data_flowset_len_padded as u16).to_be_bytes());
        data_pkt.extend_from_slice(&Ipv4Addr::new(192, 168, 1, 1).octets());
        data_pkt.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
        data_pkt.extend_from_slice(&1500u32.to_be_bytes());
        data_pkt.extend_from_slice(&30_000u32.to_be_bytes());
        data_pkt.extend_from_slice(&55_000u32.to_be_bytes());
        data_pkt.extend_from_slice(&100u16.to_be_bytes());
        while data_pkt.len() < 20 + data_flowset_len_padded {
            data_pkt.push(0);
        }

        flows.clear();
        parser.parse_into(&data_pkt, exporter, &mut flows).unwrap();

        assert_eq!(
            flows.len(),
            1,
            "data packet must find template from earlier packet (same source_id)"
        );
        assert_eq!(flows[0].dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(flows[0].byte_count, 1500);
        assert_eq!(flows[0].vlan_id, 100);
    }

    /// Verify templates are isolated per source_id — data from one source_id
    /// must not match a template registered under a different source_id.
    #[test]
    fn test_different_source_ids_isolated() {
        let exporter = IpAddr::V4(Ipv4Addr::new(172, 16, 40, 1));
        let mut parser = V9Parser::new();
        let sys_uptime: u32 = 60_000;
        let unix_secs: u32 = 1_700_000_000;

        // Register template under source_id=768
        let mut tmpl_pkt = Vec::new();
        build_v9_header(&mut tmpl_pkt, 0, sys_uptime, unix_secs, 200, 768);

        let field_count: u16 = 3;
        let flowset_len = 4 + 4 + (field_count as usize) * 4;
        let flowset_len_padded = (flowset_len + 3) & !3;
        tmpl_pkt.extend_from_slice(&0u16.to_be_bytes());
        tmpl_pkt.extend_from_slice(&(flowset_len_padded as u16).to_be_bytes());
        tmpl_pkt.extend_from_slice(&256u16.to_be_bytes());
        tmpl_pkt.extend_from_slice(&field_count.to_be_bytes());
        for &(ftype, flen) in &[(8, 4), (12, 4), (1, 4)] {
            tmpl_pkt.extend_from_slice(&(ftype as u16).to_be_bytes());
            tmpl_pkt.extend_from_slice(&(flen as u16).to_be_bytes());
        }
        while tmpl_pkt.len() < 20 + flowset_len_padded {
            tmpl_pkt.push(0);
        }
        parser
            .parse_into(&tmpl_pkt, exporter, &mut Vec::new())
            .unwrap();

        // Send data under source_id=1024 — should NOT match template from 768
        let mut data_pkt = Vec::new();
        build_v9_header(&mut data_pkt, 1, sys_uptime, unix_secs, 201, 1024);
        let record_len = 12; // 4+4+4
        let data_fs_len = 4 + record_len;
        let data_fs_padded = (data_fs_len + 3) & !3;
        data_pkt.extend_from_slice(&256u16.to_be_bytes());
        data_pkt.extend_from_slice(&(data_fs_padded as u16).to_be_bytes());
        data_pkt.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
        data_pkt.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
        data_pkt.extend_from_slice(&500u32.to_be_bytes());
        while data_pkt.len() < 20 + data_fs_padded {
            data_pkt.push(0);
        }

        let mut flows = Vec::new();
        parser.parse_into(&data_pkt, exporter, &mut flows).unwrap();
        assert!(
            flows.is_empty(),
            "data from source_id=1024 must not use template from source_id=768"
        );
    }

    #[test]
    fn test_sampling_interval() {
        let exporter = IpAddr::V4(Ipv4Addr::new(172, 16, 40, 1));
        let mut parser = V9Parser::new();
        let source_id: u32 = 1;
        let sys_uptime: u32 = 60_000;
        let unix_secs: u32 = 1_700_000_000;

        // Template with SAMPLING_INTERVAL (field 34) added
        let mut pkt = Vec::new();
        build_v9_header(&mut pkt, 0, sys_uptime, unix_secs, 1, source_id);

        let field_count: u16 = 5; // SRC, DST, IN_BYTES, IN_PACKETS, SAMPLING_INTERVAL
        let tmpl_fields_len = (field_count as usize) * 4;
        let tmpl_record_len = 4 + tmpl_fields_len;
        let flowset_len = 4 + tmpl_record_len;
        let flowset_len_padded = (flowset_len + 3) & !3;

        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&(flowset_len_padded as u16).to_be_bytes());
        pkt.extend_from_slice(&256u16.to_be_bytes());
        pkt.extend_from_slice(&field_count.to_be_bytes());

        // Fields: SRC_ADDR(4), DST_ADDR(4), IN_BYTES(4), IN_PACKETS(4), SAMPLING_INTERVAL(4)
        for &(ftype, flen) in &[(8, 4), (12, 4), (1, 4), (2, 4), (34, 4)] {
            pkt.extend_from_slice(&(ftype as u16).to_be_bytes());
            pkt.extend_from_slice(&(flen as u16).to_be_bytes());
        }
        while pkt.len() < 20 + flowset_len_padded {
            pkt.push(0);
        }

        // Data flowset: record = 4+4+4+4+4 = 20 bytes
        let record_len = 20;
        let data_fs_len = 4 + record_len;
        let data_fs_padded = (data_fs_len + 3) & !3;

        pkt.extend_from_slice(&256u16.to_be_bytes());
        pkt.extend_from_slice(&(data_fs_padded as u16).to_be_bytes());
        pkt.extend_from_slice(&Ipv4Addr::new(192, 168, 1, 1).octets()); // src
        pkt.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets()); // dst
        pkt.extend_from_slice(&500u32.to_be_bytes()); // in_bytes
        pkt.extend_from_slice(&10u32.to_be_bytes()); // in_packets
        pkt.extend_from_slice(&200u32.to_be_bytes()); // sampling_interval = 1:200
        while pkt.len() < 20 + flowset_len_padded + data_fs_padded {
            pkt.push(0);
        }

        let mut flows = Vec::new();
        parser.parse_into(&pkt, exporter, &mut flows).unwrap();

        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].byte_count, 500 * 200);
        assert_eq!(flows[0].packet_count, 10 * 200);
    }
}
