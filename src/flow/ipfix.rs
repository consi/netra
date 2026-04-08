use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
// SystemTime removed: we use u64 epoch millis directly

use super::{ExtractedFlow, ParseError, read_u16, read_u32, read_uint};

const HEADER_LEN: usize = 16;

// Field IDs we care about.
const IN_BYTES: u16 = 1;
const IN_PACKETS: u16 = 2;
const IPV4_SRC_ADDR: u16 = 8;
const IPV4_DST_ADDR: u16 = 12;
const FIRST_SWITCHED: u16 = 22;
const LAST_SWITCHED: u16 = 21;
const IPV6_SRC_ADDR: u16 = 27;
const IPV6_DST_ADDR: u16 = 28;
const SRC_VLAN: u16 = 58;
const DST_VLAN: u16 = 59;
const SAMPLING_INTERVAL: u16 = 34;
const FLOW_START_SEC: u16 = 150;
const FLOW_END_SEC: u16 = 151;
const FLOW_START_MS: u16 = 152;
const FLOW_END_MS: u16 = 153;
const SAMPLING_PACKET_INTERVAL: u16 = 305;

/// Marker for variable-length field in IPFIX templates.
const VARIABLE_LENGTH: u16 = 65535;

#[derive(Clone, Debug)]
struct FieldLoc {
    offset: usize,
    length: usize,
}

/// Describes a field in the template for variable-length scanning.
#[derive(Clone, Debug)]
struct TemplateField {
    /// Template-declared length (65535 means variable).
    length: u16,
}

#[derive(Clone, Debug)]
struct ResolvedIpfixTemplate {
    /// Total record length if all fields are fixed-length; 0 if variable fields exist.
    record_len: usize,
    has_variable_fields: bool,
    /// All fields in order, for variable-length record scanning.
    fields: Vec<TemplateField>,

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
    flow_start_sec: Option<FieldLoc>,
    flow_end_sec: Option<FieldLoc>,
    flow_start_ms: Option<FieldLoc>,
    flow_end_ms: Option<FieldLoc>,
    sampling_interval: Option<FieldLoc>,
}

/// Index into the `fields` vec for fields we care about (to resolve at runtime for variable-length records).
#[derive(Clone, Debug, Default)]
struct FieldIndices {
    src_ipv4: Option<usize>,
    src_ipv6: Option<usize>,
    dst_ipv4: Option<usize>,
    dst_ipv6: Option<usize>,
    in_bytes: Option<usize>,
    in_packets: Option<usize>,
    first_switched: Option<usize>,
    last_switched: Option<usize>,
    src_vlan: Option<usize>,
    dst_vlan: Option<usize>,
    flow_start_sec: Option<usize>,
    flow_end_sec: Option<usize>,
    flow_start_ms: Option<usize>,
    flow_end_ms: Option<usize>,
    sampling_interval: Option<usize>,
}

pub struct IpfixParser {
    templates: HashMap<(IpAddr, u32, u16), (ResolvedIpfixTemplate, FieldIndices)>,
}

impl IpfixParser {
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
        }
    }

    /// Parse an IPFIX datagram, appending flows into an existing Vec.
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
        if version != 10 {
            return Err(ParseError::BadVersion(version));
        }

        let msg_length = read_u16(data, 2) as usize;
        if data.len() < msg_length {
            return Err(ParseError::Truncated);
        }

        let export_time = read_u32(data, 4) as u64; // seconds since epoch
        let _sequence = read_u32(data, 8);
        let observation_domain_id = read_u32(data, 12);

        let mut cursor = HEADER_LEN;

        while cursor + 4 <= msg_length {
            let set_id = read_u16(data, cursor);
            let set_length = read_u16(data, cursor + 2) as usize;

            if set_length < 4 || cursor + set_length > msg_length {
                break;
            }

            let set_end = cursor + set_length;

            match set_id {
                2 => {
                    // Template Set
                    self.parse_template_set(
                        data,
                        cursor + 4,
                        set_end,
                        exporter,
                        observation_domain_id,
                    )?;
                }
                3 => {
                    // Options Template Set — skip
                }
                id if id >= 256 => {
                    // Data Set
                    let key = (exporter, observation_domain_id, id);
                    if let Some((tmpl, indices)) = self.templates.get(&key).cloned() {
                        self.parse_data_set(
                            data,
                            cursor + 4,
                            set_end,
                            &tmpl,
                            &indices,
                            export_time,
                            flows,
                        );
                    }
                }
                _ => {
                    // Reserved set IDs 4-255: skip
                }
            }

            cursor = set_end;
        }

        Ok(())
    }

    fn parse_template_set(
        &mut self,
        data: &[u8],
        mut pos: usize,
        end: usize,
        exporter: IpAddr,
        observation_domain_id: u32,
    ) -> Result<(), ParseError> {
        while pos + 4 <= end {
            let template_id = read_u16(data, pos);
            let field_count = read_u16(data, pos + 2) as usize;
            pos += 4;

            let mut tmpl = ResolvedIpfixTemplate {
                record_len: 0,
                has_variable_fields: false,
                fields: Vec::with_capacity(field_count),
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
                flow_start_sec: None,
                flow_end_sec: None,
                flow_start_ms: None,
                flow_end_ms: None,
                sampling_interval: None,
            };

            let mut indices = FieldIndices::default();
            let mut offset = 0usize;

            for field_idx in 0..field_count {
                if pos + 4 > end {
                    return Err(ParseError::MalformedTemplate);
                }

                let raw_id = read_u16(data, pos);
                let field_length = read_u16(data, pos + 2);
                pos += 4;

                let enterprise_bit = raw_id & 0x8000 != 0;
                let element_id = raw_id & 0x7FFF;

                // If enterprise bit is set, skip the 4-byte PEN.
                if enterprise_bit {
                    if pos + 4 > end {
                        return Err(ParseError::MalformedTemplate);
                    }
                    pos += 4;
                }

                let is_variable = field_length == VARIABLE_LENGTH;
                if is_variable {
                    tmpl.has_variable_fields = true;
                }

                tmpl.fields.push(TemplateField {
                    length: field_length,
                });

                // Only resolve IANA (non-enterprise) fields we care about.
                if !enterprise_bit && !is_variable {
                    let loc = FieldLoc {
                        offset,
                        length: field_length as usize,
                    };
                    match element_id {
                        IN_BYTES => {
                            tmpl.in_bytes = Some(loc);
                            indices.in_bytes = Some(field_idx);
                        }
                        IN_PACKETS => {
                            tmpl.in_packets = Some(loc);
                            indices.in_packets = Some(field_idx);
                        }
                        IPV4_SRC_ADDR => {
                            tmpl.src_ipv4 = Some(loc);
                            indices.src_ipv4 = Some(field_idx);
                        }
                        IPV4_DST_ADDR => {
                            tmpl.dst_ipv4 = Some(loc);
                            indices.dst_ipv4 = Some(field_idx);
                        }
                        IPV6_SRC_ADDR => {
                            tmpl.src_ipv6 = Some(loc);
                            indices.src_ipv6 = Some(field_idx);
                        }
                        IPV6_DST_ADDR => {
                            tmpl.dst_ipv6 = Some(loc);
                            indices.dst_ipv6 = Some(field_idx);
                        }
                        FIRST_SWITCHED => {
                            tmpl.first_switched = Some(loc);
                            indices.first_switched = Some(field_idx);
                        }
                        LAST_SWITCHED => {
                            tmpl.last_switched = Some(loc);
                            indices.last_switched = Some(field_idx);
                        }
                        SRC_VLAN => {
                            tmpl.src_vlan = Some(loc);
                            indices.src_vlan = Some(field_idx);
                        }
                        DST_VLAN => {
                            tmpl.dst_vlan = Some(loc);
                            indices.dst_vlan = Some(field_idx);
                        }
                        FLOW_START_SEC => {
                            tmpl.flow_start_sec = Some(loc);
                            indices.flow_start_sec = Some(field_idx);
                        }
                        FLOW_END_SEC => {
                            tmpl.flow_end_sec = Some(loc);
                            indices.flow_end_sec = Some(field_idx);
                        }
                        FLOW_START_MS => {
                            tmpl.flow_start_ms = Some(loc);
                            indices.flow_start_ms = Some(field_idx);
                        }
                        FLOW_END_MS => {
                            tmpl.flow_end_ms = Some(loc);
                            indices.flow_end_ms = Some(field_idx);
                        }
                        SAMPLING_INTERVAL | SAMPLING_PACKET_INTERVAL => {
                            tmpl.sampling_interval = Some(loc);
                            indices.sampling_interval = Some(field_idx);
                        }
                        _ => {}
                    }
                }

                if !is_variable {
                    offset += field_length as usize;
                }
            }

            tmpl.record_len = offset; // Only meaningful if no variable-length fields.
            self.templates.insert(
                (exporter, observation_domain_id, template_id),
                (tmpl, indices),
            );
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_data_set(
        &self,
        data: &[u8],
        start: usize,
        end: usize,
        tmpl: &ResolvedIpfixTemplate,
        indices: &FieldIndices,
        export_time: u64,
        flows: &mut Vec<ExtractedFlow>,
    ) {
        if tmpl.has_variable_fields {
            self.parse_data_set_variable(data, start, end, tmpl, indices, export_time, flows);
        } else {
            self.parse_data_set_fixed(data, start, end, tmpl, export_time, flows);
        }
    }

    /// Fast path: all fields are fixed-length, offsets precomputed.
    fn parse_data_set_fixed(
        &self,
        data: &[u8],
        start: usize,
        end: usize,
        tmpl: &ResolvedIpfixTemplate,
        export_time: u64,
        flows: &mut Vec<ExtractedFlow>,
    ) {
        if tmpl.record_len == 0 {
            return;
        }

        let mut pos = start;
        while pos + tmpl.record_len <= end {
            let rec = &data[pos..pos + tmpl.record_len];

            if let Some(flow) = self.extract_flow_fixed(rec, tmpl, export_time) {
                flows.push(flow);
            }

            pos += tmpl.record_len;
        }
    }

    fn extract_flow_fixed(
        &self,
        rec: &[u8],
        tmpl: &ResolvedIpfixTemplate,
        export_time: u64,
    ) -> Option<ExtractedFlow> {
        let dst_ip = self.extract_ip(rec, &tmpl.dst_ipv6, &tmpl.dst_ipv4)?;
        let src_ip = self
            .extract_ip(rec, &tmpl.src_ipv6, &tmpl.src_ipv4)
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

        let sampling_rate = tmpl
            .sampling_interval
            .as_ref()
            .map(|loc| read_uint(rec, loc.offset, loc.length))
            .unwrap_or(1)
            .max(1);

        let byte_count = tmpl
            .in_bytes
            .as_ref()
            .map(|loc| read_uint(rec, loc.offset, loc.length))
            .unwrap_or(0)
            * sampling_rate;

        let packet_count = tmpl
            .in_packets
            .as_ref()
            .map(|loc| read_uint(rec, loc.offset, loc.length))
            .unwrap_or(0)
            * sampling_rate;

        let (flow_start_ms, flow_end_ms) = self.resolve_timestamps_ms(rec, tmpl, export_time);

        let vlan_id = tmpl
            .dst_vlan
            .as_ref()
            .or(tmpl.src_vlan.as_ref())
            .map(|loc| read_uint(rec, loc.offset, loc.length) as u16)
            .unwrap_or(1);

        Some(ExtractedFlow {
            dst_ip,
            src_ip,
            vlan_id,
            byte_count,
            packet_count,
            flow_start_ms,
            flow_end_ms,
        })
    }

    fn extract_ip(
        &self,
        rec: &[u8],
        ipv6: &Option<FieldLoc>,
        ipv4: &Option<FieldLoc>,
    ) -> Option<IpAddr> {
        if let Some(loc) = ipv6
            && loc.length == 16
            && loc.offset + 16 <= rec.len()
        {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&rec[loc.offset..loc.offset + 16]);
            return Some(IpAddr::V6(Ipv6Addr::from(octets)));
        }
        if let Some(loc) = ipv4
            && loc.length == 4
            && loc.offset + 4 <= rec.len()
        {
            return Some(IpAddr::V4(Ipv4Addr::new(
                rec[loc.offset],
                rec[loc.offset + 1],
                rec[loc.offset + 2],
                rec[loc.offset + 3],
            )));
        }
        None
    }

    /// Returns (start_ms, end_ms) as epoch milliseconds.
    fn resolve_timestamps_ms(
        &self,
        rec: &[u8],
        tmpl: &ResolvedIpfixTemplate,
        export_time: u64,
    ) -> (u64, u64) {
        // Priority: flowStartMilliseconds/flowEndMilliseconds (152/153)
        //         > flowStartSeconds/flowEndSeconds (150/151)
        //         > FIRST_SWITCHED/LAST_SWITCHED (21/22) with export_time as base

        if let (Some(s_loc), Some(e_loc)) = (&tmpl.flow_start_ms, &tmpl.flow_end_ms) {
            let s = read_uint(rec, s_loc.offset, s_loc.length);
            let e = read_uint(rec, e_loc.offset, e_loc.length);
            return (s, e);
        }

        if let (Some(s_loc), Some(e_loc)) = (&tmpl.flow_start_sec, &tmpl.flow_end_sec) {
            let s = read_uint(rec, s_loc.offset, s_loc.length);
            let e = read_uint(rec, e_loc.offset, e_loc.length);
            return (s * 1000, e * 1000);
        }

        if let (Some(s_loc), Some(e_loc)) = (&tmpl.first_switched, &tmpl.last_switched) {
            let first_ms = read_uint(rec, s_loc.offset, s_loc.length);
            let last_ms = read_uint(rec, e_loc.offset, e_loc.length);

            let export_time_ms = export_time * 1000;
            if first_ms <= last_ms {
                let duration_ms = last_ms - first_ms;
                let end = export_time_ms;
                let start = end.saturating_sub(duration_ms);
                return (start, end);
            } else {
                return (export_time_ms, export_time_ms);
            }
        }

        let t = export_time * 1000;
        (t, t)
    }

    /// Slow path: record contains variable-length fields. Must scan each record sequentially.
    #[allow(clippy::too_many_arguments)]
    fn parse_data_set_variable(
        &self,
        data: &[u8],
        start: usize,
        end: usize,
        tmpl: &ResolvedIpfixTemplate,
        indices: &FieldIndices,
        export_time: u64,
        flows: &mut Vec<ExtractedFlow>,
    ) {
        let mut pos = start;

        'records: while pos < end {
            // We need at least 1 byte to start reading a record.
            if pos >= end {
                break;
            }

            // Scan through fields, computing actual offsets.
            let rec_start = pos;
            let mut field_offsets: Vec<(usize, usize)> = Vec::with_capacity(tmpl.fields.len());

            for f in &tmpl.fields {
                if f.length == VARIABLE_LENGTH {
                    // Read variable length.
                    if pos >= end {
                        break 'records;
                    }
                    let first_byte = data[pos] as usize;
                    pos += 1;
                    let actual_len = if first_byte < 255 {
                        first_byte
                    } else {
                        if pos + 2 > end {
                            break 'records;
                        }
                        let len = read_u16(data, pos) as usize;
                        pos += 2;
                        len
                    };
                    field_offsets.push((pos, actual_len));
                    pos += actual_len;
                    if pos > end {
                        break 'records;
                    }
                } else {
                    let len = f.length as usize;
                    if pos + len > end {
                        break 'records;
                    }
                    field_offsets.push((pos, len));
                    pos += len;
                }
            }

            // Now extract the flow using the resolved offsets.
            // Build a virtual record view using field_offsets against `data`.

            let extract_ip_var =
                |ipv6_idx: Option<usize>, ipv4_idx: Option<usize>| -> Option<IpAddr> {
                    if let Some(idx) = ipv6_idx {
                        let (off, len) = field_offsets[idx];
                        if len == 16 {
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(&data[off..off + 16]);
                            return Some(IpAddr::V6(Ipv6Addr::from(octets)));
                        }
                    }
                    if let Some(idx) = ipv4_idx {
                        let (off, len) = field_offsets[idx];
                        if len == 4 {
                            return Some(IpAddr::V4(Ipv4Addr::new(
                                data[off],
                                data[off + 1],
                                data[off + 2],
                                data[off + 3],
                            )));
                        }
                    }
                    None
                };

            let dst_ip = match extract_ip_var(indices.dst_ipv6, indices.dst_ipv4) {
                Some(ip) => ip,
                None => continue,
            };

            let src_ip = extract_ip_var(indices.src_ipv6, indices.src_ipv4)
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

            let sampling_rate = indices
                .sampling_interval
                .map(|idx| {
                    let (off, len) = field_offsets[idx];
                    read_uint(data, off, len)
                })
                .unwrap_or(1)
                .max(1);

            let byte_count = indices
                .in_bytes
                .map(|idx| {
                    let (off, len) = field_offsets[idx];
                    read_uint(data, off, len)
                })
                .unwrap_or(0)
                * sampling_rate;

            let packet_count = indices
                .in_packets
                .map(|idx| {
                    let (off, len) = field_offsets[idx];
                    read_uint(data, off, len)
                })
                .unwrap_or(0)
                * sampling_rate;

            // Timestamps — build temporary FieldLoc from actual offsets for reuse.
            let mk_loc = |idx: Option<usize>| -> Option<FieldLoc> {
                idx.map(|i| {
                    let (off, len) = field_offsets[i];
                    // Offset relative to rec_start so we can pass a subslice.
                    FieldLoc {
                        offset: off - rec_start,
                        length: len,
                    }
                })
            };

            // Build a temporary template-like struct for timestamp resolution.
            let tmp_tmpl = ResolvedIpfixTemplate {
                record_len: pos - rec_start,
                has_variable_fields: false,
                fields: Vec::new(),
                src_ipv4: None,
                src_ipv6: None,
                dst_ipv4: None,
                dst_ipv6: None,
                in_bytes: None,
                in_packets: None,
                first_switched: mk_loc(indices.first_switched),
                last_switched: mk_loc(indices.last_switched),
                src_vlan: None,
                dst_vlan: None,
                flow_start_sec: mk_loc(indices.flow_start_sec),
                flow_end_sec: mk_loc(indices.flow_end_sec),
                flow_start_ms: mk_loc(indices.flow_start_ms),
                flow_end_ms: mk_loc(indices.flow_end_ms),
                sampling_interval: None,
            };

            let rec_data = &data[rec_start..pos];
            let (flow_start_ms, flow_end_ms) =
                self.resolve_timestamps_ms(rec_data, &tmp_tmpl, export_time);

            let vlan_id = indices
                .dst_vlan
                .or(indices.src_vlan)
                .map(|idx| {
                    let (off, len) = field_offsets[idx];
                    read_uint(data, off, len) as u16
                })
                .unwrap_or(1);

            flows.push(ExtractedFlow {
                dst_ip,
                src_ip,
                vlan_id,
                byte_count,
                packet_count,
                flow_start_ms,
                flow_end_ms,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ipfix_packet() -> Vec<u8> {
        let mut pkt = Vec::new();

        let export_time: u32 = 1_700_000_000;
        let observation_domain_id: u32 = 42;

        // --- Header (16 bytes) --- placeholder for length
        pkt.extend_from_slice(&10u16.to_be_bytes()); // version
        pkt.extend_from_slice(&0u16.to_be_bytes()); // length (fill later)
        pkt.extend_from_slice(&export_time.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // sequence
        pkt.extend_from_slice(&observation_domain_id.to_be_bytes());

        // --- Template Set (set_id=2) ---
        // Template: id=256, fields:
        //   IPV4_SRC_ADDR(8, 4), IPV4_DST_ADDR(12, 4), IN_BYTES(1, 4),
        //   flowStartMilliseconds(152, 8), flowEndMilliseconds(153, 8),
        //   DST_VLAN(59, 2)
        let field_count: u16 = 6;
        let tmpl_record_bytes = 4 + (field_count as usize) * 4; // id(2)+count(2) + fields
        let set_payload = tmpl_record_bytes;
        let set_len = 4 + set_payload;
        let set_len_padded = (set_len + 3) & !3;

        pkt.extend_from_slice(&2u16.to_be_bytes()); // set_id
        pkt.extend_from_slice(&(set_len_padded as u16).to_be_bytes()); // set length

        pkt.extend_from_slice(&256u16.to_be_bytes()); // template_id
        pkt.extend_from_slice(&field_count.to_be_bytes());

        // Fields
        pkt.extend_from_slice(&8u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes()); // IPV4_SRC_ADDR
        pkt.extend_from_slice(&12u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes()); // IPV4_DST_ADDR
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes()); // IN_BYTES
        pkt.extend_from_slice(&152u16.to_be_bytes());
        pkt.extend_from_slice(&8u16.to_be_bytes()); // flowStartMs
        pkt.extend_from_slice(&153u16.to_be_bytes());
        pkt.extend_from_slice(&8u16.to_be_bytes()); // flowEndMs
        pkt.extend_from_slice(&59u16.to_be_bytes());
        pkt.extend_from_slice(&2u16.to_be_bytes()); // DST_VLAN

        let template_set_end = HEADER_LEN + set_len_padded;
        while pkt.len() < template_set_end {
            pkt.push(0);
        }

        // --- Data Set (set_id=256) ---
        // Record: src_ip(4) + dst_ip(4) + in_bytes(4) + start_ms(8) + end_ms(8) + vlan(2) = 30 bytes
        let record_len = 30;
        let data_set_len = 4 + record_len;
        let data_set_len_padded = (data_set_len + 3) & !3;

        pkt.extend_from_slice(&256u16.to_be_bytes());
        pkt.extend_from_slice(&(data_set_len_padded as u16).to_be_bytes());

        // Record:
        pkt.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets()); // src_ip
        pkt.extend_from_slice(&Ipv4Addr::new(172, 16, 0, 1).octets());
        pkt.extend_from_slice(&2000u32.to_be_bytes());
        // flowStartMs: 1_700_000_000_000 - 5000 = 1_699_999_995_000
        pkt.extend_from_slice(&1_699_999_995_000u64.to_be_bytes());
        // flowEndMs: 1_700_000_000_000
        pkt.extend_from_slice(&1_700_000_000_000u64.to_be_bytes());
        pkt.extend_from_slice(&200u16.to_be_bytes()); // vlan

        let total = template_set_end + data_set_len_padded;
        while pkt.len() < total {
            pkt.push(0);
        }

        // Fill in message length.
        let len_bytes = (pkt.len() as u16).to_be_bytes();
        pkt[2] = len_bytes[0];
        pkt[3] = len_bytes[1];

        pkt
    }

    #[test]
    fn test_parse_ipfix_template_and_data() {
        let pkt = build_ipfix_packet();
        let exporter = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let mut parser = IpfixParser::new();
        let mut flows = Vec::new();
        parser.parse_into(&pkt, exporter, &mut flows).unwrap();

        assert_eq!(flows.len(), 1);
        let f = &flows[0];
        assert_eq!(f.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)));
        assert_eq!(f.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(f.byte_count, 2000);
        assert_eq!(f.vlan_id, 200);

        let start = f.flow_start_ms as u128;
        let end = f.flow_end_ms as u128;
        assert_eq!(start, 1_699_999_995_000);
        assert_eq!(end, 1_700_000_000_000);
    }

    #[test]
    fn test_enterprise_field_skipped() {
        // Template with an enterprise field should be parsed without error.
        let mut pkt = Vec::new();
        let export_time: u32 = 1_700_000_000;

        // Header
        pkt.extend_from_slice(&10u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes()); // length placeholder
        pkt.extend_from_slice(&export_time.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());

        // Template set with 2 fields: one enterprise, one IPV4_DST_ADDR
        let field_count: u16 = 2;
        // enterprise field: 4 bytes for (id, len) + 4 bytes PEN = 8
        // normal field: 4 bytes
        // total template record = 4 (id+count) + 8 + 4 = 16
        let set_len: u16 = 4 + 4 + 8 + 4; // set header + template record
        let set_len_padded = (set_len as usize + 3) & !3;

        pkt.extend_from_slice(&2u16.to_be_bytes());
        pkt.extend_from_slice(&(set_len_padded as u16).to_be_bytes());

        pkt.extend_from_slice(&300u16.to_be_bytes()); // template_id
        pkt.extend_from_slice(&field_count.to_be_bytes());

        // Enterprise field: bit 15 set on element_id
        pkt.extend_from_slice(&(0x8000u16 | 100).to_be_bytes()); // enterprise element
        pkt.extend_from_slice(&4u16.to_be_bytes()); // length
        pkt.extend_from_slice(&12345u32.to_be_bytes()); // PEN

        // IPV4_DST_ADDR
        pkt.extend_from_slice(&12u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes());

        while pkt.len() < HEADER_LEN + set_len_padded {
            pkt.push(0);
        }

        // Fill length
        let total_len = pkt.len() as u16;
        let len_bytes = total_len.to_be_bytes();
        pkt[2] = len_bytes[0];
        pkt[3] = len_bytes[1];

        let exporter = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut parser = IpfixParser::new();
        let mut flows = Vec::new();
        parser.parse_into(&pkt, exporter, &mut flows).unwrap();
        assert!(flows.is_empty()); // no data set, just template

        // Verify template was stored: key (localhost, 1, 300)
        assert!(parser.templates.contains_key(&(exporter, 1, 300)));
    }

    #[test]
    fn test_too_short() {
        let mut parser = IpfixParser::new();
        let exporter = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(
            parser
                .parse_into(&[0; 10], exporter, &mut Vec::new())
                .is_err()
        );
    }

    #[test]
    fn test_bad_version() {
        let mut parser = IpfixParser::new();
        let exporter = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut pkt = vec![0u8; HEADER_LEN];
        // Set length to HEADER_LEN
        let len_bytes = (HEADER_LEN as u16).to_be_bytes();
        pkt[2] = len_bytes[0];
        pkt[3] = len_bytes[1];
        pkt[0] = 0;
        pkt[1] = 9; // version 9
        match parser.parse_into(&pkt, exporter, &mut Vec::new()) {
            Err(ParseError::BadVersion(9)) => {}
            other => panic!("expected BadVersion(9), got {other:?}"),
        }
    }

    #[test]
    fn test_fallback_to_switched_timestamps() {
        // Template with FIRST_SWITCHED/LAST_SWITCHED instead of absolute timestamps.
        let mut pkt = Vec::new();
        let export_time: u32 = 1_700_000_060; // 60s after epoch reference

        // Header
        pkt.extend_from_slice(&10u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&export_time.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.extend_from_slice(&5u32.to_be_bytes()); // observation domain

        // Template set: IPV4_DST_ADDR, IN_BYTES, FIRST_SWITCHED, LAST_SWITCHED
        let field_count: u16 = 4;
        let set_len = 4 + 4 + (field_count as usize) * 4;
        let set_len_padded = (set_len + 3) & !3;

        pkt.extend_from_slice(&2u16.to_be_bytes());
        pkt.extend_from_slice(&(set_len_padded as u16).to_be_bytes());
        pkt.extend_from_slice(&256u16.to_be_bytes());
        pkt.extend_from_slice(&field_count.to_be_bytes());

        pkt.extend_from_slice(&12u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes());
        pkt.extend_from_slice(&22u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes()); // FIRST_SWITCHED
        pkt.extend_from_slice(&21u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes()); // LAST_SWITCHED

        while pkt.len() < HEADER_LEN + set_len_padded {
            pkt.push(0);
        }

        // Data set: record = 4+4+4+4 = 16 bytes
        let record_len = 16;
        let data_set_len = 4 + record_len;
        let data_set_padded = (data_set_len + 3) & !3;

        pkt.extend_from_slice(&256u16.to_be_bytes());
        pkt.extend_from_slice(&(data_set_padded as u16).to_be_bytes());

        pkt.extend_from_slice(&Ipv4Addr::new(10, 1, 1, 1).octets());
        pkt.extend_from_slice(&500u32.to_be_bytes());
        pkt.extend_from_slice(&10_000u32.to_be_bytes()); // first_switched (10s after boot)
        pkt.extend_from_slice(&50_000u32.to_be_bytes()); // last_switched (50s after boot)

        while pkt.len() < HEADER_LEN + set_len_padded + data_set_padded {
            pkt.push(0);
        }

        let total_len = pkt.len() as u16;
        let len_bytes = total_len.to_be_bytes();
        pkt[2] = len_bytes[0];
        pkt[3] = len_bytes[1];

        let exporter = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut parser = IpfixParser::new();
        let mut flows = Vec::new();
        parser.parse_into(&pkt, exporter, &mut flows).unwrap();

        assert_eq!(flows.len(), 1);
        let f = &flows[0];
        assert_eq!(f.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)));
        assert_eq!(f.src_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(f.byte_count, 500);

        // With FIRST/LAST_SWITCHED fallback:
        // duration = last - first = 40_000ms
        // end = export_time_ms = 1_700_000_060_000
        // start = end - 40_000 = 1_700_000_020_000
        let start = f.flow_start_ms as u128;
        let end = f.flow_end_ms as u128;
        assert_eq!(end, 1_700_000_060_000);
        assert_eq!(start, 1_700_000_020_000);
    }

    #[test]
    fn test_sampling_interval() {
        let mut pkt = Vec::new();
        let export_time: u32 = 1_700_000_000;

        // Header
        pkt.extend_from_slice(&10u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes()); // length placeholder
        pkt.extend_from_slice(&export_time.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());

        // Template: IPV4_DST_ADDR, IN_BYTES, IN_PACKETS, samplingPacketInterval(305)
        let field_count: u16 = 4;
        let set_len = 4 + 4 + (field_count as usize) * 4;
        let set_len_padded = (set_len + 3) & !3;

        pkt.extend_from_slice(&2u16.to_be_bytes());
        pkt.extend_from_slice(&(set_len_padded as u16).to_be_bytes());
        pkt.extend_from_slice(&256u16.to_be_bytes());
        pkt.extend_from_slice(&field_count.to_be_bytes());

        pkt.extend_from_slice(&12u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes()); // IPV4_DST_ADDR
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes()); // IN_BYTES
        pkt.extend_from_slice(&2u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes()); // IN_PACKETS
        pkt.extend_from_slice(&305u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes()); // samplingPacketInterval

        while pkt.len() < HEADER_LEN + set_len_padded {
            pkt.push(0);
        }

        // Data set: record = 4+4+4+4 = 16 bytes
        let record_len = 16;
        let data_set_len = 4 + record_len;
        let data_set_padded = (data_set_len + 3) & !3;

        pkt.extend_from_slice(&256u16.to_be_bytes());
        pkt.extend_from_slice(&(data_set_padded as u16).to_be_bytes());

        pkt.extend_from_slice(&Ipv4Addr::new(10, 1, 1, 1).octets());
        pkt.extend_from_slice(&1000u32.to_be_bytes()); // in_bytes
        pkt.extend_from_slice(&5u32.to_be_bytes()); // in_packets
        pkt.extend_from_slice(&100u32.to_be_bytes()); // sampling interval = 1:100

        while pkt.len() < HEADER_LEN + set_len_padded + data_set_padded {
            pkt.push(0);
        }

        let total_len = pkt.len() as u16;
        let len_bytes = total_len.to_be_bytes();
        pkt[2] = len_bytes[0];
        pkt[3] = len_bytes[1];

        let exporter = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut parser = IpfixParser::new();
        let mut flows = Vec::new();
        parser.parse_into(&pkt, exporter, &mut flows).unwrap();

        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].byte_count, 1000 * 100);
        assert_eq!(flows[0].packet_count, 5 * 100);
    }
}
