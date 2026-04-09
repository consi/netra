use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
// SystemTime removed: we use u64 epoch millis directly

use dashmap::DashMap;

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
const SAMPLER_ID: u16 = 48;
const SAMPLER_RANDOM_INTERVAL: u16 = 50;
const FLOW_START_SEC: u16 = 150;
const FLOW_END_SEC: u16 = 151;
const FLOW_START_MS: u16 = 152;
const FLOW_END_MS: u16 = 153;
const SELECTOR_ID: u16 = 302;
const SAMPLING_PACKET_INTERVAL: u16 = 305;
const SAMPLING_PACKET_SPACE: u16 = 306;

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
    /// samplerId (48) or selectorId (302) — used to look up per-sampler rate from options data.
    sampler_id: Option<FieldLoc>,
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
    sampler_id: Option<usize>,
}

/// Describes the layout of an options template so we can extract the sampling interval
/// from options data records.
#[derive(Clone, Debug)]
struct OptionsTemplate {
    record_len: usize,
    sampling_interval: Option<FieldLoc>,
    sampler_id: Option<FieldLoc>,
    sampling_packet_space: Option<FieldLoc>,
}

/// Shared template and sampling-rate state for IPFIX, safe for concurrent access
/// across multiple SO_REUSEPORT listener threads.
pub struct IpfixCache {
    templates: DashMap<(IpAddr, u32, u16), (ResolvedIpfixTemplate, FieldIndices)>,
    options_templates: DashMap<(IpAddr, u32, u16), OptionsTemplate>,
    sampling_rates: DashMap<(IpAddr, u32, u64), u64>,
}

impl IpfixCache {
    pub fn new() -> Self {
        Self {
            templates: DashMap::new(),
            options_templates: DashMap::new(),
            sampling_rates: DashMap::new(),
        }
    }
}

pub struct IpfixParser {
    cache: Arc<IpfixCache>,
}

impl IpfixParser {
    pub fn new(cache: Arc<IpfixCache>) -> Self {
        Self { cache }
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
                    // Options Template Set
                    self.parse_options_template_set(
                        data,
                        cursor + 4,
                        set_end,
                        exporter,
                        observation_domain_id,
                    )?;
                }
                id if id >= 256 => {
                    // Data Set — could be flow data or options data
                    let key = (exporter, observation_domain_id, id);
                    if let Some(opts_tmpl) = self
                        .cache
                        .options_templates
                        .get(&key)
                        .map(|r| r.value().clone())
                    {
                        // Options data record — extract sampling rate
                        self.parse_options_data_set(
                            data,
                            cursor + 4,
                            set_end,
                            &opts_tmpl,
                            exporter,
                            observation_domain_id,
                        );
                    } else if let Some((tmpl, indices)) =
                        self.cache.templates.get(&key).map(|r| r.value().clone())
                    {
                        self.parse_data_set(
                            data,
                            cursor + 4,
                            set_end,
                            &tmpl,
                            &indices,
                            export_time,
                            exporter,
                            observation_domain_id,
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

    fn parse_options_template_set(
        &mut self,
        data: &[u8],
        mut pos: usize,
        end: usize,
        exporter: IpAddr,
        observation_domain_id: u32,
    ) -> Result<(), ParseError> {
        while pos + 6 <= end {
            let template_id = read_u16(data, pos);
            let total_field_count = read_u16(data, pos + 2) as usize;
            let scope_field_count = read_u16(data, pos + 4) as usize;
            pos += 6;
            let _ = scope_field_count; // not needed for our purposes

            let mut sampling_loc: Option<FieldLoc> = None;
            let mut sampler_id_loc: Option<FieldLoc> = None;
            let mut sampling_space_loc: Option<FieldLoc> = None;
            let mut offset = 0usize;

            for _ in 0..total_field_count {
                if pos + 4 > end {
                    return Err(ParseError::MalformedTemplate);
                }

                let raw_id = read_u16(data, pos);
                let field_length = read_u16(data, pos + 2);
                pos += 4;

                let enterprise_bit = raw_id & 0x8000 != 0;
                let element_id = raw_id & 0x7FFF;

                if enterprise_bit {
                    if pos + 4 > end {
                        return Err(ParseError::MalformedTemplate);
                    }
                    pos += 4; // skip PEN
                }

                if !enterprise_bit && field_length != VARIABLE_LENGTH {
                    let loc = FieldLoc {
                        offset,
                        length: field_length as usize,
                    };
                    match element_id {
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
                }

                if field_length != VARIABLE_LENGTH {
                    offset += field_length as usize;
                }
            }

            self.cache.options_templates.insert(
                (exporter, observation_domain_id, template_id),
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

    fn parse_options_data_set(
        &mut self,
        data: &[u8],
        start: usize,
        end: usize,
        tmpl: &OptionsTemplate,
        exporter: IpAddr,
        observation_domain_id: u32,
    ) {
        if tmpl.record_len == 0 {
            return;
        }

        let mut pos = start;
        while pos + tmpl.record_len <= end {
            let rec = &data[pos..pos + tmpl.record_len];

            if let Some(loc) = &tmpl.sampling_interval {
                let mut rate = read_uint(rec, loc.offset, loc.length);

                // If samplingPacketSpace (306) is present, compute effective rate:
                // rate = (interval + space) / interval  (like Akvorado)
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
                    self.cache
                        .sampling_rates
                        .insert((exporter, observation_domain_id, sampler_id), rate);
                }
            }

            pos += tmpl.record_len;
        }
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
                sampler_id: None,
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
                        SAMPLING_INTERVAL | SAMPLING_PACKET_INTERVAL | SAMPLER_RANDOM_INTERVAL => {
                            tmpl.sampling_interval = Some(loc);
                            indices.sampling_interval = Some(field_idx);
                        }
                        SAMPLER_ID | SELECTOR_ID => {
                            tmpl.sampler_id = Some(loc);
                            indices.sampler_id = Some(field_idx);
                        }
                        _ => {}
                    }
                }

                if !is_variable {
                    offset += field_length as usize;
                }
            }

            tmpl.record_len = offset; // Only meaningful if no variable-length fields.
            self.cache.templates.insert(
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
        exporter: IpAddr,
        observation_domain_id: u32,
        flows: &mut Vec<ExtractedFlow>,
    ) {
        if tmpl.has_variable_fields {
            self.parse_data_set_variable(
                data,
                start,
                end,
                tmpl,
                indices,
                export_time,
                exporter,
                observation_domain_id,
                flows,
            );
        } else {
            self.parse_data_set_fixed(
                data,
                start,
                end,
                tmpl,
                export_time,
                exporter,
                observation_domain_id,
                flows,
            );
        }
    }

    /// Fast path: all fields are fixed-length, offsets precomputed.
    #[allow(clippy::too_many_arguments)]
    fn parse_data_set_fixed(
        &self,
        data: &[u8],
        start: usize,
        end: usize,
        tmpl: &ResolvedIpfixTemplate,
        export_time: u64,
        exporter: IpAddr,
        observation_domain_id: u32,
        flows: &mut Vec<ExtractedFlow>,
    ) {
        if tmpl.record_len == 0 {
            return;
        }

        let mut pos = start;
        while pos + tmpl.record_len <= end {
            let rec = &data[pos..pos + tmpl.record_len];

            if let Some(flow) =
                self.extract_flow_fixed(rec, tmpl, export_time, exporter, observation_domain_id)
            {
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
        exporter: IpAddr,
        observation_domain_id: u32,
    ) -> Option<ExtractedFlow> {
        let dst_ip = self.extract_ip(rec, &tmpl.dst_ipv6, &tmpl.dst_ipv4)?;
        let src_ip = self
            .extract_ip(rec, &tmpl.src_ipv6, &tmpl.src_ipv4)
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

        let sampling_rate = self.resolve_sampling_rate(rec, tmpl, exporter, observation_domain_id);

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

    /// Resolve sampling rate for a fixed-length record.
    /// Priority: inline sampling field > per-sampler options rate > global options rate > 1.
    fn resolve_sampling_rate(
        &self,
        rec: &[u8],
        tmpl: &ResolvedIpfixTemplate,
        exporter: IpAddr,
        observation_domain_id: u32,
    ) -> u64 {
        // 1. Inline sampling field in data record (element 34/305/50).
        if let Some(loc) = &tmpl.sampling_interval {
            let v = read_uint(rec, loc.offset, loc.length);
            if v > 1 {
                return v;
            }
        }

        // 2. Look up by sampler_id from data record against options-learned rates.
        if let Some(loc) = &tmpl.sampler_id {
            let sid = read_uint(rec, loc.offset, loc.length);
            if let Some(rate) = self
                .cache
                .sampling_rates
                .get(&(exporter, observation_domain_id, sid))
                .map(|r| *r.value())
            {
                return rate.max(1);
            }
        }

        // 3. Global options rate (sampler_id=0).
        self.cache
            .sampling_rates
            .get(&(exporter, observation_domain_id, 0))
            .map(|r| *r.value())
            .unwrap_or(1)
            .max(1)
    }

    /// Resolve sampling rate for a variable-length record.
    fn resolve_sampling_rate_var(
        &self,
        data: &[u8],
        field_offsets: &[(usize, usize)],
        indices: &FieldIndices,
        exporter: IpAddr,
        observation_domain_id: u32,
    ) -> u64 {
        // 1. Inline sampling field.
        if let Some(idx) = indices.sampling_interval {
            let (off, len) = field_offsets[idx];
            let v = read_uint(data, off, len);
            if v > 1 {
                return v;
            }
        }

        // 2. Look up by sampler_id.
        if let Some(idx) = indices.sampler_id {
            let (off, len) = field_offsets[idx];
            let sid = read_uint(data, off, len);
            if let Some(rate) = self
                .cache
                .sampling_rates
                .get(&(exporter, observation_domain_id, sid))
                .map(|r| *r.value())
            {
                return rate.max(1);
            }
        }

        // 3. Global options rate.
        self.cache
            .sampling_rates
            .get(&(exporter, observation_domain_id, 0))
            .map(|r| *r.value())
            .unwrap_or(1)
            .max(1)
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
        exporter: IpAddr,
        observation_domain_id: u32,
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

            let sampling_rate = self.resolve_sampling_rate_var(
                data,
                &field_offsets,
                indices,
                exporter,
                observation_domain_id,
            );

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
                sampler_id: None,
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

        let mut parser = IpfixParser::new(Arc::new(IpfixCache::new()));
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
        let mut parser = IpfixParser::new(Arc::new(IpfixCache::new()));
        let mut flows = Vec::new();
        parser.parse_into(&pkt, exporter, &mut flows).unwrap();
        assert!(flows.is_empty()); // no data set, just template

        // Verify template was stored: key (localhost, 1, 300)
        assert!(parser.cache.templates.contains_key(&(exporter, 1, 300)));
    }

    #[test]
    fn test_too_short() {
        let mut parser = IpfixParser::new(Arc::new(IpfixCache::new()));
        let exporter = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(
            parser
                .parse_into(&[0; 10], exporter, &mut Vec::new())
                .is_err()
        );
    }

    #[test]
    fn test_bad_version() {
        let mut parser = IpfixParser::new(Arc::new(IpfixCache::new()));
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
        let mut parser = IpfixParser::new(Arc::new(IpfixCache::new()));
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
        let mut parser = IpfixParser::new(Arc::new(IpfixCache::new()));
        let mut flows = Vec::new();
        parser.parse_into(&pkt, exporter, &mut flows).unwrap();

        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].byte_count, 1000 * 100);
        assert_eq!(flows[0].packet_count, 5 * 100);
    }

    #[test]
    fn test_options_template_sampling() {
        // Simulate the common pattern: sampling rate is in an Options Template/Data,
        // not in the data template itself.
        let mut pkt = Vec::new();
        let export_time: u32 = 1_700_000_000;
        let observation_domain_id: u32 = 42;

        // Header
        pkt.extend_from_slice(&10u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes()); // length placeholder
        pkt.extend_from_slice(&export_time.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.extend_from_slice(&observation_domain_id.to_be_bytes());

        // --- Data Template (set_id=2): id=256, fields: IPV4_DST_ADDR, IN_BYTES, IN_PACKETS ---
        let field_count: u16 = 3;
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
        pkt.extend_from_slice(&2u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes());
        while pkt.len() < HEADER_LEN + set_len_padded {
            pkt.push(0);
        }
        let after_tmpl = pkt.len();

        // --- Options Template (set_id=3): id=512, scope: 1 field, option: SAMPLING_INTERVAL ---
        // scope field: some scope (e.g., id=144/exporterIPv4, len=4)
        // option field: SAMPLING_INTERVAL (id=34, len=4)
        let opts_total_fields: u16 = 2;
        let opts_scope_fields: u16 = 1;
        let opts_set_len = 4 + 6 + (opts_total_fields as usize) * 4; // set hdr + tmpl hdr + fields
        let opts_set_len_padded = (opts_set_len + 3) & !3;
        pkt.extend_from_slice(&3u16.to_be_bytes());
        pkt.extend_from_slice(&(opts_set_len_padded as u16).to_be_bytes());
        pkt.extend_from_slice(&512u16.to_be_bytes());
        pkt.extend_from_slice(&opts_total_fields.to_be_bytes());
        pkt.extend_from_slice(&opts_scope_fields.to_be_bytes());
        // Scope field: id=144, len=4
        pkt.extend_from_slice(&144u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes());
        // Option field: SAMPLING_INTERVAL id=34, len=4
        pkt.extend_from_slice(&34u16.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes());
        while pkt.len() < after_tmpl + opts_set_len_padded {
            pkt.push(0);
        }
        let after_opts_tmpl = pkt.len();

        // --- Options Data (set_id=512): record = scope(4) + sampling(4) = 8 bytes ---
        let opts_record_len = 8;
        let opts_data_set_len = 4 + opts_record_len;
        let opts_data_set_padded = (opts_data_set_len + 3) & !3;
        pkt.extend_from_slice(&512u16.to_be_bytes());
        pkt.extend_from_slice(&(opts_data_set_padded as u16).to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // scope value (don't care)
        pkt.extend_from_slice(&1024u32.to_be_bytes()); // sampling interval = 1024
        while pkt.len() < after_opts_tmpl + opts_data_set_padded {
            pkt.push(0);
        }
        let after_opts_data = pkt.len();

        // --- Data Set (set_id=256): record = dst_ip(4) + in_bytes(4) + in_packets(4) = 12 ---
        let record_len = 12;
        let data_set_len = 4 + record_len;
        let data_set_padded = (data_set_len + 3) & !3;
        pkt.extend_from_slice(&256u16.to_be_bytes());
        pkt.extend_from_slice(&(data_set_padded as u16).to_be_bytes());
        pkt.extend_from_slice(&Ipv4Addr::new(10, 1, 1, 1).octets());
        pkt.extend_from_slice(&500u32.to_be_bytes());
        pkt.extend_from_slice(&5u32.to_be_bytes());
        while pkt.len() < after_opts_data + data_set_padded {
            pkt.push(0);
        }

        // Fill in message length
        let total_len = pkt.len() as u16;
        pkt[2] = total_len.to_be_bytes()[0];
        pkt[3] = total_len.to_be_bytes()[1];

        let exporter = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut parser = IpfixParser::new(Arc::new(IpfixCache::new()));
        let mut flows = Vec::new();
        parser.parse_into(&pkt, exporter, &mut flows).unwrap();

        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].byte_count, 500 * 1024);
        assert_eq!(flows[0].packet_count, 5 * 1024);
    }

    #[test]
    fn test_options_sampling_across_packets() {
        // Options data arrives in a separate packet before data flows.
        let exporter = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let observation_domain_id: u32 = 42;
        let export_time: u32 = 1_700_000_000;
        let mut parser = IpfixParser::new(Arc::new(IpfixCache::new()));

        // Packet 1: data template + options template + options data
        let mut pkt1 = Vec::new();
        pkt1.extend_from_slice(&10u16.to_be_bytes());
        pkt1.extend_from_slice(&0u16.to_be_bytes());
        pkt1.extend_from_slice(&export_time.to_be_bytes());
        pkt1.extend_from_slice(&0u32.to_be_bytes());
        pkt1.extend_from_slice(&observation_domain_id.to_be_bytes());

        // Data template: id=256, fields: IPV4_DST_ADDR(4), IN_BYTES(4)
        let tmpl_set_len = 4 + 4 + 2 * 4; // 16
        let tmpl_set_padded = (tmpl_set_len + 3) & !3;
        pkt1.extend_from_slice(&2u16.to_be_bytes());
        pkt1.extend_from_slice(&(tmpl_set_padded as u16).to_be_bytes());
        pkt1.extend_from_slice(&256u16.to_be_bytes());
        pkt1.extend_from_slice(&2u16.to_be_bytes());
        pkt1.extend_from_slice(&12u16.to_be_bytes());
        pkt1.extend_from_slice(&4u16.to_be_bytes());
        pkt1.extend_from_slice(&1u16.to_be_bytes());
        pkt1.extend_from_slice(&4u16.to_be_bytes());
        while pkt1.len() < HEADER_LEN + tmpl_set_padded {
            pkt1.push(0);
        }
        let p1 = pkt1.len();

        // Options template: id=512, 1 scope + 1 option (SAMPLING_INTERVAL)
        let opts_set_len = 4 + 6 + 2 * 4;
        let opts_set_padded = (opts_set_len + 3) & !3;
        pkt1.extend_from_slice(&3u16.to_be_bytes());
        pkt1.extend_from_slice(&(opts_set_padded as u16).to_be_bytes());
        pkt1.extend_from_slice(&512u16.to_be_bytes());
        pkt1.extend_from_slice(&2u16.to_be_bytes());
        pkt1.extend_from_slice(&1u16.to_be_bytes());
        pkt1.extend_from_slice(&144u16.to_be_bytes());
        pkt1.extend_from_slice(&4u16.to_be_bytes());
        pkt1.extend_from_slice(&34u16.to_be_bytes());
        pkt1.extend_from_slice(&4u16.to_be_bytes());
        while pkt1.len() < p1 + opts_set_padded {
            pkt1.push(0);
        }
        let p2 = pkt1.len();

        // Options data: scope(4) + sampling(4) = 8
        let opts_data_len = 4 + 8;
        let opts_data_padded = (opts_data_len + 3) & !3;
        pkt1.extend_from_slice(&512u16.to_be_bytes());
        pkt1.extend_from_slice(&(opts_data_padded as u16).to_be_bytes());
        pkt1.extend_from_slice(&0u32.to_be_bytes());
        pkt1.extend_from_slice(&512u32.to_be_bytes()); // sampling = 512
        while pkt1.len() < p2 + opts_data_padded {
            pkt1.push(0);
        }

        let len1 = pkt1.len() as u16;
        pkt1[2] = len1.to_be_bytes()[0];
        pkt1[3] = len1.to_be_bytes()[1];

        let mut flows = Vec::new();
        parser.parse_into(&pkt1, exporter, &mut flows).unwrap();
        assert!(flows.is_empty());

        // Packet 2: data only
        let mut pkt2 = Vec::new();
        pkt2.extend_from_slice(&10u16.to_be_bytes());
        pkt2.extend_from_slice(&0u16.to_be_bytes());
        pkt2.extend_from_slice(&export_time.to_be_bytes());
        pkt2.extend_from_slice(&1u32.to_be_bytes()); // different sequence
        pkt2.extend_from_slice(&observation_domain_id.to_be_bytes());

        let data_set_len = 4 + 8; // dst_ip(4) + in_bytes(4)
        let data_set_padded = (data_set_len + 3) & !3;
        pkt2.extend_from_slice(&256u16.to_be_bytes());
        pkt2.extend_from_slice(&(data_set_padded as u16).to_be_bytes());
        pkt2.extend_from_slice(&Ipv4Addr::new(10, 1, 1, 1).octets());
        pkt2.extend_from_slice(&200u32.to_be_bytes());
        while pkt2.len() < HEADER_LEN + data_set_padded {
            pkt2.push(0);
        }

        let len2 = pkt2.len() as u16;
        pkt2[2] = len2.to_be_bytes()[0];
        pkt2[3] = len2.to_be_bytes()[1];

        flows.clear();
        parser.parse_into(&pkt2, exporter, &mut flows).unwrap();

        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].byte_count, 200 * 512);
    }

    /// Regression test using real IPFIX payloads from a router with 1:1024 sampling.
    /// The sampling rate is conveyed via Options Template (set_id=3) / Options Data (set_id=512),
    /// not inline in data records. Template 256 has no sampling field at all.
    #[test]
    fn test_real_ipfix_data_options_sampling_1024() {
        let exporter = IpAddr::V4(Ipv4Addr::new(10, 0, 48, 204));
        let mut parser = IpfixParser::new(Arc::new(IpfixCache::new()));

        // Packet 1: Data template (set_id=2, template 256 with 29 fields, no sampling field).
        let tmpl_pkt: &[u8] = &[
            0x00, 0x0a, 0x00, 0x8c, 0x69, 0xd6, 0xa1, 0xfa, 0x5a, 0x29, 0xcd, 0x81, 0x00, 0x08,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x7c, 0x01, 0x00, 0x00, 0x1d, 0x00, 0x08, 0x00, 0x04,
            0x00, 0x0c, 0x00, 0x04, 0x00, 0x05, 0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x07,
            0x00, 0x02, 0x00, 0x0b, 0x00, 0x02, 0x00, 0x20, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x04,
            0x00, 0x3a, 0x00, 0x02, 0x00, 0x09, 0x00, 0x01, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x10,
            0x00, 0x04, 0x00, 0x11, 0x00, 0x04, 0x00, 0x0f, 0x00, 0x04, 0x00, 0x06, 0x00, 0x01,
            0x00, 0x0e, 0x00, 0x04, 0x00, 0x34, 0x00, 0x01, 0x00, 0x35, 0x00, 0x01, 0x00, 0x88,
            0x00, 0x01, 0x00, 0x3c, 0x00, 0x01, 0x00, 0x12, 0x00, 0x04, 0x00, 0x3d, 0x00, 0x01,
            0x00, 0xf3, 0x00, 0x02, 0x00, 0xf5, 0x00, 0x02, 0x00, 0x36, 0x00, 0x04, 0x00, 0x01,
            0x00, 0x08, 0x00, 0x02, 0x00, 0x08, 0x00, 0x98, 0x00, 0x08, 0x00, 0x99, 0x00, 0x08,
        ];

        let mut flows = Vec::new();
        parser.parse_into(tmpl_pkt, exporter, &mut flows).unwrap();
        assert!(flows.is_empty());

        // Packet 2: Options Template (set_id=3, template 512) — defines where sampling lives.
        let opts_tmpl_pkt: &[u8] = &[
            0x00, 0x0a, 0x00, 0x48, 0x69, 0xd6, 0xa1, 0xfa, 0x00, 0x07, 0x04, 0x3d, 0x00, 0x08,
            0x00, 0x00, 0x00, 0x03, 0x00, 0x38, 0x02, 0x00, 0x00, 0x0b, 0x00, 0x01, 0x00, 0x90,
            0x00, 0x04, 0x00, 0x29, 0x00, 0x08, 0x00, 0x2a, 0x00, 0x08, 0x00, 0xa0, 0x00, 0x08,
            0x00, 0x82, 0x00, 0x04, 0x00, 0x83, 0x00, 0x10, 0x00, 0x22, 0x00, 0x04, 0x00, 0x24,
            0x00, 0x02, 0x00, 0x25, 0x00, 0x02, 0x00, 0xd6, 0x00, 0x01, 0x00, 0xd7, 0x00, 0x01,
            0x00, 0x00, // padding
        ];

        parser
            .parse_into(opts_tmpl_pkt, exporter, &mut flows)
            .unwrap();
        assert!(flows.is_empty());

        // Packet 3: Options Data (set_id=512) — carries sampling_interval=1024.
        let opts_data_pkt: &[u8] = &[
            0x00, 0x0a, 0x00, 0x50, 0x69, 0xd6, 0xa2, 0x0b, 0x00, 0x07, 0x04, 0x3d, 0x00, 0x08,
            0x00, 0x00, 0x02, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01,
            0x7e, 0xf7, 0x95, 0xa2, 0x00, 0x00, 0x00, 0x05, 0xf6, 0xbd, 0xa6, 0x71, 0x00, 0x00,
            0x01, 0x9a, 0x37, 0xe1, 0x46, 0xf0, 0x0a, 0x00, 0x30, 0xcc, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x04, 0x00, // SAMPLING_INTERVAL = 0x400 = 1024
            0x00, 0x0a, 0x00, 0x0a, 0x0a, 0x11, 0x00, 0x00, // padding
        ];

        parser
            .parse_into(opts_data_pkt, exporter, &mut flows)
            .unwrap();
        assert!(flows.is_empty());
        assert_eq!(
            parser
                .cache
                .sampling_rates
                .get(&(exporter, 0x00080000, 0))
                .map(|r| *r.value()),
            Some(1024u64),
            "sampling rate 1024 must be learned from options data"
        );

        // Packet 4: Data flow (set_id=256) — first record: src=89.44.168.109, dst=193.19.165.106,
        // in_bytes=1500, in_packets=1. Should be multiplied by 1024.
        let data_pkt: &[u8] = &[
            0x00, 0x0a, 0x01, 0x7c, 0x69, 0xd6, 0xa1, 0xf9, 0x5a, 0x29, 0xcd, 0x81, 0x00, 0x08,
            0x00, 0x00, 0x01, 0x00, 0x01, 0x6c, // Record 1 (90 bytes):
            0x59, 0x2c, 0xa8, 0x6d, // src: 89.44.168.109
            0xc1, 0x13, 0xa5, 0x6a, // dst: 193.19.165.106
            0x28, // TOS
            0x06, // proto TCP
            0x01, 0xbb, // src_port 443
            0xf4, 0xe6, // dst_port 62694
            0x00, 0x00, // icmp type
            0x00, 0x00, 0x02, 0x62, // input snmp
            0x01, 0x36, // src_vlan 310
            0x18, // src prefix
            0x16, // dst prefix
            0x00, 0x03, 0x19, 0x2f, // bgp_src_as
            0x00, 0x00, 0x89, 0x7f, // bgp_dst_as
            0xc1, 0x5b, 0x05, 0xf7, // next_hop
            0x18, // tcp_flags
            0x00, 0x00, 0x02, 0x81, // output snmp
            0x36, // min_ttl
            0x36, // max_ttl
            0x02, // flow_end_reason
            0x04, // ip_version
            0xc1, 0x5b, 0x05, 0xf7, // unknown(18)
            0xff, // direction
            0x00, 0x00, // unknown(243)
            0x00, 0x00, // unknown(245)
            0x00, 0x00, 0x00, 0x00, // unknown(54)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc, // in_bytes = 1500
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // in_packets = 1
            0x00, 0x00, 0x01, 0x9d, 0x6e, 0x68, 0x61, 0x00, // flow_start_ms
            0x00, 0x00, 0x01, 0x9d, 0x6e, 0x68, 0xa2, 0x00, // flow_end_ms
            // Record 2:
            0x03, 0x05, 0x7a, 0x71, 0x6d, 0x5f, 0x8f, 0x3f, 0x00, 0x06, 0x01, 0xbb, 0xb6, 0xbf,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x38, 0x02, 0x68, 0x18, 0x17, 0x00, 0x00, 0x40, 0x7d,
            0x00, 0x00, 0xac, 0x36, 0xc1, 0x5b, 0x05, 0xcb, 0x10, 0x00, 0x00, 0x02, 0xad, 0xfa,
            0xfa, 0x02, 0x04, 0xc1, 0x5b, 0x05, 0xcb, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xc8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x9d, 0x6e, 0x68, 0x8e, 0x00, 0x00, 0x00,
            0x01, 0x9d, 0x6e, 0x68, 0x8e, 0x00, // Record 3:
            0x68, 0x12, 0x04, 0xf6, 0xb9, 0x1d, 0x0c, 0xaf, 0x00, 0x06, 0x01, 0xbb, 0x9b, 0x78,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x38, 0x02, 0x68, 0x14, 0x16, 0x00, 0x00, 0x34, 0x17,
            0x00, 0x00, 0xec, 0xad, 0xc1, 0x5b, 0x05, 0xdb, 0x18, 0x00, 0x00, 0x02, 0x6b, 0x3e,
            0x3e, 0x02, 0x04, 0xc1, 0x5b, 0x05, 0xa7, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xe1, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x9d, 0x6e, 0x68, 0x88, 0x00, 0x00, 0x00,
            0x01, 0x9d, 0x6e, 0x68, 0x88, 0x00, // Record 4:
            0x95, 0x38, 0xf0, 0x46, 0xb9, 0x87, 0xc2, 0xac, 0x18, 0x06, 0x01, 0xbb, 0xe2, 0x24,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x38, 0x02, 0x68, 0x10, 0x18, 0x00, 0x00, 0x3f, 0x94,
            0x00, 0x00, 0xe8, 0x44, 0xc1, 0x5b, 0x05, 0xff, 0x10, 0x00, 0x00, 0x02, 0xa1, 0x35,
            0x35, 0x02, 0x04, 0xc1, 0x5b, 0x05, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0xa8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x9d, 0x6e, 0x67, 0xc6, 0x00, 0x00, 0x00,
            0x01, 0x9d, 0x6e, 0x68, 0x9e, 0x00,
        ];

        flows.clear();
        parser.parse_into(data_pkt, exporter, &mut flows).unwrap();

        assert_eq!(flows.len(), 4, "should parse 4 data records");

        // Record 1: in_bytes=1500, in_packets=1, multiplied by 1024
        let f = &flows[0];
        assert_eq!(f.src_ip, IpAddr::V4(Ipv4Addr::new(89, 44, 168, 109)));
        assert_eq!(f.dst_ip, IpAddr::V4(Ipv4Addr::new(193, 19, 165, 106)));
        assert_eq!(f.byte_count, 1500 * 1024);
        assert_eq!(f.packet_count, 1 * 1024);
        assert_eq!(f.vlan_id, 310);

        // All records should have sampling applied
        for (i, f) in flows.iter().enumerate() {
            assert!(
                f.byte_count > 0 && f.byte_count % 1024 == 0,
                "record {i}: byte_count {} should be a multiple of 1024",
                f.byte_count,
            );
            assert!(
                f.packet_count > 0 && f.packet_count % 1024 == 0,
                "record {i}: packet_count {} should be a multiple of 1024",
                f.packet_count,
            );
        }
    }

    /// Test the sampler-based model: options template defines samplerId (48) + samplerRandomInterval (50),
    /// data template contains samplerId (48) for lookup. Like Juniper MX / Cisco patterns.
    #[test]
    fn test_sampler_id_based_sampling() {
        let exporter = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut parser = IpfixParser::new(Arc::new(IpfixCache::new()));
        let mut flows = Vec::new();

        // Packet 1: Options Template (set_id=3, template 512).
        // Set: 4 header + 6 tmpl header + 8 fields = 18 bytes.  Packet: 16 + 18 = 34.
        #[rustfmt::skip]
        let opts_tmpl_pkt: &[u8] = &[
            // IPFIX header (16 bytes)
            0x00, 0x0a, 0x00, 0x22, // version=10, length=34
            0x00, 0x00, 0x03, 0xe8, // export_time
            0x00, 0x00, 0x00, 0x00, // seq
            0x00, 0x00, 0x00, 0x01, // obs_domain=1
            // Options Template Set (18 bytes)
            0x00, 0x03, 0x00, 0x12, // set_id=3, length=18
            0x02, 0x00, 0x00, 0x02, 0x00, 0x01, // tmpl_id=512, total=2, scope=1
            0x00, 0x30, 0x00, 0x02, // samplerId(48), 2 bytes
            0x00, 0x32, 0x00, 0x04, // samplerRandomInterval(50), 4 bytes
        ];
        parser
            .parse_into(opts_tmpl_pkt, exporter, &mut flows)
            .unwrap();

        // Packet 2: Options Data (set_id=512).  Record: 2+4 = 6 bytes.  Set: 4+6 = 10.  Packet: 26.
        #[rustfmt::skip]
        let opts_data_pkt: &[u8] = &[
            0x00, 0x0a, 0x00, 0x1a, // version=10, length=26
            0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x02, 0x00, 0x00, 0x0a, // set_id=512, length=10
            0x00, 0x05,             // samplerId=5
            0x00, 0x00, 0x07, 0xd0, // samplerRandomInterval=2000
        ];
        parser
            .parse_into(opts_data_pkt, exporter, &mut flows)
            .unwrap();
        assert_eq!(
            parser
                .cache
                .sampling_rates
                .get(&(exporter, 1, 5))
                .map(|r| *r.value()),
            Some(2000u64)
        );

        // Packet 3: Data Template (set_id=2, template 256).
        // 7 fields * 4 = 28.  Set: 4 + 4 + 28 = 36.  Packet: 16+36 = 52.
        #[rustfmt::skip]
        let data_tmpl_pkt: &[u8] = &[
            0x00, 0x0a, 0x00, 0x34, // version=10, length=52
            0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x02, 0x00, 0x24, // set_id=2, length=36
            0x01, 0x00, 0x00, 0x07, // tmpl_id=256, field_count=7
            0x00, 0x08, 0x00, 0x04, // srcIPv4(8), 4
            0x00, 0x0c, 0x00, 0x04, // dstIPv4(12), 4
            0x00, 0x01, 0x00, 0x04, // inBytes(1), 4
            0x00, 0x02, 0x00, 0x04, // inPackets(2), 4
            0x00, 0x30, 0x00, 0x02, // samplerId(48), 2
            0x00, 0x98, 0x00, 0x08, // flowStartMs(152), 8
            0x00, 0x99, 0x00, 0x08, // flowEndMs(153), 8
        ];
        parser
            .parse_into(data_tmpl_pkt, exporter, &mut flows)
            .unwrap();

        // Packet 4: Data record (set_id=256).  Record: 4+4+4+4+2+8+8 = 34.  Set: 38.  Packet: 54.
        #[rustfmt::skip]
        let data_pkt: &[u8] = &[
            0x00, 0x0a, 0x00, 0x36, // version=10, length=54
            0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x01, 0x00, 0x00, 0x26, // set_id=256, length=38
            0x0a, 0x00, 0x00, 0x01, // src: 10.0.0.1
            0x0a, 0x00, 0x00, 0x02, // dst: 10.0.0.2
            0x00, 0x00, 0x01, 0xf4, // inBytes=500
            0x00, 0x00, 0x00, 0x03, // inPackets=3
            0x00, 0x05,             // samplerId=5
            0x00, 0x00, 0x01, 0x90, 0x00, 0x00, 0x00, 0x00, // flowStartMs
            0x00, 0x00, 0x01, 0x90, 0x00, 0x00, 0x10, 0x00, // flowEndMs
        ];
        parser.parse_into(data_pkt, exporter, &mut flows).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].byte_count, 500 * 2000);
        assert_eq!(flows[0].packet_count, 3 * 2000);
    }

    /// Test samplingPacketInterval (305) + samplingPacketSpace (306) in options.
    /// Effective rate = (interval + space) / interval. E.g. interval=1, space=999 → rate=1000.
    #[test]
    fn test_sampling_packet_space() {
        let exporter = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut parser = IpfixParser::new(Arc::new(IpfixCache::new()));
        let mut flows = Vec::new();

        // Options Template (set_id=3, template 512).
        // 2 fields * 4 = 8.  Set: 4 + 6 + 8 = 18.  Packet: 34.
        #[rustfmt::skip]
        let opts_tmpl_pkt: &[u8] = &[
            0x00, 0x0a, 0x00, 0x22, // version=10, length=34
            0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x03, 0x00, 0x12, // set_id=3, length=18
            0x02, 0x00, 0x00, 0x02, 0x00, 0x00, // tmpl_id=512, total=2, scope=0
            0x01, 0x31, 0x00, 0x04, // samplingPacketInterval(305), 4
            0x01, 0x32, 0x00, 0x04, // samplingPacketSpace(306), 4
        ];
        parser
            .parse_into(opts_tmpl_pkt, exporter, &mut flows)
            .unwrap();

        // Options Data (set_id=512).  Record: 4+4 = 8.  Set: 12.  Packet: 28.
        #[rustfmt::skip]
        let opts_data_pkt: &[u8] = &[
            0x00, 0x0a, 0x00, 0x1c, // version=10, length=28
            0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x02, 0x00, 0x00, 0x0c, // set_id=512, length=12
            0x00, 0x00, 0x00, 0x01, // samplingPacketInterval=1
            0x00, 0x00, 0x03, 0xe7, // samplingPacketSpace=999
        ];
        parser
            .parse_into(opts_data_pkt, exporter, &mut flows)
            .unwrap();
        assert_eq!(
            parser
                .cache
                .sampling_rates
                .get(&(exporter, 1, 0))
                .map(|r| *r.value()),
            Some(1000u64),
            "rate should be (1+999)/1 = 1000"
        );

        // Data Template (set_id=2, template 256).
        // 6 fields * 4 = 24.  Set: 4+4+24 = 32.  Packet: 48.
        #[rustfmt::skip]
        let data_tmpl_pkt: &[u8] = &[
            0x00, 0x0a, 0x00, 0x30, // version=10, length=48
            0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x02, 0x00, 0x20, // set_id=2, length=32
            0x01, 0x00, 0x00, 0x06, // tmpl_id=256, field_count=6
            0x00, 0x08, 0x00, 0x04, // srcIPv4(8), 4
            0x00, 0x0c, 0x00, 0x04, // dstIPv4(12), 4
            0x00, 0x01, 0x00, 0x04, // inBytes(1), 4
            0x00, 0x02, 0x00, 0x04, // inPackets(2), 4
            0x00, 0x98, 0x00, 0x08, // flowStartMs(152), 8
            0x00, 0x99, 0x00, 0x08, // flowEndMs(153), 8
        ];
        parser
            .parse_into(data_tmpl_pkt, exporter, &mut flows)
            .unwrap();

        // Data record (set_id=256).  Record: 4+4+4+4+8+8 = 32.  Set: 36.  Packet: 52.
        #[rustfmt::skip]
        let data_pkt: &[u8] = &[
            0x00, 0x0a, 0x00, 0x34, // version=10, length=52
            0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x01, 0x00, 0x00, 0x24, // set_id=256, length=36
            0x0a, 0x00, 0x00, 0x01, // src: 10.0.0.1
            0x0a, 0x00, 0x00, 0x02, // dst: 10.0.0.2
            0x00, 0x00, 0x00, 0x64, // inBytes=100
            0x00, 0x00, 0x00, 0x02, // inPackets=2
            0x00, 0x00, 0x01, 0x90, 0x00, 0x00, 0x00, 0x00, // flowStartMs
            0x00, 0x00, 0x01, 0x90, 0x00, 0x00, 0x10, 0x00, // flowEndMs
        ];
        parser.parse_into(data_pkt, exporter, &mut flows).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].byte_count, 100_000);
        assert_eq!(flows[0].packet_count, 2_000);
    }

    /// Two IPFIX exporters with different sampling rates share the same cache.
    /// Templates and options learned on one parser are used by another, simulating
    /// SO_REUSEPORT packet distribution across threads.
    #[test]
    fn test_shared_cache_multiple_exporters() {
        let cache = Arc::new(IpfixCache::new());
        let mut parser_a = IpfixParser::new(cache.clone());
        let mut parser_b = IpfixParser::new(cache.clone());

        let router1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let router2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let obs_domain: u32 = 1;

        // Helper: build an IPFIX header
        fn ipfix_hdr(pkt: &mut Vec<u8>, length: u16, export_time: u32, obs_domain: u32) {
            pkt.extend_from_slice(&10u16.to_be_bytes());
            pkt.extend_from_slice(&length.to_be_bytes());
            pkt.extend_from_slice(&export_time.to_be_bytes());
            pkt.extend_from_slice(&0u32.to_be_bytes());
            pkt.extend_from_slice(&obs_domain.to_be_bytes());
        }

        // --- Router 1 template arrives on parser A ---
        // Template 256: SRC_IPV4(4), DST_IPV4(4), IN_BYTES(4), IN_PACKETS(4), SAMPLING_INTERVAL(4)
        let field_count: u16 = 5;
        let tmpl_set_len = 4 + 4 + (field_count as usize) * 4; // set header + tmpl header + fields
        let tmpl_set_padded = (tmpl_set_len + 3) & !3;
        let pkt_len = 16 + tmpl_set_padded;

        let mut pkt1 = Vec::new();
        ipfix_hdr(&mut pkt1, pkt_len as u16, 1_700_000_000, obs_domain);
        pkt1.extend_from_slice(&2u16.to_be_bytes()); // set_id=2 (template)
        pkt1.extend_from_slice(&(tmpl_set_padded as u16).to_be_bytes());
        pkt1.extend_from_slice(&256u16.to_be_bytes());
        pkt1.extend_from_slice(&field_count.to_be_bytes());
        for &(ft, fl) in &[(8, 4), (12, 4), (1, 4), (2, 4), (34, 4)] {
            pkt1.extend_from_slice(&(ft as u16).to_be_bytes());
            pkt1.extend_from_slice(&(fl as u16).to_be_bytes());
        }
        while pkt1.len() < pkt_len {
            pkt1.push(0);
        }
        parser_a
            .parse_into(&pkt1, router1, &mut Vec::new())
            .unwrap();

        // --- Router 2 template arrives on parser B (same layout) ---
        let mut pkt2 = Vec::new();
        ipfix_hdr(&mut pkt2, pkt_len as u16, 1_700_000_000, obs_domain);
        pkt2.extend_from_slice(&2u16.to_be_bytes());
        pkt2.extend_from_slice(&(tmpl_set_padded as u16).to_be_bytes());
        pkt2.extend_from_slice(&256u16.to_be_bytes());
        pkt2.extend_from_slice(&field_count.to_be_bytes());
        for &(ft, fl) in &[(8, 4), (12, 4), (1, 4), (2, 4), (34, 4)] {
            pkt2.extend_from_slice(&(ft as u16).to_be_bytes());
            pkt2.extend_from_slice(&(fl as u16).to_be_bytes());
        }
        while pkt2.len() < pkt_len {
            pkt2.push(0);
        }
        parser_b
            .parse_into(&pkt2, router2, &mut Vec::new())
            .unwrap();

        // --- Router 1 data on parser B (cross-thread), sampling=100 ---
        let record_len = 20; // 4+4+4+4+4
        let data_set_len = (4 + record_len + 3) & !3;
        let data_pkt_len = 16 + data_set_len;

        let mut d1 = Vec::new();
        ipfix_hdr(&mut d1, data_pkt_len as u16, 1_700_000_000, obs_domain);
        d1.extend_from_slice(&256u16.to_be_bytes());
        d1.extend_from_slice(&(data_set_len as u16).to_be_bytes());
        d1.extend_from_slice(&Ipv4Addr::new(192, 168, 1, 1).octets());
        d1.extend_from_slice(&Ipv4Addr::new(10, 1, 1, 1).octets());
        d1.extend_from_slice(&1000u32.to_be_bytes());
        d1.extend_from_slice(&5u32.to_be_bytes());
        d1.extend_from_slice(&100u32.to_be_bytes()); // sampling=100
        while d1.len() < data_pkt_len {
            d1.push(0);
        }

        let mut flows = Vec::new();
        parser_b.parse_into(&d1, router1, &mut flows).unwrap();
        assert_eq!(
            flows.len(),
            1,
            "parser B must decode router 1 data via shared cache"
        );
        assert_eq!(flows[0].byte_count, 1000 * 100);
        assert_eq!(flows[0].packet_count, 5 * 100);

        // --- Router 2 data on parser A (cross-thread), sampling=500 ---
        let mut d2 = Vec::new();
        ipfix_hdr(&mut d2, data_pkt_len as u16, 1_700_000_000, obs_domain);
        d2.extend_from_slice(&256u16.to_be_bytes());
        d2.extend_from_slice(&(data_set_len as u16).to_be_bytes());
        d2.extend_from_slice(&Ipv4Addr::new(172, 16, 0, 1).octets());
        d2.extend_from_slice(&Ipv4Addr::new(10, 2, 2, 2).octets());
        d2.extend_from_slice(&2000u32.to_be_bytes());
        d2.extend_from_slice(&8u32.to_be_bytes());
        d2.extend_from_slice(&500u32.to_be_bytes()); // sampling=500
        while d2.len() < data_pkt_len {
            d2.push(0);
        }

        flows.clear();
        parser_a.parse_into(&d2, router2, &mut flows).unwrap();
        assert_eq!(
            flows.len(),
            1,
            "parser A must decode router 2 data via shared cache"
        );
        assert_eq!(flows[0].byte_count, 2000 * 500);
        assert_eq!(flows[0].packet_count, 8 * 500);
    }
}
