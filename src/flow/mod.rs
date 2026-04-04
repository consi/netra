pub mod ipfix;
pub mod listener;
pub mod v5;
pub mod v9;
pub mod xdp;

use std::fmt;
use std::net::IpAddr;

/// Minimal extracted data from any NetFlow/IPFIX record.
/// All other fields are discarded at parse time.
/// Timestamps stored as epoch milliseconds to avoid SystemTime overhead.
#[derive(Debug)]
pub struct ExtractedFlow {
    pub dst_ip: IpAddr,
    pub src_ip: IpAddr,
    pub vlan_id: u16,
    pub byte_count: u64,
    pub packet_count: u64,
    pub flow_start_ms: u64,
    pub flow_end_ms: u64,
}

#[derive(Debug)]
pub enum ParseError {
    TooShort,
    BadVersion(u16),
    Truncated,
    MalformedTemplate,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::TooShort => write!(f, "packet too short"),
            ParseError::BadVersion(v) => write!(f, "unexpected version {v}"),
            ParseError::Truncated => write!(f, "truncated packet"),
            ParseError::MalformedTemplate => write!(f, "malformed template"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Read a u16 from big-endian bytes at the given offset.
#[inline(always)]
pub fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

/// Read a u32 from big-endian bytes at the given offset.
#[inline(always)]
pub fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Read a u64 from big-endian bytes at the given offset.
#[inline(always)]
pub fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Read an integer of given byte length (1, 2, 4, or 8) as u64.
#[inline]
pub fn read_uint(data: &[u8], offset: usize, len: usize) -> u64 {
    match len {
        1 => data[offset] as u64,
        2 => read_u16(data, offset) as u64,
        4 => read_u32(data, offset) as u64,
        8 => read_u64(data, offset),
        // For unusual lengths, read big-endian manually
        _ => {
            let mut val = 0u64;
            for i in 0..len.min(8) {
                val = (val << 8) | data[offset + i] as u64;
            }
            val
        }
    }
}
