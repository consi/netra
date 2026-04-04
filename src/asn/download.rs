use super::{AsnDb, AsnMeta};
use flate2::read::GzDecoder;
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TSV_URL: &str = "https://iptoasn.com/data/ip2asn-combined.tsv.gz";

pub async fn download_and_build() -> Result<AsnDb, Box<dyn std::error::Error + Send + Sync>> {
    let resp = reqwest::get(TSV_URL).await?.error_for_status()?;
    let bytes = resp.bytes().await?;

    let decoder = GzDecoder::new(&bytes[..]);
    let reader = BufReader::new(decoder);

    let mut table = IpNetworkTable::<u32>::new();
    let mut meta: HashMap<u32, AsnMeta> = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 5 {
            continue;
        }

        let asn: u32 = match fields[2].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if asn == 0 {
            continue;
        }

        let start: IpAddr = match fields[0].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let end: IpAddr = match fields[1].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let cidrs = range_to_cidrs(start, end);
        for network in cidrs {
            table.insert(network, asn);
        }

        meta.entry(asn).or_insert_with(|| {
            let country_str = fields[3].as_bytes();
            let country = if country_str.len() >= 2 {
                [country_str[0], country_str[1]]
            } else {
                [b'?', b'?']
            };
            AsnMeta {
                country,
                name: fields[4].into(),
            }
        });
    }

    Ok(AsnDb { table, meta })
}

fn range_to_cidrs(start: IpAddr, end: IpAddr) -> Vec<IpNetwork> {
    match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) => range_to_cidrs_v4(s, e),
        (IpAddr::V6(s), IpAddr::V6(e)) => range_to_cidrs_v6(s, e),
        _ => Vec::new(), // mismatched address families
    }
}

fn range_to_cidrs_v4(start: Ipv4Addr, end: Ipv4Addr) -> Vec<IpNetwork> {
    let mut result = Vec::new();
    let mut current = u32::from(start);
    let end_val = u32::from(end);

    while current <= end_val {
        let alignment_bits = if current == 0 {
            32
        } else {
            current.trailing_zeros() as u8
        };

        let range_size = end_val - current + 1;
        let range_bits = (u32::BITS - range_size.leading_zeros()) as u8 - 1;

        let bits = alignment_bits.min(range_bits);
        let prefix_len = 32 - bits;

        let addr = Ipv4Addr::from(current);
        if let Ok(network) = IpNetwork::new(IpAddr::V4(addr), prefix_len) {
            result.push(network);
        }

        // Advance past this prefix
        current = match current.checked_add(1u32 << bits) {
            Some(v) => v,
            None => break, // wrapped around, we're done
        };
    }

    result
}

fn range_to_cidrs_v6(start: Ipv6Addr, end: Ipv6Addr) -> Vec<IpNetwork> {
    let mut result = Vec::new();
    let mut current = u128::from(start);
    let end_val = u128::from(end);

    while current <= end_val {
        let alignment_bits = if current == 0 {
            128
        } else {
            current.trailing_zeros() as u8
        };

        let range_size = end_val - current + 1;
        let range_bits = (128 - range_size.leading_zeros()) as u8 - 1;

        let bits = alignment_bits.min(range_bits);
        let prefix_len = 128 - bits;

        let addr = Ipv6Addr::from(current);
        if let Ok(network) = IpNetwork::new(IpAddr::V6(addr), prefix_len) {
            result.push(network);
        }

        current = match current.checked_add(1u128 << bits) {
            Some(v) => v,
            None => break,
        };
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidrs_to_strings(cidrs: Vec<IpNetwork>) -> Vec<String> {
        cidrs.iter().map(|c| c.to_string()).collect()
    }

    #[test]
    fn single_ip() {
        let start = Ipv4Addr::new(1, 2, 3, 4);
        let end = Ipv4Addr::new(1, 2, 3, 4);
        let result = cidrs_to_strings(range_to_cidrs_v4(start, end));
        assert_eq!(result, vec!["1.2.3.4/32"]);
    }

    #[test]
    fn aligned_block() {
        let start = Ipv4Addr::new(10, 0, 0, 0);
        let end = Ipv4Addr::new(10, 0, 0, 255);
        let result = cidrs_to_strings(range_to_cidrs_v4(start, end));
        assert_eq!(result, vec!["10.0.0.0/24"]);
    }

    #[test]
    fn unaligned_range() {
        let start = Ipv4Addr::new(10, 0, 0, 1);
        let end = Ipv4Addr::new(10, 0, 0, 6);
        let result = cidrs_to_strings(range_to_cidrs_v4(start, end));
        assert_eq!(
            result,
            vec!["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32",]
        );
    }

    #[test]
    fn single_ipv6() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let result = cidrs_to_strings(range_to_cidrs_v6(addr, addr));
        assert_eq!(result, vec!["2001:db8::1/128"]);
    }
}
