use super::{AsnDb, AsnMeta};
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

const MAGIC: &[u8; 4] = b"ASDB";
const VERSION: u8 = 1;

pub fn save(db: &AsnDb, path: &Path) -> io::Result<()> {
    let file = std::fs::File::create(path)?;
    let mut w = BufWriter::new(file);

    // Header
    w.write_all(MAGIC)?;
    w.write_all(&[VERSION])?;

    // ASN meta section
    let meta_count = db.meta.len() as u32;
    w.write_all(&meta_count.to_le_bytes())?;
    for (&asn, meta) in &db.meta {
        w.write_all(&asn.to_le_bytes())?;
        w.write_all(&meta.country)?;
        let name_bytes = meta.name.as_bytes();
        let name_len = name_bytes.len() as u16;
        w.write_all(&name_len.to_le_bytes())?;
        w.write_all(name_bytes)?;
    }

    // Prefix section
    let prefixes: Vec<_> = db.table.iter().collect();
    let prefix_count = prefixes.len() as u32;
    w.write_all(&prefix_count.to_le_bytes())?;
    for (network, &asn) in prefixes {
        match network {
            IpNetwork::V4(net) => {
                w.write_all(&[4u8])?;
                w.write_all(&net.network_address().octets())?;
                w.write_all(&[net.netmask()])?;
                w.write_all(&asn.to_le_bytes())?;
            }
            IpNetwork::V6(net) => {
                w.write_all(&[6u8])?;
                w.write_all(&net.network_address().octets())?;
                w.write_all(&[net.netmask()])?;
                w.write_all(&asn.to_le_bytes())?;
            }
        }
    }

    w.flush()?;
    Ok(())
}

pub fn load(path: &Path) -> io::Result<AsnDb> {
    let file = std::fs::File::open(path)?;
    let mut r = BufReader::new(file);

    // Header
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid magic"));
    }
    let mut ver = [0u8; 1];
    r.read_exact(&mut ver)?;
    if ver[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported version {}", ver[0]),
        ));
    }

    // ASN meta section
    let mut buf4 = [0u8; 4];
    r.read_exact(&mut buf4)?;
    let meta_count = u32::from_le_bytes(buf4) as usize;
    let mut meta = HashMap::with_capacity(meta_count);
    for _ in 0..meta_count {
        r.read_exact(&mut buf4)?;
        let asn = u32::from_le_bytes(buf4);

        let mut country = [0u8; 2];
        r.read_exact(&mut country)?;

        let mut buf2 = [0u8; 2];
        r.read_exact(&mut buf2)?;
        let name_len = u16::from_le_bytes(buf2) as usize;

        let mut name_buf = vec![0u8; name_len];
        r.read_exact(&mut name_buf)?;
        let name = String::from_utf8(name_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .into_boxed_str();

        meta.insert(asn, AsnMeta { country, name });
    }

    // Prefix section
    r.read_exact(&mut buf4)?;
    let prefix_count = u32::from_le_bytes(buf4) as usize;
    let mut table = IpNetworkTable::<u32>::new();
    for _ in 0..prefix_count {
        let mut af = [0u8; 1];
        r.read_exact(&mut af)?;

        match af[0] {
            4 => {
                let mut addr = [0u8; 4];
                r.read_exact(&mut addr)?;
                let mut plen = [0u8; 1];
                r.read_exact(&mut plen)?;
                r.read_exact(&mut buf4)?;
                let asn = u32::from_le_bytes(buf4);
                let network = IpNetwork::new(IpAddr::V4(Ipv4Addr::from(addr)), plen[0])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                table.insert(network, asn);
            }
            6 => {
                let mut addr = [0u8; 16];
                r.read_exact(&mut addr)?;
                let mut plen = [0u8; 1];
                r.read_exact(&mut plen)?;
                r.read_exact(&mut buf4)?;
                let asn = u32::from_le_bytes(buf4);
                let network = IpNetwork::new(IpAddr::V6(Ipv6Addr::from(addr)), plen[0])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                table.insert(network, asn);
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown address family {other}"),
                ));
            }
        }
    }

    Ok(AsnDb { table, meta })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut table = IpNetworkTable::<u32>::new();
        let net1 = IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24).unwrap();
        let net2 = IpNetwork::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            32,
        )
        .unwrap();
        table.insert(net1, 64496);
        table.insert(net2, 64497);

        let mut meta = HashMap::new();
        meta.insert(
            64496,
            AsnMeta {
                country: *b"US",
                name: "TEST-NET-1".into(),
            },
        );
        meta.insert(
            64497,
            AsnMeta {
                country: *b"DE",
                name: "TEST-NET-2".into(),
            },
        );

        let db = AsnDb { table, meta };

        let dir = std::env::temp_dir().join("netra_asn_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.asdb");

        save(&db, &path).unwrap();
        let loaded = load(&path).unwrap();

        assert_eq!(loaded.prefix_count(), 2);
        assert_eq!(loaded.asn_count(), 2);

        // Verify lookup works
        let (asn, m) = loaded
            .lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)))
            .unwrap();
        assert_eq!(asn, 64496);
        assert_eq!(&*m.name, "TEST-NET-1");
        assert_eq!(&m.country, b"US");

        let (asn, m) = loaded
            .lookup(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1)))
            .unwrap();
        assert_eq!(asn, 64497);
        assert_eq!(&*m.name, "TEST-NET-2");
        assert_eq!(&m.country, b"DE");

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }
}
