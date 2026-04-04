pub mod db;
pub mod download;

use arc_swap::ArcSwap;
use ip_network_table::IpNetworkTable;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

const MAX_AGE: Duration = Duration::from_secs(24 * 3600);

#[derive(Clone)]
pub struct AsnMeta {
    pub country: [u8; 2],
    pub name: Box<str>,
}

pub struct AsnDb {
    pub table: IpNetworkTable<u32>,
    pub meta: HashMap<u32, AsnMeta>,
}

impl AsnDb {
    pub fn lookup(&self, ip: IpAddr) -> Option<(u32, &AsnMeta)> {
        let (_, &asn) = self.table.longest_match(ip)?;
        let meta = self.meta.get(&asn)?;
        Some((asn, meta))
    }

    /// Hot-path: returns just the ASN number, or 0 if not found.
    /// Skips meta lookup and avoids IpNetwork reconstruction overhead.
    #[inline]
    pub fn lookup_asn(&self, ip: IpAddr) -> u32 {
        match ip {
            IpAddr::V4(v4) => self
                .table
                .longest_match_ipv4(v4)
                .map(|(_, asn)| *asn)
                .unwrap_or(0),
            IpAddr::V6(v6) => self
                .table
                .longest_match_ipv6(v6)
                .map(|(_, asn)| *asn)
                .unwrap_or(0),
        }
    }

    pub fn prefix_count(&self) -> usize {
        self.table.iter().count()
    }

    pub fn asn_count(&self) -> usize {
        self.meta.len()
    }
}

/// Returns how old the file is, or None if it doesn't exist / can't be read.
fn file_age(path: &Path) -> Option<Duration> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    SystemTime::now().duration_since(modified).ok()
}

/// Initialize ASN database: load from disk if fresh enough, else download.
pub async fn init(db_path: &Path) -> Result<Arc<AsnDb>, Box<dyn std::error::Error + Send + Sync>> {
    let age = file_age(db_path);
    let stale = age.is_none_or(|a| a > MAX_AGE);

    if let Some(a) = age {
        tracing::info!(
            "ASN database on disk is {:.1}h old{}",
            a.as_secs_f64() / 3600.0,
            if stale { " (stale)" } else { "" }
        );
    }

    if !stale {
        tracing::info!("Loading ASN database from {}", db_path.display());
        match db::load(db_path) {
            Ok(db) => {
                tracing::info!(
                    "ASN database loaded: {} prefixes, {} ASNs",
                    db.prefix_count(),
                    db.asn_count()
                );
                return Ok(Arc::new(db));
            }
            Err(e) => {
                tracing::warn!("Failed to load ASN database: {e}, will re-download");
            }
        }
    }

    tracing::info!("Downloading ASN database...");
    let db = download::download_and_build().await?;
    tracing::info!(
        "ASN database built: {} prefixes, {} ASNs",
        db.prefix_count(),
        db.asn_count()
    );

    if let Err(e) = db::save(&db, db_path) {
        tracing::warn!("Failed to save ASN database to disk: {e}");
    }

    Ok(Arc::new(db))
}

/// Periodically refresh the ASN database when the file on disk is older than 24h.
pub async fn refresh_loop(db_path: std::path::PathBuf, holder: Arc<ArcSwap<AsnDb>>) {
    loop {
        // Sleep until the file should be stale, checking every hour as a fallback.
        let sleep_dur = file_age(&db_path)
            .and_then(|age| MAX_AGE.checked_sub(age))
            .map(|remaining| remaining + Duration::from_secs(60)) // small buffer
            .unwrap_or(Duration::from_secs(3600));

        tokio::time::sleep(sleep_dur).await;

        if file_age(&db_path).is_some_and(|a| a <= MAX_AGE) {
            continue; // not stale yet (e.g. another instance refreshed it)
        }

        tracing::info!("Refreshing ASN database...");
        match download::download_and_build().await {
            Ok(db) => {
                tracing::info!(
                    "ASN database refreshed: {} prefixes, {} ASNs",
                    db.prefix_count(),
                    db.asn_count()
                );
                if let Err(e) = db::save(&db, &db_path) {
                    tracing::warn!("Failed to save refreshed ASN database: {e}");
                }
                holder.store(Arc::new(db));
            }
            Err(e) => {
                tracing::warn!("ASN database refresh failed: {e}, will retry in 1h");
            }
        }
    }
}
