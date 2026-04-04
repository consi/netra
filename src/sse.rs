use crate::asn::AsnDb;
use crate::pipeline::WindowManager;
use crate::pipeline::window::FrozenWindow;
use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Deserialize, Serialize)]
pub struct StreamConfig {
    #[serde(default = "default_window")]
    pub window: u64,
    #[serde(default = "default_top_n")]
    pub top_n: usize,
}

fn default_window() -> u64 {
    30
}
fn default_top_n() -> usize {
    20
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            window: default_window(),
            top_n: default_top_n(),
        }
    }
}

fn clamp_config(mut config: StreamConfig) -> StreamConfig {
    config.window = config.window.clamp(5, 300);
    config.top_n = config.top_n.clamp(1, 100);
    config
}

#[derive(Serialize)]
struct SseResponse {
    ts: u64,
    window: u64,
    active_vlans: usize,
    vlans: HashMap<String, VlanData>,
}

#[derive(Serialize)]
struct VlanData {
    upload: DirectionData,
    download: DirectionData,
}

#[derive(Clone, Serialize)]
struct DirectionData {
    total_bytes: u64,
    total_flows: u64,
    total_packets: u64,
    total_asns: usize,
    asns: Vec<AsnEntry>,
}

#[derive(Clone, Serialize)]
struct AsnEntry {
    asn: u32,
    name: String,
    country: String,
    bytes: u64,
    flows: u64,
    packets: u64,
}

fn aggregate_direction(
    windows: &[Arc<FrozenWindow>],
    asn_db: &AsnDb,
    top_n: usize,
    get_map: impl Fn(&FrozenWindow) -> &HashMap<(u16, u32), crate::pipeline::window::FlowStats>,
) -> HashMap<String, DirectionData> {
    let mut acc: HashMap<u16, HashMap<u32, (u64, u64, u64)>> = HashMap::new();

    for w in windows {
        for (&(vlan, asn), stats) in get_map(w) {
            let entry = acc.entry(vlan).or_default().entry(asn).or_insert((0, 0, 0));
            entry.0 += stats.byte_count;
            entry.1 += stats.flow_count;
            entry.2 += stats.packet_count;
        }
    }

    let mut result = HashMap::new();
    for (vlan, asn_map) in acc {
        let mut total_bytes: u64 = 0;
        let mut total_flows: u64 = 0;
        let mut total_packets: u64 = 0;
        let mut entries: Vec<(u32, u64, u64, u64)> = Vec::new();

        for (&asn, &(bytes, flows, packets)) in &asn_map {
            total_bytes += bytes;
            total_flows += flows;
            total_packets += packets;
            entries.push((asn, bytes, flows, packets));
        }

        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(top_n);

        let asns = entries
            .into_iter()
            .map(|(asn, bytes, flows, packets)| {
                let (name, country) = match asn_db.meta.get(&asn) {
                    Some(meta) => (
                        meta.name.to_string(),
                        std::str::from_utf8(&meta.country)
                            .unwrap_or("??")
                            .to_string(),
                    ),
                    None => ("Unknown".to_string(), "??".to_string()),
                };
                AsnEntry {
                    asn,
                    name,
                    country,
                    bytes,
                    flows,
                    packets,
                }
            })
            .collect();

        let total_asns = asn_map.len();

        result.insert(
            vlan.to_string(),
            DirectionData {
                total_bytes,
                total_flows,
                total_packets,
                total_asns,
                asns,
            },
        );
    }

    result
}

fn aggregate_windows(
    windows: &[Arc<FrozenWindow>],
    asn_db: &AsnDb,
    top_n: usize,
    now: u64,
) -> SseResponse {
    let upload_map = aggregate_direction(windows, asn_db, top_n, |w| &w.upload);
    let download_map = aggregate_direction(windows, asn_db, top_n, |w| &w.download);

    let all_vlans: std::collections::HashSet<&String> =
        upload_map.keys().chain(download_map.keys()).collect();

    let mut vlans = HashMap::new();
    for vlan in all_vlans {
        let empty = DirectionData {
            total_bytes: 0,
            total_flows: 0,
            total_packets: 0,
            total_asns: 0,
            asns: Vec::new(),
        };
        let upload = upload_map.get(vlan).cloned().unwrap_or(empty.clone());
        let download = download_map.get(vlan).cloned().unwrap_or(empty);
        vlans.insert(vlan.clone(), VlanData { upload, download });
    }

    let active_vlans = vlans.len();

    SseResponse {
        ts: now,
        window: 0,
        active_vlans,
        vlans,
    }
}

fn collect_windows(manager: &WindowManager, window_secs: u64) -> Vec<Arc<FrozenWindow>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let cutoff = now.saturating_sub(window_secs);

    let history = manager.history.load();
    let mut result: Vec<Arc<FrozenWindow>> = history
        .iter()
        .filter(|w| w.epoch >= cutoff)
        .cloned()
        .collect();

    // Use cached snapshot instead of freezing live DashMap on every SSE tick
    let snapshot = manager.current_snapshot.load();
    result.push(Arc::clone(&snapshot));

    result
}

fn build_message(state: &crate::AppState, config: &StreamConfig) -> Option<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let windows = collect_windows(&state.windows, config.window);
    let asn_db = state.asn_db.load();
    let mut response = aggregate_windows(&windows, &asn_db, config.top_n, now);
    response.window = config.window;
    serde_json::to_string(&response).ok()
}

// --- SSE stream endpoint (per-session config via query params) ---

pub async fn events_handler(
    Query(query): Query<StreamConfig>,
    State(state): State<Arc<crate::AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let config = clamp_config(query);

    let stream = async_stream::stream! {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(800));
        loop {
            interval.tick().await;
            if let Some(msg) = build_message(&state, &config) {
                yield Ok(Event::default().data(msg));
            }
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn::{AsnDb, AsnMeta};
    use crate::pipeline::window::FlowStats;
    use ip_network_table::IpNetworkTable;

    fn parse_config(text: &str) -> StreamConfig {
        let config: StreamConfig = serde_json::from_str(text).unwrap_or_default();
        clamp_config(config)
    }

    fn make_asn_db(entries: Vec<(u32, &str, &str)>) -> AsnDb {
        let mut meta = HashMap::new();
        for (asn, name, country) in entries {
            let country_bytes: [u8; 2] = country.as_bytes().try_into().unwrap_or([b'?', b'?']);
            meta.insert(
                asn,
                AsnMeta {
                    name: name.into(),
                    country: country_bytes,
                },
            );
        }
        AsnDb {
            table: IpNetworkTable::new(),
            meta,
        }
    }

    fn build_map(data: Vec<(u16, Vec<(u32, u64, u64)>)>) -> HashMap<(u16, u32), FlowStats> {
        let mut map = HashMap::new();
        for (vlan, asns) in data {
            for (asn, bytes, flows) in asns {
                map.insert(
                    (vlan, asn),
                    FlowStats {
                        byte_count: bytes,
                        flow_count: flows,
                        packet_count: bytes / 1500,
                    },
                );
            }
        }
        map
    }

    fn make_window(
        epoch: u64,
        upload: Vec<(u16, Vec<(u32, u64, u64)>)>,
        download: Vec<(u16, Vec<(u32, u64, u64)>)>,
    ) -> FrozenWindow {
        FrozenWindow {
            epoch,
            upload: build_map(upload),
            download: build_map(download),
        }
    }

    #[test]
    fn test_aggregate_sums_windows() {
        let db = make_asn_db(vec![(100, "AS100", "US")]);
        let w1 = Arc::new(make_window(
            1000,
            vec![(10, vec![(100, 500, 3)])],
            vec![(10, vec![(100, 200, 1)])],
        ));
        let w2 = Arc::new(make_window(
            1005,
            vec![(10, vec![(100, 300, 2)])],
            vec![(10, vec![(100, 100, 1)])],
        ));
        let resp = aggregate_windows(&[w1, w2], &db, 20, 1010);
        let vlan = &resp.vlans["10"];
        assert_eq!(vlan.upload.total_bytes, 800);
        assert_eq!(vlan.upload.total_flows, 5);
        assert_eq!(vlan.upload.asns.len(), 1);
        assert_eq!(vlan.upload.asns[0].bytes, 800);
        assert_eq!(vlan.upload.asns[0].flows, 5);
        assert_eq!(vlan.download.total_bytes, 300);
        assert_eq!(vlan.download.total_flows, 2);
    }

    #[test]
    fn test_aggregate_top_n_truncation() {
        let db = make_asn_db(vec![(1, "AS1", "US"), (2, "AS2", "DE"), (3, "AS3", "FR")]);
        let w = Arc::new(make_window(
            1000,
            vec![(10, vec![(1, 1000, 10), (2, 500, 5), (3, 200, 2)])],
            vec![],
        ));
        let resp = aggregate_windows(&[w], &db, 2, 1010);
        let vlan = &resp.vlans["10"];
        assert_eq!(vlan.upload.total_bytes, 1700);
        assert_eq!(vlan.upload.total_flows, 17);
        assert_eq!(vlan.upload.asns.len(), 2);
        assert_eq!(vlan.upload.asns[0].asn, 1);
        assert_eq!(vlan.upload.asns[1].asn, 2);
    }

    #[test]
    fn test_aggregate_enriches_metadata() {
        let db = make_asn_db(vec![(13335, "Cloudflare", "US")]);
        let w = Arc::new(make_window(1000, vec![(10, vec![(13335, 100, 1)])], vec![]));
        let resp = aggregate_windows(&[w], &db, 20, 1010);
        let entry = &resp.vlans["10"].upload.asns[0];
        assert_eq!(entry.name, "Cloudflare");
        assert_eq!(entry.country, "US");
    }

    #[test]
    fn test_aggregate_unknown_asn() {
        let db = make_asn_db(vec![]);
        let w = Arc::new(make_window(1000, vec![(10, vec![(99999, 100, 1)])], vec![]));
        let resp = aggregate_windows(&[w], &db, 20, 1010);
        let entry = &resp.vlans["10"].upload.asns[0];
        assert_eq!(entry.name, "Unknown");
        assert_eq!(entry.country, "??");
    }

    #[test]
    fn test_parse_config_valid() {
        let config = parse_config(r#"{"window": 60, "top_n": 10}"#);
        assert_eq!(config.window, 60);
        assert_eq!(config.top_n, 10);
    }

    #[test]
    fn test_parse_config_clamps() {
        let config = parse_config(r#"{"window": 1, "top_n": 999}"#);
        assert_eq!(config.window, 5);
        assert_eq!(config.top_n, 100);
    }

    #[test]
    fn test_parse_config_malformed() {
        let config = parse_config("not json at all");
        assert_eq!(config.window, 30);
        assert_eq!(config.top_n, 20);
    }

    #[test]
    fn test_different_window_settings_see_different_data() {
        // Simulate 3 windows at epochs 1000, 1005, 1010 (5s apart).
        // A 10s window should see last 2, a 20s window should see all 3.
        let db = make_asn_db(vec![(100, "AS100", "US")]);
        let w1 = Arc::new(make_window(1000, vec![(10, vec![(100, 100, 1)])], vec![]));
        let w2 = Arc::new(make_window(1005, vec![(10, vec![(100, 200, 2)])], vec![]));
        let w3 = Arc::new(make_window(1010, vec![(10, vec![(100, 300, 3)])], vec![]));

        // User A: 10s window → sees w2 + w3
        let resp_10 = aggregate_windows(&[w2.clone(), w3.clone()], &db, 20, 1012);
        let vlan = &resp_10.vlans["10"];
        assert_eq!(vlan.upload.total_bytes, 500); // 200 + 300
        assert_eq!(vlan.upload.total_flows, 5); // 2 + 3

        // User B: 20s window → sees w1 + w2 + w3
        let resp_20 = aggregate_windows(&[w1, w2, w3], &db, 20, 1012);
        let vlan = &resp_20.vlans["10"];
        assert_eq!(vlan.upload.total_bytes, 600); // 100 + 200 + 300
        assert_eq!(vlan.upload.total_flows, 6); // 1 + 2 + 3
    }
}
