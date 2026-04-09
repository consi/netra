use crate::asn::AsnDb;
use crate::pipeline::WindowManager;
use crate::pipeline::window::FrozenWindow;
use axum::extract::{RawQuery, State};
use axum::http::header;
use axum::response::IntoResponse;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
pub struct MetricsQuery {
    #[serde(default = "default_window")]
    window: u64,
    #[serde(default = "default_top")]
    top: usize,
}

fn default_window() -> u64 {
    60
}
fn default_top() -> usize {
    25
}

struct DirectionTotals {
    bytes: u64,
    packets: u64,
    flows: u64,
}

struct AsnMetrics {
    asn: u32,
    name: String,
    country: String,
    bytes: u64,
    packets: u64,
    flows: u64,
}

struct VlanMetrics {
    upload: DirectionTotals,
    download: DirectionTotals,
    upload_asns: Vec<AsnMetrics>,
    download_asns: Vec<AsnMetrics>,
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

    let snapshot = manager.current_snapshot.load();
    result.push(Arc::clone(&snapshot));
    result
}

fn aggregate_for_prometheus(
    windows: &[Arc<FrozenWindow>],
    asn_db: &AsnDb,
    top_n: usize,
    skip_asns: &[u32],
) -> HashMap<u16, VlanMetrics> {
    // Accumulate per (vlan, asn) for upload and download
    let mut upload_acc: HashMap<u16, HashMap<u32, (u64, u64, u64)>> = HashMap::new();
    let mut download_acc: HashMap<u16, HashMap<u32, (u64, u64, u64)>> = HashMap::new();

    for w in windows {
        for (&(vlan, asn), stats) in &w.upload {
            let e = upload_acc.entry(vlan).or_default().entry(asn).or_default();
            e.0 += stats.byte_count;
            e.1 += stats.packet_count;
            e.2 += stats.flow_count;
        }
        for (&(vlan, asn), stats) in &w.download {
            let e = download_acc
                .entry(vlan)
                .or_default()
                .entry(asn)
                .or_default();
            e.0 += stats.byte_count;
            e.1 += stats.packet_count;
            e.2 += stats.flow_count;
        }
    }

    let all_vlans: std::collections::HashSet<u16> = upload_acc
        .keys()
        .chain(download_acc.keys())
        .copied()
        .collect();

    let mut result = HashMap::new();

    for vlan in all_vlans {
        let build_direction =
            |acc: &HashMap<u16, HashMap<u32, (u64, u64, u64)>>| -> (DirectionTotals, Vec<AsnMetrics>) {
                let empty = HashMap::new();
                let asn_map = acc.get(&vlan).unwrap_or(&empty);

                let mut total_bytes: u64 = 0;
                let mut total_packets: u64 = 0;
                let mut total_flows: u64 = 0;
                let mut entries: Vec<(u32, u64, u64, u64)> = Vec::new();

                for (&asn, &(bytes, packets, flows)) in asn_map {
                    if skip_asns.contains(&asn) {
                        continue;
                    }
                    total_bytes += bytes;
                    total_packets += packets;
                    total_flows += flows;
                    entries.push((asn, bytes, packets, flows));
                }

                entries.sort_by(|a, b| b.1.cmp(&a.1));
                entries.truncate(top_n);

                let asns = entries
                    .into_iter()
                    .map(|(asn, bytes, packets, flows)| {
                        let (name, country) = match asn_db.meta.get(&asn) {
                            Some(meta) => (
                                meta.name.to_string(),
                                std::str::from_utf8(&meta.country)
                                    .unwrap_or("??")
                                    .to_string(),
                            ),
                            None => ("Unknown".to_string(), "??".to_string()),
                        };
                        AsnMetrics {
                            asn,
                            name,
                            country,
                            bytes,
                            packets,
                            flows,
                        }
                    })
                    .collect();

                (
                    DirectionTotals {
                        bytes: total_bytes,
                        packets: total_packets,
                        flows: total_flows,
                    },
                    asns,
                )
            };

        let (upload_totals, upload_asns) = build_direction(&upload_acc);
        let (download_totals, download_asns) = build_direction(&download_acc);

        result.insert(
            vlan,
            VlanMetrics {
                upload: upload_totals,
                download: download_totals,
                upload_asns,
                download_asns,
            },
        );
    }

    result
}

fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn write_direction_metrics(
    out: &mut String,
    vlan_label: &str,
    direction: &str,
    totals: &DirectionTotals,
    asns: &[AsnMetrics],
) {
    // Per-ASN metrics with percentage
    for a in asns {
        let name = escape_label(&a.name);
        let labels = format!(
            "vlan=\"{vlan_label}\",direction=\"{direction}\",asn=\"{}\",name=\"{name}\",country=\"{}\"",
            a.asn, a.country
        );

        let _ = writeln!(out, "netra_asn_bytes{{{labels}}} {}", a.bytes);
        let _ = writeln!(out, "netra_asn_packets{{{labels}}} {}", a.packets);
        let _ = writeln!(out, "netra_asn_flows{{{labels}}} {}", a.flows);

        let pct_bytes = if totals.bytes > 0 {
            a.bytes as f64 / totals.bytes as f64 * 100.0
        } else {
            0.0
        };
        let pct_packets = if totals.packets > 0 {
            a.packets as f64 / totals.packets as f64 * 100.0
        } else {
            0.0
        };
        let pct_flows = if totals.flows > 0 {
            a.flows as f64 / totals.flows as f64 * 100.0
        } else {
            0.0
        };
        let _ = writeln!(out, "netra_asn_bytes_percent{{{labels}}} {pct_bytes:.4}");
        let _ = writeln!(
            out,
            "netra_asn_packets_percent{{{labels}}} {pct_packets:.4}"
        );
        let _ = writeln!(out, "netra_asn_flows_percent{{{labels}}} {pct_flows:.4}");
    }
}

pub async fn metrics_handler(
    RawQuery(raw): RawQuery,
    State(state): State<Arc<crate::AppState>>,
) -> impl IntoResponse {
    let query = raw
        .as_deref()
        .and_then(|qs| serde_urlencoded::from_str::<MetricsQuery>(qs).ok())
        .unwrap_or(MetricsQuery {
            window: default_window(),
            top: default_top(),
        });
    let window = query.window.clamp(5, 300);
    let top = query.top.clamp(1, 100);

    let windows = collect_windows(&state.windows, window);
    let asn_db = state.asn_db.load();
    let vlan_metrics = aggregate_for_prometheus(&windows, &asn_db, top, &state.skip_asns);

    let mut out = String::with_capacity(8192);

    // Header comments
    let _ = writeln!(
        out,
        "# HELP netra_total_bytes Total bytes in window by direction and vlan"
    );
    let _ = writeln!(out, "# TYPE netra_total_bytes gauge");
    let _ = writeln!(
        out,
        "# HELP netra_total_packets Total packets in window by direction and vlan"
    );
    let _ = writeln!(out, "# TYPE netra_total_packets gauge");
    let _ = writeln!(
        out,
        "# HELP netra_total_flows Total flows in window by direction and vlan"
    );
    let _ = writeln!(out, "# TYPE netra_total_flows gauge");
    let _ = writeln!(out, "# HELP netra_asn_bytes Bytes per ASN in window");
    let _ = writeln!(out, "# TYPE netra_asn_bytes gauge");
    let _ = writeln!(out, "# HELP netra_asn_packets Packets per ASN in window");
    let _ = writeln!(out, "# TYPE netra_asn_packets gauge");
    let _ = writeln!(out, "# HELP netra_asn_flows Flows per ASN in window");
    let _ = writeln!(out, "# TYPE netra_asn_flows gauge");
    let _ = writeln!(
        out,
        "# HELP netra_asn_bytes_percent Percentage of total bytes per ASN"
    );
    let _ = writeln!(out, "# TYPE netra_asn_bytes_percent gauge");
    let _ = writeln!(
        out,
        "# HELP netra_asn_packets_percent Percentage of total packets per ASN"
    );
    let _ = writeln!(out, "# TYPE netra_asn_packets_percent gauge");
    let _ = writeln!(
        out,
        "# HELP netra_asn_flows_percent Percentage of total flows per ASN"
    );
    let _ = writeln!(out, "# TYPE netra_asn_flows_percent gauge");

    // Accumulate grand totals across all VLANs
    let mut grand_upload = DirectionTotals {
        bytes: 0,
        packets: 0,
        flows: 0,
    };
    let mut grand_download = DirectionTotals {
        bytes: 0,
        packets: 0,
        flows: 0,
    };

    // Per-VLAN metrics (sorted by vlan id for stable output)
    let mut vlans: Vec<_> = vlan_metrics.into_iter().collect();
    vlans.sort_by_key(|(v, _)| *v);

    for (vlan, metrics) in &vlans {
        let vlan_label = vlan.to_string();

        // Totals per vlan + direction
        let _ = writeln!(
            out,
            "netra_total_bytes{{vlan=\"{vlan_label}\",direction=\"upload\"}} {}",
            metrics.upload.bytes
        );
        let _ = writeln!(
            out,
            "netra_total_packets{{vlan=\"{vlan_label}\",direction=\"upload\"}} {}",
            metrics.upload.packets
        );
        let _ = writeln!(
            out,
            "netra_total_flows{{vlan=\"{vlan_label}\",direction=\"upload\"}} {}",
            metrics.upload.flows
        );
        let _ = writeln!(
            out,
            "netra_total_bytes{{vlan=\"{vlan_label}\",direction=\"download\"}} {}",
            metrics.download.bytes
        );
        let _ = writeln!(
            out,
            "netra_total_packets{{vlan=\"{vlan_label}\",direction=\"download\"}} {}",
            metrics.download.packets
        );
        let _ = writeln!(
            out,
            "netra_total_flows{{vlan=\"{vlan_label}\",direction=\"download\"}} {}",
            metrics.download.flows
        );

        // Per-ASN metrics
        write_direction_metrics(
            &mut out,
            &vlan_label,
            "upload",
            &metrics.upload,
            &metrics.upload_asns,
        );
        write_direction_metrics(
            &mut out,
            &vlan_label,
            "download",
            &metrics.download,
            &metrics.download_asns,
        );

        // Accumulate grand totals
        grand_upload.bytes += metrics.upload.bytes;
        grand_upload.packets += metrics.upload.packets;
        grand_upload.flows += metrics.upload.flows;
        grand_download.bytes += metrics.download.bytes;
        grand_download.packets += metrics.download.packets;
        grand_download.flows += metrics.download.flows;
    }

    // Grand totals (vlan="total")
    let _ = writeln!(
        out,
        "netra_total_bytes{{vlan=\"total\",direction=\"upload\"}} {}",
        grand_upload.bytes
    );
    let _ = writeln!(
        out,
        "netra_total_packets{{vlan=\"total\",direction=\"upload\"}} {}",
        grand_upload.packets
    );
    let _ = writeln!(
        out,
        "netra_total_flows{{vlan=\"total\",direction=\"upload\"}} {}",
        grand_upload.flows
    );
    let _ = writeln!(
        out,
        "netra_total_bytes{{vlan=\"total\",direction=\"download\"}} {}",
        grand_download.bytes
    );
    let _ = writeln!(
        out,
        "netra_total_packets{{vlan=\"total\",direction=\"download\"}} {}",
        grand_download.packets
    );
    let _ = writeln!(
        out,
        "netra_total_flows{{vlan=\"total\",direction=\"download\"}} {}",
        grand_download.flows
    );

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn::{AsnDb, AsnMeta};
    use crate::pipeline::window::{FlowStats, FrozenWindow};
    use ip_network_table::IpNetworkTable;

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

    fn make_window(
        epoch: u64,
        upload: Vec<(u16, u32, u64, u64, u64)>,
        download: Vec<(u16, u32, u64, u64, u64)>,
    ) -> FrozenWindow {
        let mut up = HashMap::new();
        for (vlan, asn, bytes, packets, flows) in upload {
            up.insert(
                (vlan, asn),
                FlowStats {
                    byte_count: bytes,
                    packet_count: packets,
                    flow_count: flows,
                },
            );
        }
        let mut down = HashMap::new();
        for (vlan, asn, bytes, packets, flows) in download {
            down.insert(
                (vlan, asn),
                FlowStats {
                    byte_count: bytes,
                    packet_count: packets,
                    flow_count: flows,
                },
            );
        }
        FrozenWindow {
            epoch,
            upload: up,
            download: down,
        }
    }

    fn lines_matching(output: &str, prefix: &str) -> Vec<String> {
        output
            .lines()
            .filter(|l| l.starts_with(prefix))
            .map(|l| l.to_string())
            .collect()
    }

    fn metric_value(output: &str, metric_name: &str, labels: &str) -> Option<f64> {
        let needle = format!("{metric_name}{{{labels}}}");
        output.lines().find_map(|l| {
            if l.starts_with(&needle) {
                l.rsplit_once(' ').and_then(|(_, v)| v.parse().ok())
            } else {
                None
            }
        })
    }

    fn render(windows: &[Arc<FrozenWindow>], db: &AsnDb, top: usize, skip: &[u32]) -> String {
        let vlan_metrics = aggregate_for_prometheus(windows, db, top, skip);

        let mut out = String::new();

        let mut grand_upload = DirectionTotals {
            bytes: 0,
            packets: 0,
            flows: 0,
        };
        let mut grand_download = DirectionTotals {
            bytes: 0,
            packets: 0,
            flows: 0,
        };

        let mut vlans: Vec<_> = vlan_metrics.into_iter().collect();
        vlans.sort_by_key(|(v, _)| *v);

        for (vlan, metrics) in &vlans {
            let vl = vlan.to_string();
            let _ = writeln!(
                out,
                "netra_total_bytes{{vlan=\"{vl}\",direction=\"upload\"}} {}",
                metrics.upload.bytes
            );
            let _ = writeln!(
                out,
                "netra_total_packets{{vlan=\"{vl}\",direction=\"upload\"}} {}",
                metrics.upload.packets
            );
            let _ = writeln!(
                out,
                "netra_total_flows{{vlan=\"{vl}\",direction=\"upload\"}} {}",
                metrics.upload.flows
            );
            let _ = writeln!(
                out,
                "netra_total_bytes{{vlan=\"{vl}\",direction=\"download\"}} {}",
                metrics.download.bytes
            );
            let _ = writeln!(
                out,
                "netra_total_packets{{vlan=\"{vl}\",direction=\"download\"}} {}",
                metrics.download.packets
            );
            let _ = writeln!(
                out,
                "netra_total_flows{{vlan=\"{vl}\",direction=\"download\"}} {}",
                metrics.download.flows
            );

            write_direction_metrics(
                &mut out,
                &vl,
                "upload",
                &metrics.upload,
                &metrics.upload_asns,
            );
            write_direction_metrics(
                &mut out,
                &vl,
                "download",
                &metrics.download,
                &metrics.download_asns,
            );

            grand_upload.bytes += metrics.upload.bytes;
            grand_upload.packets += metrics.upload.packets;
            grand_upload.flows += metrics.upload.flows;
            grand_download.bytes += metrics.download.bytes;
            grand_download.packets += metrics.download.packets;
            grand_download.flows += metrics.download.flows;
        }

        let _ = writeln!(
            out,
            "netra_total_bytes{{vlan=\"total\",direction=\"upload\"}} {}",
            grand_upload.bytes
        );
        let _ = writeln!(
            out,
            "netra_total_packets{{vlan=\"total\",direction=\"upload\"}} {}",
            grand_upload.packets
        );
        let _ = writeln!(
            out,
            "netra_total_flows{{vlan=\"total\",direction=\"upload\"}} {}",
            grand_upload.flows
        );
        let _ = writeln!(
            out,
            "netra_total_bytes{{vlan=\"total\",direction=\"download\"}} {}",
            grand_download.bytes
        );
        let _ = writeln!(
            out,
            "netra_total_packets{{vlan=\"total\",direction=\"download\"}} {}",
            grand_download.packets
        );
        let _ = writeln!(
            out,
            "netra_total_flows{{vlan=\"total\",direction=\"download\"}} {}",
            grand_download.flows
        );

        out
    }

    #[test]
    fn test_basic_totals_per_vlan() {
        let db = make_asn_db(vec![(100, "AS100", "US"), (200, "AS200", "DE")]);
        let w = Arc::new(make_window(
            1000,
            vec![(10, 100, 5000, 100, 10), (10, 200, 3000, 60, 5)],
            vec![(10, 100, 2000, 40, 8)],
        ));
        let out = render(&[w], &db, 25, &[]);

        assert_eq!(
            metric_value(
                &out,
                "netra_total_bytes",
                "vlan=\"10\",direction=\"upload\""
            ),
            Some(8000.0)
        );
        assert_eq!(
            metric_value(
                &out,
                "netra_total_packets",
                "vlan=\"10\",direction=\"upload\""
            ),
            Some(160.0)
        );
        assert_eq!(
            metric_value(
                &out,
                "netra_total_flows",
                "vlan=\"10\",direction=\"upload\""
            ),
            Some(15.0)
        );
        assert_eq!(
            metric_value(
                &out,
                "netra_total_bytes",
                "vlan=\"10\",direction=\"download\""
            ),
            Some(2000.0)
        );
    }

    #[test]
    fn test_grand_totals_across_vlans() {
        let db = make_asn_db(vec![(100, "AS100", "US")]);
        let w = Arc::new(make_window(
            1000,
            vec![(10, 100, 1000, 20, 2), (20, 100, 3000, 60, 6)],
            vec![(10, 100, 500, 10, 1), (20, 100, 1500, 30, 3)],
        ));
        let out = render(&[w], &db, 25, &[]);

        assert_eq!(
            metric_value(
                &out,
                "netra_total_bytes",
                "vlan=\"total\",direction=\"upload\""
            ),
            Some(4000.0)
        );
        assert_eq!(
            metric_value(
                &out,
                "netra_total_packets",
                "vlan=\"total\",direction=\"upload\""
            ),
            Some(80.0)
        );
        assert_eq!(
            metric_value(
                &out,
                "netra_total_bytes",
                "vlan=\"total\",direction=\"download\""
            ),
            Some(2000.0)
        );
    }

    #[test]
    fn test_asn_metrics_with_name_and_country() {
        let db = make_asn_db(vec![(13335, "Cloudflare", "US")]);
        let w = Arc::new(make_window(1000, vec![(10, 13335, 5000, 100, 10)], vec![]));
        let out = render(&[w], &db, 25, &[]);

        let labels =
            "vlan=\"10\",direction=\"upload\",asn=\"13335\",name=\"Cloudflare\",country=\"US\"";
        assert_eq!(metric_value(&out, "netra_asn_bytes", labels), Some(5000.0));
        assert_eq!(metric_value(&out, "netra_asn_packets", labels), Some(100.0));
        assert_eq!(metric_value(&out, "netra_asn_flows", labels), Some(10.0));
    }

    #[test]
    fn test_percentage_calculation() {
        let db = make_asn_db(vec![(100, "A", "US"), (200, "B", "DE")]);
        // 100 has 750 bytes, 200 has 250 bytes => 75% and 25%
        let w = Arc::new(make_window(
            1000,
            vec![(10, 100, 750, 15, 3), (10, 200, 250, 5, 1)],
            vec![],
        ));
        let out = render(&[w], &db, 25, &[]);

        let pct_100 = metric_value(
            &out,
            "netra_asn_bytes_percent",
            "vlan=\"10\",direction=\"upload\",asn=\"100\",name=\"A\",country=\"US\"",
        )
        .unwrap();
        let pct_200 = metric_value(
            &out,
            "netra_asn_bytes_percent",
            "vlan=\"10\",direction=\"upload\",asn=\"200\",name=\"B\",country=\"DE\"",
        )
        .unwrap();

        assert!((pct_100 - 75.0).abs() < 0.01);
        assert!((pct_200 - 25.0).abs() < 0.01);
    }

    #[test]
    fn test_skip_asns_excluded() {
        let db = make_asn_db(vec![(100, "Own", "PL"), (200, "Other", "US")]);
        let w = Arc::new(make_window(
            1000,
            vec![(10, 100, 9000, 180, 90), (10, 200, 1000, 20, 10)],
            vec![],
        ));
        let out = render(&[w], &db, 25, &[100]);

        // ASN 100 excluded from totals
        assert_eq!(
            metric_value(
                &out,
                "netra_total_bytes",
                "vlan=\"10\",direction=\"upload\""
            ),
            Some(1000.0)
        );
        // No metric lines for ASN 100
        let asn100_lines = lines_matching(
            &out,
            "netra_asn_bytes{vlan=\"10\",direction=\"upload\",asn=\"100\"",
        );
        assert!(asn100_lines.is_empty());
    }

    #[test]
    fn test_top_n_truncation() {
        let db = make_asn_db(vec![(1, "A1", "US"), (2, "A2", "US"), (3, "A3", "US")]);
        let w = Arc::new(make_window(
            1000,
            vec![
                (10, 1, 3000, 60, 30),
                (10, 2, 2000, 40, 20),
                (10, 3, 1000, 20, 10),
            ],
            vec![],
        ));
        let out = render(&[w], &db, 2, &[]);

        // Only top 2 ASNs should appear
        let asn_lines = lines_matching(&out, "netra_asn_bytes{vlan=\"10\",direction=\"upload\"");
        assert_eq!(asn_lines.len(), 2);
        // But totals include all 3
        assert_eq!(
            metric_value(
                &out,
                "netra_total_bytes",
                "vlan=\"10\",direction=\"upload\""
            ),
            Some(6000.0)
        );
    }

    #[test]
    fn test_multiple_windows_summed() {
        let db = make_asn_db(vec![(100, "AS100", "US")]);
        let w1 = Arc::new(make_window(1000, vec![(10, 100, 500, 10, 2)], vec![]));
        let w2 = Arc::new(make_window(1005, vec![(10, 100, 300, 6, 1)], vec![]));
        let out = render(&[w1, w2], &db, 25, &[]);

        assert_eq!(
            metric_value(
                &out,
                "netra_total_bytes",
                "vlan=\"10\",direction=\"upload\""
            ),
            Some(800.0)
        );
        let labels = "vlan=\"10\",direction=\"upload\",asn=\"100\",name=\"AS100\",country=\"US\"";
        assert_eq!(metric_value(&out, "netra_asn_bytes", labels), Some(800.0));
        assert_eq!(metric_value(&out, "netra_asn_flows", labels), Some(3.0));
    }

    #[test]
    fn test_unknown_asn_metadata() {
        let db = make_asn_db(vec![]);
        let w = Arc::new(make_window(1000, vec![(10, 99999, 100, 2, 1)], vec![]));
        let out = render(&[w], &db, 25, &[]);

        let labels =
            "vlan=\"10\",direction=\"upload\",asn=\"99999\",name=\"Unknown\",country=\"??\"";
        assert_eq!(metric_value(&out, "netra_asn_bytes", labels), Some(100.0));
    }

    #[test]
    fn test_empty_windows_produce_only_totals() {
        let db = make_asn_db(vec![]);
        let out = render(&[], &db, 25, &[]);

        // Should have grand totals of zero
        assert_eq!(
            metric_value(
                &out,
                "netra_total_bytes",
                "vlan=\"total\",direction=\"upload\""
            ),
            Some(0.0)
        );
        assert_eq!(
            metric_value(
                &out,
                "netra_total_bytes",
                "vlan=\"total\",direction=\"download\""
            ),
            Some(0.0)
        );
    }

    #[test]
    fn test_label_escaping() {
        let name = escape_label("AS with \"quotes\" and \\backslash");
        assert_eq!(name, "AS with \\\"quotes\\\" and \\\\backslash");
    }

    #[test]
    fn test_query_defaults() {
        let q: MetricsQuery = serde_urlencoded::from_str("").unwrap();
        assert_eq!(q.window, 60);
        assert_eq!(q.top, 25);
    }

    #[test]
    fn test_query_custom_values() {
        let q: MetricsQuery = serde_urlencoded::from_str("window=10&top=50").unwrap();
        assert_eq!(q.window, 10);
        assert_eq!(q.top, 50);
    }

    #[test]
    fn test_query_malformed_falls_back() {
        let result = serde_urlencoded::from_str::<MetricsQuery>("window=abc&top=xyz");
        assert!(result.is_err()); // confirms malformed input is rejected, handler uses defaults
    }
}
