use ahash::RandomState;
use dashmap::DashMap;
use serde::Serialize;
use std::collections::HashMap;

pub const WINDOW_SECS: u64 = 5;
pub const HISTORY_SIZE: usize = 60; // 5 minutes

#[derive(Default, Clone, Serialize)]
pub struct FlowStats {
    pub flow_count: u64,
    pub byte_count: u64,
    pub packet_count: u64,
}

/// A live window accepting concurrent writes from multiple threads.
pub struct LiveWindow {
    pub epoch: u64, // window start as unix epoch seconds (aligned to WINDOW_SECS)
    /// upload: (vlan_id, dst_asn) → stats
    pub upload: DashMap<(u16, u32), FlowStats, RandomState>,
    /// download: (vlan_id, src_asn) → stats
    pub download: DashMap<(u16, u32), FlowStats, RandomState>,
}

impl LiveWindow {
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            upload: DashMap::with_capacity_and_hasher(8192, RandomState::default()),
            download: DashMap::with_capacity_and_hasher(8192, RandomState::default()),
        }
    }

    /// Record an upload flow (by dst ASN) into this window. Thread-safe.
    pub fn record_upload(
        &self,
        vlan_id: u16,
        asn: u32,
        byte_count: u64,
        packet_count: u64,
        flow_count: u64,
    ) {
        self.upload
            .entry((vlan_id, asn))
            .and_modify(|s| {
                s.flow_count += flow_count;
                s.byte_count += byte_count;
                s.packet_count += packet_count;
            })
            .or_insert(FlowStats {
                flow_count,
                byte_count,
                packet_count,
            });
    }

    /// Record a download flow (by src ASN) into this window. Thread-safe.
    pub fn record_download(
        &self,
        vlan_id: u16,
        asn: u32,
        byte_count: u64,
        packet_count: u64,
        flow_count: u64,
    ) {
        self.download
            .entry((vlan_id, asn))
            .and_modify(|s| {
                s.flow_count += flow_count;
                s.byte_count += byte_count;
                s.packet_count += packet_count;
            })
            .or_insert(FlowStats {
                flow_count,
                byte_count,
                packet_count,
            });
    }

    fn freeze_map(
        map: &DashMap<(u16, u32), FlowStats, RandomState>,
    ) -> HashMap<(u16, u32), FlowStats> {
        let mut result: HashMap<(u16, u32), FlowStats> = HashMap::with_capacity(map.len());
        for entry in map.iter() {
            result.insert(*entry.key(), entry.value().clone());
        }
        result
    }

    /// Freeze into an immutable snapshot.
    pub fn freeze(&self) -> FrozenWindow {
        FrozenWindow {
            epoch: self.epoch,
            upload: Self::freeze_map(&self.upload),
            download: Self::freeze_map(&self.download),
        }
    }
}

/// Immutable snapshot of a completed window.
#[derive(Clone, Serialize)]
pub struct FrozenWindow {
    pub epoch: u64,
    pub upload: HashMap<(u16, u32), FlowStats>,
    pub download: HashMap<(u16, u32), FlowStats>,
}

impl FrozenWindow {
    pub fn empty(epoch: u64) -> Self {
        Self {
            epoch,
            upload: HashMap::new(),
            download: HashMap::new(),
        }
    }
}

/// Attribute a flow's bytes across the appropriate window(s).
///
/// If the flow fits within a single 5-sec window, all bytes go there (fast path).
/// If it spans multiple windows, bytes are distributed proportionally.
/// Flow count is always attributed to the window containing flow_start.
///
/// `record_fn` is called for each window that receives attribution:
///   record_fn(window_epoch, vlan_id, asn, byte_count, flow_count)
#[cfg(test)]
fn attribute_flow<F>(
    vlan_id: u16,
    asn: u32,
    byte_count: u64,
    flow_start_ms: u64,
    flow_end_ms: u64,
    mut record_fn: F,
) where
    F: FnMut(u64, u16, u32, u64, u64),
{
    let start_epoch = flow_start_ms / 1000;
    let end_epoch = flow_end_ms / 1000;

    let first_window = start_epoch / WINDOW_SECS * WINDOW_SECS;
    let last_window = end_epoch / WINDOW_SECS * WINDOW_SECS;

    if first_window == last_window {
        record_fn(first_window, vlan_id, asn, byte_count, 1);
        return;
    }

    let total_duration_ms = flow_end_ms.saturating_sub(flow_start_ms).max(1);

    let mut window_epoch = first_window;
    let mut remaining_bytes = byte_count;
    let mut first = true;

    while window_epoch <= last_window {
        let w_start_ms = window_epoch * 1000;
        let w_end_ms = (window_epoch + WINDOW_SECS) * 1000;

        let overlap_start = flow_start_ms.max(w_start_ms);
        let overlap_end = flow_end_ms.min(w_end_ms);

        if overlap_start < overlap_end {
            let overlap_ms = overlap_end - overlap_start;
            let attributed = if window_epoch == last_window {
                remaining_bytes
            } else {
                let b =
                    (byte_count as u128 * overlap_ms as u128 / total_duration_ms as u128) as u64;
                remaining_bytes = remaining_bytes.saturating_sub(b);
                b
            };
            let count = if first { 1 } else { 0 };
            first = false;
            record_fn(window_epoch, vlan_id, asn, attributed, count);
        }

        window_epoch += WINDOW_SECS;
    }
}

/// Attribute a flow's bytes for both upload (dst ASN) and download (src ASN) in one pass.
///
/// Same window calculation as `attribute_flow`, but the callback receives both ASNs
/// so the caller can record upload and download in a single traversal.
///
/// `record_fn` is called for each window that receives attribution:
///   record_fn(window_epoch, vlan_id, dst_asn, src_asn, byte_count, flow_count)
#[allow(clippy::too_many_arguments)]
pub fn attribute_flow_dual<F>(
    vlan_id: u16,
    dst_asn: u32,
    src_asn: u32,
    byte_count: u64,
    packet_count: u64,
    flow_start_ms: u64,
    flow_end_ms: u64,
    mut record_fn: F,
) where
    F: FnMut(u64, u16, u32, u32, u64, u64, u64),
{
    let start_epoch = flow_start_ms / 1000;
    let end_epoch = flow_end_ms / 1000;

    let first_window = start_epoch / WINDOW_SECS * WINDOW_SECS;
    let last_window = end_epoch / WINDOW_SECS * WINDOW_SECS;

    // Fast path: single window
    if first_window == last_window {
        record_fn(
            first_window,
            vlan_id,
            dst_asn,
            src_asn,
            byte_count,
            packet_count,
            1,
        );
        return;
    }

    // Slow path: distribute proportionally
    let total_duration_ms = flow_end_ms.saturating_sub(flow_start_ms).max(1);

    let mut window_epoch = first_window;
    let mut remaining_bytes = byte_count;
    let mut remaining_packets = packet_count;
    let mut first = true;

    while window_epoch <= last_window {
        let w_start_ms = window_epoch * 1000;
        let w_end_ms = (window_epoch + WINDOW_SECS) * 1000;

        let overlap_start = flow_start_ms.max(w_start_ms);
        let overlap_end = flow_end_ms.min(w_end_ms);

        if overlap_start < overlap_end {
            let overlap_ms = overlap_end - overlap_start;
            let (attributed_bytes, attributed_packets) = if window_epoch == last_window {
                (remaining_bytes, remaining_packets)
            } else {
                let b =
                    (byte_count as u128 * overlap_ms as u128 / total_duration_ms as u128) as u64;
                let p =
                    (packet_count as u128 * overlap_ms as u128 / total_duration_ms as u128) as u64;
                remaining_bytes = remaining_bytes.saturating_sub(b);
                remaining_packets = remaining_packets.saturating_sub(p);
                (b, p)
            };
            let count = if first { 1 } else { 0 };
            first = false;
            record_fn(
                window_epoch,
                vlan_id,
                dst_asn,
                src_asn,
                attributed_bytes,
                attributed_packets,
                count,
            );
        }

        window_epoch += WINDOW_SECS;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// epoch seconds -> epoch millis (for test convenience)
    fn epoch(secs: u64) -> u64 {
        secs * 1000
    }

    fn epoch_ms(ms: u64) -> u64 {
        ms
    }

    /// Collect all calls to record_fn into a vec for inspection.
    fn collect_attributions(
        byte_count: u64,
        flow_start_ms: u64,
        flow_end_ms: u64,
    ) -> Vec<(u64, u16, u32, u64, u64)> {
        let mut results = Vec::new();
        attribute_flow(
            100,
            13335,
            byte_count,
            flow_start_ms,
            flow_end_ms,
            |ep, vlan, asn, bytes, count| {
                results.push((ep, vlan, asn, bytes, count));
            },
        );
        results
    }

    #[test]
    fn zero_duration_flow() {
        // flow_start == flow_end → single window, all bytes
        let t = epoch(1000);
        let results = collect_attributions(5000, t, t);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 1000); // epoch aligned to 5s (1000 is divisible by 5)
        assert_eq!(results[0].3, 5000); // all bytes
        assert_eq!(results[0].4, 1); // flow_count = 1
    }

    #[test]
    fn flow_within_single_window() {
        // Both start and end within same 5-second window [10, 15)
        let start = epoch_ms(11_000); // 11s
        let end = epoch_ms(13_500); // 13.5s
        let results = collect_attributions(10_000, start, end);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 10); // window epoch
        assert_eq!(results[0].3, 10_000);
        assert_eq!(results[0].4, 1);
    }

    #[test]
    fn flow_spanning_two_windows() {
        // Flow from 8s to 12s → windows [5,10) and [10,15)
        // Overlap with [5,10) = 2s, overlap with [10,15) = 2s → 50/50 split
        let start = epoch(8);
        let end = epoch(12);
        let results = collect_attributions(1000, start, end);
        assert_eq!(results.len(), 2);

        // First window [5,10): 2s overlap out of 4s total = 500 bytes
        assert_eq!(results[0].0, 5);
        assert_eq!(results[0].3, 500);
        assert_eq!(results[0].4, 1); // flow_count in first window

        // Second window [10,15): remainder = 500 bytes
        assert_eq!(results[1].0, 10);
        assert_eq!(results[1].3, 500);
        assert_eq!(results[1].4, 0); // no flow_count in subsequent windows
    }

    #[test]
    fn flow_spanning_three_windows_no_byte_loss() {
        // Flow from 3s to 13s → windows [0,5), [5,10), [10,15)
        // Total duration: 10s
        // [0,5): overlap 2s → 20%
        // [5,10): overlap 5s → 50%
        // [10,15): overlap 3s → 30%
        let start = epoch(3);
        let end = epoch(13);
        let byte_count = 10_000u64;
        let results = collect_attributions(byte_count, start, end);
        assert_eq!(results.len(), 3);

        // Verify no byte loss: sum of all attributed bytes == original byte_count
        let total_bytes: u64 = results.iter().map(|r| r.3).sum();
        assert_eq!(
            total_bytes, byte_count,
            "bytes must not be lost in attribution"
        );

        // First window gets ~2000 bytes (20%)
        assert_eq!(results[0].0, 0);
        assert_eq!(results[0].3, 2000);

        // Second window gets ~5000 bytes (50%)
        assert_eq!(results[1].0, 5);
        assert_eq!(results[1].3, 5000);

        // Third window gets remainder (3000)
        assert_eq!(results[2].0, 10);
        assert_eq!(results[2].3, 3000);
    }

    #[test]
    fn flow_count_only_in_first_window() {
        // Verify across a 3-window span that flow_count=1 only in first
        let start = epoch(3);
        let end = epoch(13);
        let results = collect_attributions(9999, start, end);

        assert_eq!(results[0].4, 1, "first window must have flow_count=1");
        for r in &results[1..] {
            assert_eq!(r.4, 0, "subsequent windows must have flow_count=0");
        }
    }

    #[test]
    fn live_window_concurrent_record() {
        let w = LiveWindow::new(100);
        w.record_upload(10, 1000, 500, 10, 1);
        w.record_upload(10, 1000, 300, 6, 1);
        w.record_upload(10, 2000, 100, 2, 1);
        w.record_upload(20, 1000, 200, 4, 1);
        w.record_download(10, 3000, 400, 8, 2);
        w.record_download(10, 3000, 100, 2, 1);

        let frozen = w.freeze();
        assert_eq!(frozen.upload[&(10, 1000)].byte_count, 800);
        assert_eq!(frozen.upload[&(10, 1000)].packet_count, 16);
        assert_eq!(frozen.upload[&(10, 1000)].flow_count, 2);
        assert_eq!(frozen.upload[&(10, 2000)].byte_count, 100);
        assert_eq!(frozen.upload[&(20, 1000)].byte_count, 200);

        assert_eq!(frozen.download[&(10, 3000)].byte_count, 500);
        assert_eq!(frozen.download[&(10, 3000)].packet_count, 10);
        assert_eq!(frozen.download[&(10, 3000)].flow_count, 3);
    }
}
