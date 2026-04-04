import { memo } from "react";
import { colors } from "../theme";
import { formatBytes, formatFlows, formatPackets } from "../utils/format";
import type { MergedView } from "../types";

interface SummaryCardsProps {
  view: MergedView;
  windowSecs: number;
}

const styles = {
  container: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
    gap: 12,
    padding: "16px 16px",
  } as React.CSSProperties,
  card: {
    background: colors.bgCard,
    border: `1px solid ${colors.border}`,
    borderRadius: 8,
    padding: 14,
    minWidth: 0,
  } as React.CSSProperties,
  label: {
    color: colors.textMuted,
    fontSize: 10,
    textTransform: "uppercase",
    letterSpacing: 1,
  } as React.CSSProperties,
  value: {
    color: colors.textPrimary,
    fontSize: 28,
    fontWeight: 700,
    fontFamily: "monospace",
    marginTop: 4,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
  } as React.CSSProperties,
  splitValue: {
    display: "flex",
    gap: 8,
    alignItems: "baseline",
    marginTop: 4,
  } as React.CSSProperties,
  splitNum: {
    color: colors.textPrimary,
    fontSize: 28,
    fontWeight: 700,
    fontFamily: "monospace",
  } as React.CSSProperties,
  splitSep: {
    color: colors.textMuted,
    fontSize: 20,
    fontWeight: 300,
  } as React.CSSProperties,
} as const;

export const SummaryCards = memo(function SummaryCards({
  view,
  windowSecs,
}: SummaryCardsProps) {
  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <div style={styles.label}>Throughput</div>
        <div style={styles.value}>
          {formatBytes(view.totalBytes / windowSecs)}
        </div>
      </div>
      <div style={styles.card}>
        <div style={styles.label}>Packets</div>
        <div style={styles.value}>
          {formatPackets(view.totalPackets / windowSecs)}
        </div>
      </div>
      <div style={styles.card}>
        <div style={styles.label}>Flows</div>
        <div style={styles.value}>
          {formatFlows(view.totalFlows / windowSecs)}
        </div>
      </div>
      <div style={styles.card}>
        <div style={styles.label}>ASNs / VLANs</div>
        <div style={styles.splitValue}>
          <span style={styles.splitNum}>{view.activeAsns}</span>
          <span style={styles.splitSep}>/</span>
          <span style={styles.splitNum}>{view.activeVlans}</span>
        </div>
      </div>
    </div>
  );
});
