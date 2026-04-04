import { memo } from "react";
import { colors } from "../theme";
import {
  formatBytes,
  formatFlows,
  formatPackets,
  countryFlag,
} from "../utils/format";
import type { GroupBy, MergedAsn } from "../types";

interface TopTalkersProps {
  uploadAsns: MergedAsn[];
  downloadAsns: MergedAsn[];
  groupBy: GroupBy;
  windowSecs: number;
}

interface TalkerTableProps {
  title: string;
  subtitle: string;
  asns: MergedAsn[];
  groupBy: GroupBy;
  windowSecs: number;
}

const styles = {
  container: {
    background: colors.bgCard,
    border: `1px solid ${colors.border}`,
    borderRadius: 8,
    display: "flex",
    flexDirection: "column",
    overflow: "hidden",
  } as React.CSSProperties,
  titleRow: {
    padding: "12px 16px",
    borderBottom: `1px solid ${colors.border}`,
    fontSize: 13,
    fontWeight: 600,
    color: colors.textPrimary,
    display: "flex",
    alignItems: "baseline",
    gap: 8,
  } as React.CSSProperties,
  subtitle: {
    fontSize: 10,
    color: colors.textMuted,
    fontWeight: 400,
  } as React.CSSProperties,
  scrollWrapper: {
    overflowX: "auto",
    WebkitOverflowScrolling: "touch",
  } as React.CSSProperties,
  table: {
    width: "100%",
    minWidth: 520,
    borderCollapse: "collapse",
    fontFamily: "monospace",
    fontSize: 12,
  } as React.CSSProperties,
  theadRow: {
    fontSize: 10,
    color: colors.textMuted,
    textTransform: "uppercase",
    letterSpacing: 0.5,
    borderBottom: `1px solid ${colors.bg}`,
  } as React.CSSProperties,
  thRank: {
    width: 30,
    padding: "6px 8px 6px 16px",
    textAlign: "left",
    fontWeight: 400,
  } as React.CSSProperties,
  thAsn: {
    padding: "6px 8px",
    textAlign: "left",
    fontWeight: 400,
  } as React.CSSProperties,
  thPrimary: {
    width: 130,
    padding: "6px 8px",
    textAlign: "right",
    fontWeight: 400,
  } as React.CSSProperties,
  thSecondary: {
    width: 100,
    padding: "6px 8px",
    textAlign: "right",
    fontWeight: 400,
  } as React.CSSProperties,
  thShare: {
    width: 60,
    padding: "6px 16px 6px 8px",
    textAlign: "right",
    fontWeight: 400,
  } as React.CSSProperties,
  tbodyRow: {
    borderBottom: `1px solid ${colors.bg}`,
  } as React.CSSProperties,
  tdRank: {
    padding: "7px 8px 7px 16px",
    color: colors.textMuted,
  } as React.CSSProperties,
  tdAsn: {
    padding: "7px 8px",
    whiteSpace: "nowrap",
  } as React.CSSProperties,
  asnNumber: {
    color: colors.accent,
  } as React.CSSProperties,
  asnName: {
    color: colors.textSecondary,
  } as React.CSSProperties,
  tdPrimary: {
    padding: "7px 8px",
    textAlign: "right",
    color: colors.textPrimary,
    whiteSpace: "nowrap",
  } as React.CSSProperties,
  tdSecondary: {
    padding: "7px 8px",
    textAlign: "right",
    color: colors.textSecondary,
    whiteSpace: "nowrap",
  } as React.CSSProperties,
  tdShare: {
    padding: "7px 16px 7px 8px",
    textAlign: "right",
  } as React.CSSProperties,
  outerContainer: {
    display: "flex",
    flexDirection: "column",
    gap: 16,
    padding: "0 16px 20px",
  } as React.CSSProperties,
} as const;

const shareBadgeStyle = (color: string): React.CSSProperties => ({
  background: color + "33",
  color: color,
  padding: "1px 6px",
  borderRadius: 3,
  fontSize: 10,
  whiteSpace: "nowrap",
});

const TalkerTable = memo(function TalkerTable({
  title,
  subtitle,
  asns,
  groupBy,
  windowSecs,
}: TalkerTableProps) {
  return (
    <div style={styles.container}>
      <div style={styles.titleRow}>
        {title}
        <span style={styles.subtitle}>{subtitle}</span>
      </div>
      <div style={styles.scrollWrapper}>
        <table style={styles.table}>
          <thead>
            <tr style={styles.theadRow}>
              <th style={styles.thRank}>#</th>
              <th style={styles.thAsn}>ASN</th>
              <th style={styles.thPrimary}>
                {groupBy === "bytes"
                  ? "Bytes/s"
                  : groupBy === "packets"
                    ? "Pps"
                    : "Flows/s"}
              </th>
              <th style={styles.thSecondary}>
                {groupBy === "bytes" ? "Pps" : "Bytes/s"}
              </th>
              <th style={styles.thSecondary}>
                {groupBy === "flows" ? "Pps" : "Flows/s"}
              </th>
              <th style={styles.thShare}>Share</th>
            </tr>
          </thead>
          <tbody>
            {asns.map((asn, i) => (
              <tr key={asn.asn} style={styles.tbodyRow}>
                <td style={styles.tdRank}>{i + 1}</td>
                <td style={styles.tdAsn}>
                  {countryFlag(asn.country)}{" "}
                  <span style={styles.asnNumber}>
                    {asn.asn === 0 ? "NONE" : `AS${asn.asn}`}
                  </span>{" "}
                  <span style={styles.asnName}>
                    {asn.asn === 0 ? "No ASN detected" : asn.name}
                  </span>
                </td>
                <td style={styles.tdPrimary}>
                  {groupBy === "bytes"
                    ? formatBytes(asn.bytes / windowSecs)
                    : groupBy === "packets"
                      ? formatPackets(asn.packets / windowSecs)
                      : formatFlows(asn.flows / windowSecs)}
                </td>
                <td style={styles.tdSecondary}>
                  {groupBy === "bytes"
                    ? formatPackets(asn.packets / windowSecs)
                    : formatBytes(asn.bytes / windowSecs)}
                </td>
                <td style={styles.tdSecondary}>
                  {groupBy === "flows"
                    ? formatPackets(asn.packets / windowSecs)
                    : formatFlows(asn.flows / windowSecs)}
                </td>
                <td style={styles.tdShare}>
                  <span style={shareBadgeStyle(asn.color)}>
                    {(asn.share * 100).toFixed(1)}%
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
});

export const TopTalkers = memo(function TopTalkers({
  uploadAsns,
  downloadAsns,
  groupBy,
  windowSecs,
}: TopTalkersProps) {
  return (
    <div style={styles.outerContainer}>
      <TalkerTable
        title="Download"
        subtitle="by source"
        asns={downloadAsns}
        groupBy={groupBy}
        windowSecs={windowSecs}
      />
      <TalkerTable
        title="Upload"
        subtitle="by destination"
        asns={uploadAsns}
        groupBy={groupBy}
        windowSecs={windowSecs}
      />
    </div>
  );
});
