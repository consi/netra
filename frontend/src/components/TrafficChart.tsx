import { memo, useCallback, useMemo, useState } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import { colors } from "../theme";
import type { GroupBy, MergedAsn, MergedDirection } from "../types";

interface TrafficChartsProps {
  upload: MergedDirection;
  download: MergedDirection;
  groupBy: GroupBy;
}

interface SinglePieProps {
  title: string;
  asns: MergedAsn[];
  groupBy: GroupBy;
}

const styles = {
  wrapper: {
    display: "flex",
    gap: 16,
    flexWrap: "wrap",
  } as React.CSSProperties,
  container: {
    background: colors.bgCard,
    border: `1px solid ${colors.border}`,
    borderRadius: 8,
    padding: 16,
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    flex: "1 1 280px",
    minWidth: 0,
  } as React.CSSProperties,
  title: {
    fontSize: 13,
    fontWeight: 600,
    color: colors.textPrimary,
    alignSelf: "flex-start",
    marginBottom: 12,
  } as React.CSSProperties,
  chartWrapper: {
    width: 180,
    height: 180,
  } as React.CSSProperties,
  legend: {
    width: "100%",
    marginTop: 12,
    display: "flex",
    flexDirection: "column",
    gap: 4,
  } as React.CSSProperties,
  legendRow: {
    display: "flex",
    alignItems: "center",
    gap: 6,
    fontSize: 11,
    borderRadius: 4,
    padding: "2px 4px",
    transition: "background 0.15s",
  } as React.CSSProperties,
  legendName: {
    color: colors.textSecondary,
    flex: 1,
  } as React.CSSProperties,
  legendValue: {
    color: colors.textPrimary,
    fontFamily: "monospace",
  } as React.CSSProperties,
} as const;

const legendSwatchStyle = (color: string): React.CSSProperties => ({
  width: 8,
  height: 8,
  borderRadius: 2,
  background: color,
  flexShrink: 0,
});

const SinglePie = memo(function SinglePie({
  title,
  asns,
  groupBy,
}: SinglePieProps) {
  const [hoveredName, setHoveredName] = useState<string | null>(null);
  const onPieEnter = useCallback(
    (entry: { name?: string }) => setHoveredName(entry.name ?? null),
    [],
  );
  const onPieLeave = useCallback(() => setHoveredName(null), []);

  const chartData = useMemo(() => {
    const valueFor = (a: MergedAsn) =>
      groupBy === "bytes"
        ? a.bytes
        : groupBy === "packets"
          ? a.packets
          : a.flows;

    const slices = asns.map((a) => ({
      name: a.asn === 0 ? "No ASN" : `${a.name} (${a.asn})`,
      value: valueFor(a),
      color: a.color,
    }));

    // Sort by name for stable slice positions — recharts animates by index,
    // so reordering by value on every update causes flicker.
    slices.sort((a, b) => a.name.localeCompare(b.name));

    return slices;
  }, [asns, groupBy]);

  const legendData = useMemo(
    () => [...chartData].sort((a, b) => b.value - a.value),
    [chartData],
  );

  const total = useMemo(
    () => chartData.reduce((s, d) => s + d.value, 0),
    [chartData],
  );

  return (
    <div style={styles.container}>
      <div style={styles.title}>{title}</div>
      <div style={styles.chartWrapper}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              dataKey="value"
              outerRadius={80}
              strokeWidth={0}
              animationDuration={400}
              animationEasing="ease-out"
              onMouseEnter={onPieEnter}
              onMouseLeave={onPieLeave}
            >
              {chartData.map((entry) => (
                <Cell key={entry.name} fill={entry.color} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
      </div>
      <div style={styles.legend}>
        {legendData.map((entry) => (
          <div
            key={entry.name}
            style={{
              ...styles.legendRow,
              background:
                hoveredName === entry.name ? colors.border + "66" : undefined,
            }}
          >
            <div style={legendSwatchStyle(entry.color)} />
            <span style={styles.legendName}>{entry.name}</span>
            <span style={styles.legendValue}>
              {total > 0 ? ((entry.value / total) * 100).toFixed(1) : "0.0"}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
});

export const TrafficCharts = memo(function TrafficCharts({
  upload,
  download,
  groupBy,
}: TrafficChartsProps) {
  return (
    <div style={styles.wrapper}>
      <SinglePie title="Download" asns={download.asns} groupBy={groupBy} />
      <SinglePie title="Upload" asns={upload.asns} groupBy={groupBy} />
    </div>
  );
});
