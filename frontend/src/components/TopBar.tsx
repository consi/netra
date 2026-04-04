import { memo, useCallback, useEffect, useRef, useState } from "react";
import { colors } from "../theme";
import type { GroupBy } from "../types";

interface TopBarProps {
  windowSecs: number;
  topN: number;
  groupBy: GroupBy;
  vlans: string[];
  selectedVlans: string[];
  connected: boolean;
  lastUpdate: number | null;
  onWindowChange: (secs: number) => void;
  onTopNChange: (n: number) => void;
  onGroupByChange: (g: GroupBy) => void;
  onVlansChange: (vlans: string[]) => void;
}

const styles = {
  header: {
    display: "flex",
    flexWrap: "wrap",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "10px 16px",
    gap: 10,
    borderBottom: `1px solid ${colors.border}`,
    background: colors.bgHeader,
    position: "sticky",
    top: 0,
    zIndex: 10,
  } as React.CSSProperties,
  logoGroup: {
    display: "flex",
    alignItems: "center",
    gap: 10,
  } as React.CSSProperties,
  logo: {
    color: colors.accent,
    fontSize: 18,
    fontWeight: 700,
    fontFamily: "monospace",
  } as React.CSSProperties,
  badgeBase: {
    padding: "2px 8px",
    borderRadius: 4,
    fontSize: 10,
  } as React.CSSProperties,
  ago: {
    color: colors.textMuted,
    fontSize: 9,
    fontFamily: "monospace",
  } as React.CSSProperties,
  controlGroup: {
    display: "flex",
    flexWrap: "wrap",
    alignItems: "center",
    gap: 14,
    fontSize: 11,
  } as React.CSSProperties,
  label: {
    display: "flex",
    alignItems: "center",
    gap: 6,
    minHeight: 44,
    touchAction: "manipulation",
  } as React.CSSProperties,
  labelText: {
    color: colors.textMuted,
  } as React.CSSProperties,
  windowValue: {
    color: colors.accent,
    fontFamily: "monospace",
    minWidth: 32,
    textAlign: "right",
  } as React.CSSProperties,
  windowSlider: { width: 100 } as React.CSSProperties,
  topNValue: {
    color: colors.accent,
    fontFamily: "monospace",
    minWidth: 20,
    textAlign: "right",
  } as React.CSSProperties,
  topNSlider: { width: 80 } as React.CSSProperties,
  groupByRow: {
    display: "flex",
    gap: 2,
  } as React.CSSProperties,
  vlanWrapper: {
    position: "relative",
    display: "inline-block",
  } as React.CSSProperties,
  detailsRoot: {
    position: "relative",
  } as React.CSSProperties,
  summary: {
    background: colors.bgCard,
    border: `1px solid ${colors.border}`,
    borderRadius: 4,
    padding: "6px 12px",
    color: colors.textSecondary,
    fontSize: 11,
    cursor: "pointer",
    listStyle: "none",
    minHeight: 44,
    display: "flex",
    alignItems: "center",
    touchAction: "manipulation",
  } as React.CSSProperties,
  dropdown: {
    position: "absolute",
    right: 0,
    top: "100%",
    marginTop: 4,
    background: colors.bgCard,
    border: `1px solid ${colors.border}`,
    borderRadius: 6,
    padding: 10,
    minWidth: 160,
    zIndex: 20,
  } as React.CSSProperties,
  dropdownHeader: {
    display: "flex",
    justifyContent: "space-between",
    marginBottom: 8,
    fontSize: 11,
  } as React.CSSProperties,
  allBtn: {
    background: "none",
    border: "none",
    color: colors.accent,
    cursor: "pointer",
    fontSize: 11,
    padding: "8px 4px",
    touchAction: "manipulation",
  } as React.CSSProperties,
  noneBtn: {
    background: "none",
    border: "none",
    color: colors.textMuted,
    cursor: "pointer",
    fontSize: 11,
    padding: "8px 4px",
    touchAction: "manipulation",
  } as React.CSSProperties,
  vlanLabel: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    padding: "6px 4px",
    color: colors.textPrimary,
    fontSize: 12,
    fontFamily: "monospace",
    cursor: "pointer",
    touchAction: "manipulation",
  } as React.CSSProperties,
  vlanCheckbox: {
    accentColor: colors.accent,
    width: 18,
    height: 18,
  } as React.CSSProperties,
} as const;

const badgeStyle = (connected: boolean): React.CSSProperties => ({
  ...styles.badgeBase,
  background: connected ? colors.accentGreenBg : colors.accentRedBg,
  color: connected ? colors.accentGreen : colors.accentRed,
});

const groupByBtnStyle = (active: boolean): React.CSSProperties => ({
  background: active ? colors.accent : colors.bgCard,
  color: active ? colors.bg : colors.textSecondary,
  border: active ? "none" : `1px solid ${colors.border}`,
  padding: "6px 14px",
  borderRadius: 3,
  fontSize: 11,
  fontWeight: active ? 600 : 400,
  cursor: "pointer",
  minHeight: 44,
  touchAction: "manipulation",
});

export const TopBar = memo(function TopBar({
  windowSecs,
  topN,
  groupBy,
  vlans,
  selectedVlans,
  connected,
  lastUpdate,
  onWindowChange,
  onTopNChange,
  onGroupByChange,
  onVlansChange,
}: TopBarProps) {
  const formatWindow = (s: number) =>
    s >= 60 ? `${(s / 60).toFixed(1)}m` : `${s}s`;
  const toggleVlan = (vlan: string) => {
    if (selectedVlans.includes(vlan)) {
      onVlansChange(selectedVlans.filter((v) => v !== vlan));
    } else {
      onVlansChange([...selectedVlans, vlan]);
    }
  };

  const detailsRef = useRef<HTMLDetailsElement>(null);
  const closeVlanPicker = useCallback((e: PointerEvent) => {
    if (
      detailsRef.current?.open &&
      !detailsRef.current.contains(e.target as Node)
    ) {
      detailsRef.current.open = false;
    }
  }, []);
  useEffect(() => {
    document.addEventListener("pointerdown", closeVlanPicker);
    return () => document.removeEventListener("pointerdown", closeVlanPicker);
  }, [closeVlanPicker]);

  const [ago, setAgo] = useState("");
  useEffect(() => {
    if (!lastUpdate) return;
    const update = () => {
      const delta = Math.max(0, Math.floor(Date.now() / 1000) - lastUpdate);
      setAgo(`${delta}s ago`);
    };
    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, [lastUpdate]);

  return (
    <div style={styles.header}>
      <div style={styles.logoGroup}>
        <span style={styles.logo}>netra</span>
        <span style={badgeStyle(connected)}>
          <span
            key={lastUpdate ?? 0}
            className={connected && lastUpdate ? "sse-pulse" : undefined}
          >
            {"\u25CF"}
          </span>
          {connected ? " LIVE" : " DISCONNECTED"}
        </span>
        {ago && <span style={styles.ago}>{ago}</span>}
      </div>
      <div style={styles.controlGroup}>
        <label style={styles.label}>
          <span style={styles.labelText}>Window</span>
          <span style={styles.windowValue}>{formatWindow(windowSecs)}</span>
          <input
            type="range"
            min={5}
            max={300}
            step={5}
            value={windowSecs}
            onChange={(e) => onWindowChange(Number(e.target.value))}
            style={styles.windowSlider}
          />
        </label>
        <label style={styles.label}>
          <span style={styles.labelText}>Top N</span>
          <span style={styles.topNValue}>{topN}</span>
          <input
            type="range"
            min={1}
            max={100}
            step={1}
            value={topN}
            onChange={(e) => onTopNChange(Number(e.target.value))}
            style={styles.topNSlider}
          />
        </label>
        <div style={styles.groupByRow}>
          {(["bytes", "packets", "flows"] as const).map((g) => (
            <button
              key={g}
              onClick={() => onGroupByChange(g)}
              style={groupByBtnStyle(groupBy === g)}
            >
              {g === "bytes" ? "Bytes/s" : g === "packets" ? "Pps" : "Flows"}
            </button>
          ))}
        </div>
        <div style={styles.vlanWrapper}>
          <details ref={detailsRef} style={styles.detailsRoot}>
            <summary style={styles.summary}>
              VLANs ({selectedVlans.length}/{vlans.length}) &#x25BE;
            </summary>
            <div style={styles.dropdown}>
              <div style={styles.dropdownHeader}>
                <button
                  onClick={() => onVlansChange([...vlans])}
                  style={styles.allBtn}
                >
                  All
                </button>
                <button
                  onClick={() => onVlansChange([])}
                  style={styles.noneBtn}
                >
                  None
                </button>
              </div>
              {vlans.map((v) => (
                <label key={v} style={styles.vlanLabel}>
                  <input
                    type="checkbox"
                    checked={selectedVlans.includes(v)}
                    onChange={() => toggleVlan(v)}
                    style={styles.vlanCheckbox}
                  />
                  VLAN {v}
                </label>
              ))}
            </div>
          </details>
        </div>
      </div>
    </div>
  );
});
