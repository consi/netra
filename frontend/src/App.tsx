import { useCallback, useMemo, useRef, useState } from "react";
import "./App.css";
import { useNetraSocket } from "./hooks/useNetraSocket";
import { mergeVlans } from "./utils/aggregate";
import { TopBar } from "./components/TopBar";
import { SummaryCards } from "./components/SummaryCards";
import { TopTalkers } from "./components/TopTalkers";
import { TrafficCharts } from "./components/TrafficChart";
import { colors } from "./theme";
import type { GroupBy } from "./types";

const STORAGE_KEY = "netra-config";

function loadConfig(): { window: number; top_n: number; groupBy: GroupBy } {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      return {
        window: typeof parsed.window === "number" ? parsed.window : 30,
        top_n: typeof parsed.top_n === "number" ? parsed.top_n : 20,
        groupBy:
          parsed.groupBy === "flows"
            ? "flows"
            : parsed.groupBy === "packets"
              ? "packets"
              : "bytes",
      };
    }
  } catch {
    // ignore
  }
  return { window: 30, top_n: 20, groupBy: "bytes" };
}

function saveConfig(config: {
  window: number;
  top_n: number;
  groupBy: GroupBy;
}) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
  } catch {
    // ignore
  }
}

const initialConfig = loadConfig();

function App() {
  const { data, connected, sendConfig } = useNetraSocket(initialConfig);
  const [windowSecs, setWindowSecs] = useState(initialConfig.window);
  const [topN, setTopN] = useState(initialConfig.top_n);
  const [groupBy, setGroupBy] = useState<GroupBy>(initialConfig.groupBy);
  const [deselectedVlans, setDeselectedVlans] = useState<Set<string>>(
    new Set(),
  );

  const allVlans = useMemo(
    () =>
      data ? Object.keys(data.vlans).sort((a, b) => Number(a) - Number(b)) : [],
    [data],
  );

  const selectedVlans = useMemo(
    () => allVlans.filter((v) => !deselectedVlans.has(v)),
    [allVlans, deselectedVlans],
  );

  const handleVlansChange = useCallback(
    (vlans: string[]) => {
      const selected = new Set(vlans);
      setDeselectedVlans(new Set(allVlans.filter((v) => !selected.has(v))));
    },
    [allVlans],
  );

  const view = useMemo(
    () =>
      data
        ? mergeVlans(data, selectedVlans, groupBy)
        : {
            upload: { totalBytes: 0, totalFlows: 0, totalPackets: 0, asns: [] },
            download: {
              totalBytes: 0,
              totalFlows: 0,
              totalPackets: 0,
              asns: [],
            },
            totalBytes: 0,
            totalFlows: 0,
            totalPackets: 0,
            activeAsns: 0,
            activeVlans: 0,
          },
    [data, selectedVlans, groupBy],
  );

  // Debounce SSE reconnect — UI updates immediately, SSE reconnects after 500ms idle
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const debouncedSendConfig = useCallback(
    (config: { window: number; top_n: number; groupBy: GroupBy }) => {
      saveConfig(config);
      if (debounceRef.current) clearTimeout(debounceRef.current);
      debounceRef.current = setTimeout(() => {
        sendConfig({ window: config.window, top_n: config.top_n });
      }, 500);
    },
    [sendConfig],
  );

  const handleWindowChange = useCallback(
    (secs: number) => {
      setWindowSecs(secs);
      debouncedSendConfig({ window: secs, top_n: topN, groupBy });
    },
    [debouncedSendConfig, topN, groupBy],
  );

  const handleTopNChange = useCallback(
    (n: number) => {
      setTopN(n);
      debouncedSendConfig({ window: windowSecs, top_n: n, groupBy });
    },
    [debouncedSendConfig, windowSecs, groupBy],
  );

  const handleGroupByChange = useCallback(
    (g: GroupBy) => {
      setGroupBy(g);
      saveConfig({ window: windowSecs, top_n: topN, groupBy: g });
    },
    [windowSecs, topN],
  );

  return (
    <div
      style={{
        minHeight: "100vh",
        background: colors.bg,
      }}
    >
      <TopBar
        windowSecs={windowSecs}
        topN={topN}
        groupBy={groupBy}
        vlans={allVlans}
        selectedVlans={selectedVlans}
        connected={connected}
        lastUpdate={data?.ts ?? null}
        onWindowChange={handleWindowChange}
        onTopNChange={handleTopNChange}
        onGroupByChange={handleGroupByChange}
        onVlansChange={handleVlansChange}
      />
      <SummaryCards view={view} windowSecs={windowSecs} />
      <div style={{ padding: "0 16px 16px" }}>
        <TrafficCharts
          upload={view.upload}
          download={view.download}
          groupBy={groupBy}
        />
      </div>
      <TopTalkers
        uploadAsns={view.upload.asns}
        downloadAsns={view.download.asns}
        groupBy={groupBy}
        windowSecs={windowSecs}
      />
      <footer
        style={{
          textAlign: "center",
          padding: "16px 0 20px",
          color: colors.textMuted,
          fontSize: 11,
          fontFamily: "monospace",
        }}
      >
        Marek Wajdzik 2026&copy; Netra v
        {import.meta.env.VITE_APP_VERSION || "dev"}
      </footer>
    </div>
  );
}

export default App;
