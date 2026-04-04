import { useCallback, useEffect, useRef, useState } from "react";
import type { WsConfig, WsMessage } from "../types";

export function useNetraSocket(
  initialConfig: WsConfig = { window: 30, top_n: 20 },
) {
  const [data, setData] = useState<WsMessage | null>(null);
  const [connected, setConnected] = useState(false);
  const sourceRef = useRef<EventSource | null>(null);
  const configRef = useRef<WsConfig>(initialConfig);
  const mountedRef = useRef(true);

  const connect = useCallback(() => {
    if (!mountedRef.current) return;

    // Close existing connection
    if (sourceRef.current) {
      sourceRef.current.close();
      sourceRef.current = null;
    }

    const { window, top_n } = configRef.current;
    const es = new EventSource(`/api/events?window=${window}&top_n=${top_n}`);
    sourceRef.current = es;

    es.onopen = () => {
      if (mountedRef.current) setConnected(true);
    };

    es.onmessage = (event) => {
      if (!mountedRef.current) return;
      setConnected(true);
      try {
        const msg: WsMessage = JSON.parse(event.data);
        setData(msg);
      } catch {
        // ignore
      }
    };

    es.onerror = () => {
      if (mountedRef.current) setConnected(false);
      // EventSource auto-reconnects with same URL (same config)
    };
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    connect();

    return () => {
      mountedRef.current = false;
      if (sourceRef.current) {
        sourceRef.current.close();
        sourceRef.current = null;
      }
    };
  }, [connect]);

  const sendConfig = useCallback(
    (config: WsConfig) => {
      configRef.current = config;
      // Reconnect SSE with new query params
      connect();
    },
    [connect],
  );

  return { data, connected, sendConfig };
}
