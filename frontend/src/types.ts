export interface AsnEntry {
  asn: number;
  name: string;
  country: string;
  bytes: number;
  flows: number;
  packets: number;
}

export interface DirectionData {
  total_bytes: number;
  total_flows: number;
  total_packets: number;
  total_asns: number;
  asns: AsnEntry[];
}

export interface VlanData {
  upload: DirectionData;
  download: DirectionData;
}

export interface WsMessage {
  ts: number;
  window: number;
  active_vlans: number;
  vlans: Record<string, VlanData>;
}

export interface WsConfig {
  window: number;
  top_n: number;
}

export type GroupBy = "bytes" | "flows" | "packets";

export interface MergedAsn extends AsnEntry {
  share: number;
  color: string;
}

export interface MergedDirection {
  totalBytes: number;
  totalFlows: number;
  totalPackets: number;
  asns: MergedAsn[];
}

export interface MergedView {
  upload: MergedDirection;
  download: MergedDirection;
  totalBytes: number;
  totalFlows: number;
  totalPackets: number;
  activeAsns: number;
  activeVlans: number;
}
