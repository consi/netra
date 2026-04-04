import type {
  AsnEntry,
  GroupBy,
  MergedAsn,
  MergedDirection,
  MergedView,
  WsMessage,
} from "../types";
import { chartColorForAsn } from "../theme";

export function mergeVlans(
  msg: WsMessage,
  selectedVlans: string[],
  groupBy: GroupBy,
): MergedView {
  const uploadAcc = new Map<number, AsnEntry>();
  const downloadAcc = new Map<number, AsnEntry>();
  let uploadBytes = 0,
    uploadFlows = 0,
    uploadPackets = 0;
  let downloadBytes = 0,
    downloadFlows = 0,
    downloadPackets = 0;
  let totalUploadAsns = 0,
    totalDownloadAsns = 0;

  for (const vlanId of selectedVlans) {
    const vlan = msg.vlans[vlanId];
    if (!vlan) continue;

    uploadBytes += vlan.upload.total_bytes;
    uploadFlows += vlan.upload.total_flows;
    uploadPackets += vlan.upload.total_packets;
    totalUploadAsns += vlan.upload.total_asns;
    downloadBytes += vlan.download.total_bytes;
    downloadFlows += vlan.download.total_flows;
    downloadPackets += vlan.download.total_packets;
    totalDownloadAsns += vlan.download.total_asns;

    for (const asn of vlan.upload.asns) {
      accumulateAsn(uploadAcc, asn);
    }
    for (const asn of vlan.download.asns) {
      accumulateAsn(downloadAcc, asn);
    }
  }

  // Each unidirectional flow contributes to both upload (by dst_asn) and
  // download (by src_asn), so their totals are equal.  Use one direction
  // to avoid double-counting.  (Per RFC 3954 §7 / RFC 7011 §4.1.)
  const totalBytes = downloadBytes;
  const totalFlows = downloadFlows;
  const totalPackets = downloadPackets;

  return {
    upload: buildDirection(
      uploadAcc,
      uploadBytes,
      uploadFlows,
      uploadPackets,
      groupBy,
    ),
    download: buildDirection(
      downloadAcc,
      downloadBytes,
      downloadFlows,
      downloadPackets,
      groupBy,
    ),
    totalBytes,
    totalFlows,
    totalPackets,
    activeAsns: totalUploadAsns + totalDownloadAsns,
    activeVlans: msg.active_vlans,
  };
}

function accumulateAsn(acc: Map<number, AsnEntry>, asn: AsnEntry) {
  const existing = acc.get(asn.asn);
  if (existing) {
    existing.bytes += asn.bytes;
    existing.flows += asn.flows;
    existing.packets += asn.packets;
  } else {
    acc.set(asn.asn, { ...asn });
  }
}

function buildDirection(
  acc: Map<number, AsnEntry>,
  totalBytes: number,
  totalFlows: number,
  totalPackets: number,
  groupBy: GroupBy,
): MergedDirection {
  return {
    totalBytes,
    totalFlows,
    totalPackets,
    asns: buildMergedAsns(acc, groupBy, totalBytes, totalFlows, totalPackets),
  };
}

function buildMergedAsns(
  acc: Map<number, AsnEntry>,
  groupBy: GroupBy,
  totalBytes: number,
  totalFlows: number,
  totalPackets: number,
): MergedAsn[] {
  const sortKey =
    groupBy === "bytes" ? "bytes" : groupBy === "flows" ? "flows" : "packets";
  const total =
    groupBy === "bytes"
      ? totalBytes
      : groupBy === "flows"
        ? totalFlows
        : totalPackets;
  const sorted = [...acc.values()].sort((a, b) => b[sortKey] - a[sortKey]);
  return sorted.map((a) => ({
    ...a,
    share: total > 0 ? a[sortKey] / total : 0,
    color: chartColorForAsn(a.asn),
  }));
}
