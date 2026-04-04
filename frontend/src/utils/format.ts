export function formatBytes(bytesPerSec: number): string {
  const bitsPerSec = Math.round(bytesPerSec) * 8;
  if (bitsPerSec === 0) return "0 bps";
  if (bitsPerSec < 1_000) return `${bitsPerSec} bps`;
  if (bitsPerSec < 1_000_000) return `${(bitsPerSec / 1_000).toFixed(1)} Kbps`;
  if (bitsPerSec < 1_000_000_000)
    return `${(bitsPerSec / 1_000_000).toFixed(1)} Mbps`;
  if (bitsPerSec < 1_000_000_000_000)
    return `${(bitsPerSec / 1_000_000_000).toFixed(2)} Gbps`;
  return `${(bitsPerSec / 1_000_000_000_000).toFixed(2)} Tbps`;
}

export function formatFlows(flowsPerSec: number): string {
  const fps = Math.round(flowsPerSec);
  if (fps === 0) return "0/s";
  if (fps < 1_000) return `${fps}/s`;
  if (fps < 1_000_000) return `${(fps / 1_000).toFixed(1)}K/s`;
  return `${(fps / 1_000_000).toFixed(2)}M/s`;
}

export function formatPackets(packetsPerSec: number): string {
  const pps = Math.round(packetsPerSec);
  if (pps === 0) return "0 pps";
  if (pps < 1_000) return `${pps} pps`;
  if (pps < 1_000_000) return `${(pps / 1_000).toFixed(1)}K pps`;
  if (pps < 1_000_000_000) return `${(pps / 1_000_000).toFixed(2)}M pps`;
  return `${(pps / 1_000_000_000).toFixed(2)}G pps`;
}

export function countryFlag(code: string): string {
  const upper = code.toUpperCase();
  if (upper === "??" || upper.length !== 2) return "\u{1F3F3}\u{FE0F}";
  return [...upper]
    .map((c) => String.fromCodePoint(0x1f1e6 + c.charCodeAt(0) - 65))
    .join("");
}
