import { describe, it, expect } from "vitest";
import { mergeVlans } from "../utils/aggregate";
import type { WsMessage } from "../types";

const sampleMsg: WsMessage = {
  ts: 1000,
  window: 30,
  active_vlans: 2,
  vlans: {
    "100": {
      upload: {
        total_bytes: 3000,
        total_flows: 30,
        total_packets: 300,
        total_asns: 5,
        asns: [
          {
            asn: 13335,
            name: "Cloudflare",
            country: "US",
            bytes: 2000,
            flows: 20,
            packets: 200,
          },
          {
            asn: 15169,
            name: "Google",
            country: "US",
            bytes: 1000,
            flows: 10,
            packets: 100,
          },
        ],
      },
      download: {
        total_bytes: 2000,
        total_flows: 20,
        total_packets: 200,
        total_asns: 4,
        asns: [
          {
            asn: 16509,
            name: "Amazon",
            country: "US",
            bytes: 1500,
            flows: 15,
            packets: 150,
          },
          {
            asn: 13335,
            name: "Cloudflare",
            country: "US",
            bytes: 500,
            flows: 5,
            packets: 50,
          },
        ],
      },
    },
    "200": {
      upload: {
        total_bytes: 1000,
        total_flows: 10,
        total_packets: 100,
        total_asns: 3,
        asns: [
          {
            asn: 13335,
            name: "Cloudflare",
            country: "US",
            bytes: 1000,
            flows: 10,
            packets: 100,
          },
        ],
      },
      download: {
        total_bytes: 500,
        total_flows: 5,
        total_packets: 50,
        total_asns: 2,
        asns: [
          {
            asn: 15169,
            name: "Google",
            country: "US",
            bytes: 500,
            flows: 5,
            packets: 50,
          },
        ],
      },
    },
  },
};

describe("mergeVlans", () => {
  it("merges all vlans when all selected", () => {
    const view = mergeVlans(sampleMsg, ["100", "200"], "bytes");
    // totalBytes uses download only (each flow counted once, not upload+download)
    expect(view.totalBytes).toBe(2500);
    expect(view.totalFlows).toBe(25);
    expect(view.activeVlans).toBe(2);
    expect(view.upload.totalBytes).toBe(4000);
    expect(view.download.totalBytes).toBe(2500);
  });

  it("filters to single vlan", () => {
    const view = mergeVlans(sampleMsg, ["200"], "bytes");
    expect(view.totalBytes).toBe(500); // download total for vlan 200
    expect(view.upload.asns.length).toBe(1);
    expect(view.download.asns.length).toBe(1);
  });

  it("sorts by flows when groupBy is flows", () => {
    const view = mergeVlans(sampleMsg, ["100"], "flows");
    expect(view.upload.asns[0].asn).toBe(13335);
    expect(view.upload.asns[1].asn).toBe(15169);
  });

  it("computes share percentages for upload", () => {
    const view = mergeVlans(sampleMsg, ["100"], "bytes");
    expect(view.upload.asns[0].share).toBeCloseTo(2 / 3);
    expect(view.upload.asns[1].share).toBeCloseTo(1 / 3);
  });

  it("assigns distinct colors to each ASN", () => {
    const view = mergeVlans(sampleMsg, ["100"], "bytes");
    expect(view.upload.asns[0].color).toMatch(/^#[0-9a-f]{6}$/);
    expect(view.upload.asns[1].color).toMatch(/^#[0-9a-f]{6}$/);
    expect(view.upload.asns[0].color).not.toBe(view.upload.asns[1].color);
  });

  it("handles empty selection", () => {
    const view = mergeVlans(sampleMsg, [], "bytes");
    expect(view.totalBytes).toBe(0);
    expect(view.upload.asns.length).toBe(0);
    expect(view.download.asns.length).toBe(0);
  });

  it("uses backend total_asns for activeAsns count", () => {
    const view = mergeVlans(sampleMsg, ["100"], "bytes");
    // upload: 5, download: 4 => 9 total (real count from backend, not just top_n)
    expect(view.activeAsns).toBe(9);
  });

  it("uses backend active_vlans", () => {
    const view = mergeVlans(sampleMsg, ["100"], "bytes");
    // Backend says 2 VLANs active regardless of frontend selection
    expect(view.activeVlans).toBe(2);
  });
});
