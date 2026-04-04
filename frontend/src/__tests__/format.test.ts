import { describe, it, expect } from "vitest";
import { formatBytes, formatFlows, countryFlag } from "../utils/format";

describe("formatBytes", () => {
  it("formats zero", () => {
    expect(formatBytes(0)).toBe("0 bps");
  });
  it("formats bits", () => {
    expect(formatBytes(50)).toBe("400 bps");
  });
  it("formats Kbps", () => {
    expect(formatBytes(1500)).toBe("12.0 Kbps");
  });
  it("formats Mbps", () => {
    expect(formatBytes(12_500_000)).toBe("100.0 Mbps");
  });
  it("formats Gbps boundary", () => {
    expect(formatBytes(125_000_000)).toBe("1.00 Gbps");
  });
  it("formats Gbps", () => {
    expect(formatBytes(4_200_000_000)).toBe("33.60 Gbps");
  });
  it("formats Tbps", () => {
    expect(formatBytes(200_000_000_000)).toBe("1.60 Tbps");
  });
  it("rounds floats before formatting", () => {
    // 14000 / 3 = 4666.666... should not produce long decimals
    expect(formatBytes(14000 / 3)).toBe("37.3 Kbps");
  });
});

describe("formatFlows", () => {
  it("formats zero", () => {
    expect(formatFlows(0)).toBe("0/s");
  });
  it("formats small", () => {
    expect(formatFlows(340)).toBe("340/s");
  });
  it("formats thousands", () => {
    expect(formatFlows(128400)).toBe("128.4K/s");
  });
  it("formats millions", () => {
    expect(formatFlows(1_200_000)).toBe("1.20M/s");
  });
  it("rounds floats", () => {
    expect(formatFlows(100 / 3)).toBe("33/s");
  });
});

describe("countryFlag", () => {
  it("converts US", () => {
    expect(countryFlag("US")).toBe("\u{1F1FA}\u{1F1F8}");
  });
  it("converts DE", () => {
    expect(countryFlag("DE")).toBe("\u{1F1E9}\u{1F1EA}");
  });
  it("handles lowercase", () => {
    expect(countryFlag("gb")).toBe("\u{1F1EC}\u{1F1E7}");
  });
  it("handles unknown", () => {
    expect(countryFlag("??")).toBe("\u{1F3F3}\u{FE0F}");
  });
});
