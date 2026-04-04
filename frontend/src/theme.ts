// Solarized Dark — slightly customized for network monitoring
// Base: Ethan Schoonover's Solarized, with warmer card backgrounds
// and higher contrast accents for data-dense dashboards.

export const colors = {
  bg: "#002b36", // base03
  bgCard: "#073642", // base02
  bgHeader: "#01313d", // between base03 and base02
  border: "#586e75", // base01
  textPrimary: "#fdf6e3", // base3
  textSecondary: "#93a1a1", // base1
  textMuted: "#657b83", // base00
  accent: "#2aa198", // cyan
  accentGreen: "#859900", // green
  accentGreenBg: "#85990022",
  accentRed: "#dc322f", // red
  accentRedBg: "#dc322f33",
} as const;

export const chartOthers = "#586e75"; // base01

// Golden-angle hue distribution for maximum visual distinction.
// Top items (0-7) get Solarized accent hues at full saturation.
// Items 8+ use golden angle spacing with gradually reduced saturation
// so they're still distinguishable but visually recede.
const solarizedHues = [175, 205, 331, 68, 18, 237, 45, 1]; // cyan, blue, magenta, green, orange, violet, yellow, red
const GOLDEN_ANGLE = 137.508;

function hslToHex(h: number, s: number, l: number): string {
  const hNorm = ((h % 360) + 360) % 360;
  const sNorm = s / 100;
  const lNorm = l / 100;
  const c = (1 - Math.abs(2 * lNorm - 1)) * sNorm;
  const x = c * (1 - Math.abs(((hNorm / 60) % 2) - 1));
  const m = lNorm - c / 2;
  let r = 0,
    g = 0,
    b = 0;
  if (hNorm < 60) {
    r = c;
    g = x;
  } else if (hNorm < 120) {
    r = x;
    g = c;
  } else if (hNorm < 180) {
    g = c;
    b = x;
  } else if (hNorm < 240) {
    g = x;
    b = c;
  } else if (hNorm < 300) {
    r = x;
    b = c;
  } else {
    r = c;
    b = x;
  }
  const toHex = (v: number) =>
    Math.round((v + m) * 255)
      .toString(16)
      .padStart(2, "0");
  return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
}

/** Deterministic color for an ASN number — stable across rank changes. */
export function chartColorForAsn(asn: number): string {
  // Use golden angle spacing seeded by ASN number for maximum hue separation
  const hue = (asn * GOLDEN_ANGLE) % 360;
  return hslToHex(hue, 75, 52);
}

export function chartColor(index: number): string {
  if (index < solarizedHues.length) {
    // Top items: Solarized accent hues, high saturation, good lightness for dark bg
    return hslToHex(solarizedHues[index], 80, 55);
  }
  // Beyond palette: golden angle spacing for maximum hue separation
  // Gradually decrease saturation and shift lightness so they're subtler
  const rank = index - solarizedHues.length;
  const hue = (rank * GOLDEN_ANGLE + 30) % 360; // offset by 30 to avoid starting at 0
  const saturation = Math.max(45, 70 - rank * 0.8);
  const lightness = 45 + (rank % 3) * 5; // slight variation to break visual monotony
  return hslToHex(hue, saturation, lightness);
}
