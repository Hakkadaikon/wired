// Screen-share receive metrics from the frontend's window.__wiredScreenTap
// entries (screenTap.ts: one per decoded frame, t = performance.now()).

import { percentileStats } from "./voiceMetrics.mjs";

/** Per sender: frame count, p99 of the gap between consecutive decoded
 * frames, and how many gaps reached stallMs (the tile's "Stalled" bar). */
export function screenGapStats(entries, stallMs) {
  const bySender = {};
  for (const e of entries) (bySender[e.senderId] ??= []).push(e.t);
  const out = {};
  for (const [sender, ts] of Object.entries(bySender)) {
    ts.sort((a, b) => a - b);
    const gaps = ts.slice(1).map((t, i) => t - ts[i]);
    out[sender] = {
      frames: ts.length,
      gapP99Ms: percentileStats(gaps)?.p99 ?? null,
      stalls: gaps.filter((g) => g >= stallMs).length,
    };
  }
  return out;
}
