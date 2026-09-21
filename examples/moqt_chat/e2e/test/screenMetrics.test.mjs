import { test } from "node:test";
import assert from "node:assert/strict";
import { screenGapStats } from "../lib/screenMetrics.mjs";

// Tap event shape (screenTap.ts): { senderId, width, height, t }, t in ms.

test("screenGapStats: per-sender frame gaps, p99 and stalls at/over the threshold", () => {
  const entries = [
    ...[0, 100, 200, 3200, 3300].map((t) => ({ senderId: "a", t })),
    ...[0, 100].map((t) => ({ senderId: "b", t })),
  ];
  const r = screenGapStats(entries, 3000);
  assert.equal(r.a.frames, 5);
  assert.equal(r.a.gapP99Ms, 3000);
  assert.equal(r.a.stalls, 1);
  assert.equal(r.b.stalls, 0);
  assert.equal(r.b.gapP99Ms, 100);
});

test("screenGapStats: a sender with one frame has no gaps and no stalls", () => {
  const r = screenGapStats([{ senderId: "a", t: 5 }], 3000);
  assert.deepEqual(r.a, { frames: 1, gapP99Ms: null, stalls: 0 });
  assert.deepEqual(screenGapStats([], 3000), {});
});
