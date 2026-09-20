import { test } from "node:test";
import assert from "node:assert/strict";
import {
  percentileStats,
  seqGapStats,
  interArrivalStats,
  playheadLagStats,
  sendBytesMean,
  summarizeVoiceTrace,
} from "../lib/voiceMetrics.mjs";

// Tap event shape (voiceLoadTest.mjs installs the tap; all t share the
// Date.now() epoch): { dir: 'send'|'recv'|'drain'|'play', seq, t, src?, lag? }

test("percentileStats: nearest-rank p50/p95/p99, null on empty", () => {
  const vals = Array.from({ length: 100 }, (_, i) => i + 1); // 1..100
  assert.deepEqual(percentileStats(vals), { p50: 50, p95: 95, p99: 99 });
  assert.equal(percentileStats([]), null);
});

test("seqGapStats: contiguous sequence has zero loss", () => {
  const recvs = [0, 1, 2, 3].map((seq, i) => ({ dir: "recv", seq, t: i * 20 }));
  const r = seqGapStats(recvs);
  assert.equal(r.lost, 0);
  assert.equal(r.lossRate, 0);
  assert.deepEqual(r.burstHistogram, {});
});

test("seqGapStats: a gap of 2 counts 2 lost and one burst of length 2", () => {
  const recvs = [0, 1, 4, 5].map((seq, i) => ({ dir: "recv", seq, t: i * 20 }));
  const r = seqGapStats(recvs);
  assert.equal(r.lost, 2);
  assert.equal(r.lossRate, 2 / 6); // 4 received + 2 lost
  assert.deepEqual(r.burstHistogram, { 2: 1 });
});

test("seqGapStats: u16 wrap 65534,65535,0,1 is contiguous, not a huge loss", () => {
  const recvs = [65534, 65535, 0, 1].map((seq, i) => ({ dir: "recv", seq, t: i * 20 }));
  const r = seqGapStats(recvs);
  assert.equal(r.lost, 0);
});

test("seqGapStats: a loss burst across the wrap boundary is counted", () => {
  const recvs = [65534, 1].map((seq, i) => ({ dir: "recv", seq, t: i * 20 }));
  // 65535 and 0 lost
  const r = seqGapStats(recvs);
  assert.equal(r.lost, 2);
  assert.deepEqual(r.burstHistogram, { 2: 1 });
});

test("seqGapStats: a reordered/late frame (backward gap) is not loss", () => {
  const recvs = [0, 1, 2, 1, 3].map((seq, i) => ({ dir: "recv", seq, t: i * 20 }));
  const r = seqGapStats(recvs);
  assert.equal(r.lost, 0);
});

test("interArrivalStats: percentiles and 5ms-bucket histogram with >100 bucket", () => {
  // arrival deltas: 20, 20, 25, 150
  const recvs = [0, 20, 40, 65, 215].map((t, i) => ({ dir: "recv", seq: i, t }));
  const r = interArrivalStats(recvs);
  assert.equal(r.p50, 20);
  assert.deepEqual(r.histogram, { "20-25": 2, "25-30": 1, ">100": 1 });
});

test("playheadLagStats: min/max/p50/p95 and quarter means expose monotonic growth", () => {
  const lags = Array.from({ length: 8 }, (_, i) => (i + 1) * 10); // 10..80
  const plays = lags.map((lag, i) => ({ dir: "play", seq: -1, t: i * 20, lag }));
  const r = playheadLagStats(plays);
  assert.equal(r.min, 10);
  assert.equal(r.max, 80);
  assert.equal(r.p50, 40);
  assert.equal(r.p95, 80);
  assert.equal(r.firstQuarterMeanMs, 15); // mean(10, 20)
  assert.equal(r.lastQuarterMeanMs, 75); // mean(70, 80)
  assert.equal(playheadLagStats([]), null);
});

test("sendBytesMean: mean of send events' bytes, null when none carry it", () => {
  const sends = [
    { dir: "send", seq: 0, t: 0, bytes: 80 },
    { dir: "send", seq: 1, t: 20, bytes: 100 },
  ];
  assert.equal(sendBytesMean(sends), 90);
  assert.equal(sendBytesMean([{ dir: "send", seq: 0, t: 0 }]), null);
  assert.equal(sendBytesMean([]), null);
});

test("summarizeVoiceTrace: cross-page send->recv/drain latency and dwell per sender", () => {
  const pages = {
    A: [
      { dir: "send", seq: 0, t: 1000, bytes: 80 },
      { dir: "send", seq: 1, t: 1020, bytes: 100 },
    ],
    B: [
      { dir: "recv", seq: 0, src: "A", t: 1050 },
      { dir: "recv", seq: 1, src: "A", t: 1075 },
      { dir: "drain", seq: 0, src: "A", t: 1060 },
      { dir: "drain", seq: 1, src: "A", t: 1085 },
      { dir: "play", seq: -1, t: 1061, lag: 5 },
    ],
  };
  const out = summarizeVoiceTrace(pages);
  const forA = out.B.perSender.A;
  assert.deepEqual(forA.recvLatencyMs, { p50: 50, p95: 55, p99: 55 });
  assert.deepEqual(forA.drainLatencyMs, { p50: 60, p95: 65, p99: 65 });
  assert.deepEqual(forA.dwellMs, { p50: 10, p95: 10, p99: 10 });
  assert.equal(forA.loss.lost, 0);
  assert.equal(forA.sendBytesMean, 90);
  assert.equal(out.B.playheadLag.max, 5);
  assert.deepEqual(out.A.perSender, {}); // sender page received nothing
});

test("summarizeVoiceTrace: events without src fall into a single '' group", () => {
  const pages = {
    B: [
      { dir: "recv", seq: 0, t: 10 },
      { dir: "recv", seq: 1, t: 30 },
    ],
  };
  const out = summarizeVoiceTrace(pages);
  assert.equal(out.B.perSender[""].loss.received, 2);
  assert.equal(out.B.perSender[""].recvLatencyMs, null); // no matching send page
});

test("summarizeVoiceTrace: a null page (evaluate failed) is skipped, not a crash", () => {
  const out = summarizeVoiceTrace({ A: null });
  assert.deepEqual(out.A.perSender, {});
});

test("summarizeVoiceTrace: per-sender jitter buffer depth p50/p95 from drain events", () => {
  const pages = {
    B: [
      { dir: "recv", seq: 0, src: "A", t: 0 },
      { dir: "drain", seq: 0, src: "A", t: 0, depth: 1 },
      { dir: "drain", seq: 1, src: "A", t: 20, depth: 2 },
      { dir: "drain", seq: 2, src: "A", t: 40, depth: 3 },
      { dir: "drain", seq: 3, src: "A", t: 60, depth: 4 },
    ],
  };
  const out = summarizeVoiceTrace(pages);
  assert.deepEqual(out.B.perSender.A.depth, { p50: 2, p95: 4, p99: 4 });
});

test("summarizeVoiceTrace: per-sender plcCount counts drain events with plc:true, not frames", () => {
  const pages = {
    B: [
      { dir: "recv", seq: 0, src: "A", t: 0 },
      { dir: "drain", seq: 0, src: "A", t: 0, depth: 1 },
      { dir: "drain", seq: 1, src: "A", t: 20, plc: true },
      { dir: "drain", seq: 2, src: "A", t: 40, plc: true },
    ],
  };
  const out = summarizeVoiceTrace(pages);
  assert.equal(out.B.perSender.A.plcCount, 2);
});

test("summarizeVoiceTrace: skippedCount counts page-level play events with skipped:true", () => {
  const pages = {
    B: [
      { dir: "play", seq: -1, t: 0, lag: 5 },
      { dir: "play", seq: -1, t: 20, skipped: true },
      { dir: "play", seq: -1, t: 40, skipped: true },
    ],
  };
  const out = summarizeVoiceTrace(pages);
  assert.equal(out.B.skippedCount, 2);
});

test("summarizeVoiceTrace: depth/plcCount/skippedCount default to sane empties", () => {
  const out = summarizeVoiceTrace({ B: [] });
  assert.deepEqual(out.B.perSender, {});
  assert.equal(out.B.skippedCount, 0);
  assert.equal(out.B.playCount, 0);
});
