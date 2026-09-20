import test from "node:test";
import assert from "node:assert/strict";
import { evaluateVoiceGates } from "../lib/voiceGates.mjs";

const trace = ({
  lossRate = 0,
  lost = 0,
  received = 100,
  p99 = 20,
  firstQ = 10,
  lastQ = 20,
  lagP95 = 20,
  sendBytesMean = 80,
  skippedCount = 0,
  playCount = 100,
  plcCount = 0,
}) => ({
  user1: {
    perSender: {
      user2: {
        loss: { lossRate, lost, received },
        interArrivalMs: { p50: 20, p95: 25, p99 },
        sendBytesMean,
        plcCount,
      },
    },
    playheadLag: {
      firstQuarterMeanMs: firstQ,
      lastQuarterMeanMs: lastQ,
      min: 0,
      max: lastQ,
      p50: firstQ,
      p95: lagP95,
    },
    skippedCount,
    playCount,
  },
});

test("clean trace passes every gate", () => {
  assert.deepEqual(evaluateVoiceGates(trace({})), []);
});

test("frame loss above threshold fails, at threshold passes", () => {
  assert.equal(evaluateVoiceGates(trace({ lossRate: 0.006, lost: 6 })).length, 1);
  assert.deepEqual(evaluateVoiceGates(trace({ lossRate: 0.005, lost: 5 })), []);
});

test("inter-arrival p99 above threshold fails", () => {
  const fails = evaluateVoiceGates(trace({ p99: 101 }));
  assert.equal(fails.length, 1);
  assert.match(fails[0], /inter-arrival/);
});

test("playhead lag growth above threshold fails", () => {
  const fails = evaluateVoiceGates(trace({ firstQ: 10, lastQ: 120 }));
  assert.equal(fails.length, 1);
  assert.match(fails[0], /playhead/);
});

test("mean send bytes above threshold fails, at threshold passes", () => {
  const fails = evaluateVoiceGates(trace({ sendBytesMean: 91 }));
  assert.equal(fails.length, 1);
  assert.match(fails[0], /send bytes/);
  assert.deepEqual(evaluateVoiceGates(trace({ sendBytesMean: 90 })), []);
});

test("overrides loosen a knob per profile", () => {
  assert.deepEqual(
    evaluateVoiceGates(trace({ lossRate: 0.03, lost: 30 }), { maxFrameLossRate: 0.05 }),
    [],
  );
});

test("missing sections do not crash", () => {
  assert.deepEqual(evaluateVoiceGates({ user1: { perSender: {}, playheadLag: null } }), []);
  assert.deepEqual(evaluateVoiceGates(undefined), []);
});

test("playhead lag p95 above threshold fails, at threshold passes", () => {
  const fails = evaluateVoiceGates(trace({ lagP95: 221 }));
  assert.equal(fails.length, 1);
  assert.match(fails[0], /lag p95/);
  assert.deepEqual(evaluateVoiceGates(trace({ lagP95: 220 })), []);
});

test("skipped rate above threshold fails, at threshold passes", () => {
  const fails = evaluateVoiceGates(trace({ skippedCount: 2, playCount: 100 })); // 2%
  assert.equal(fails.length, 1);
  assert.match(fails[0], /skip/);
  assert.deepEqual(evaluateVoiceGates(trace({ skippedCount: 1, playCount: 100 })), []); // 1%
});

test("skipped rate is report-only when there were no play attempts", () => {
  assert.deepEqual(evaluateVoiceGates(trace({ skippedCount: 0, playCount: 0 })), []);
});

test("plcCount above maxPlcCount fails, at the default (0) passes", () => {
  const fails = evaluateVoiceGates(trace({ plcCount: 1 }));
  assert.equal(fails.length, 1);
  assert.match(fails[0], /plc/i);
  assert.deepEqual(evaluateVoiceGates(trace({ plcCount: 0 })), []);
});

test("plcCount below minPlcCount fails when overridden; default minPlcCount (0) never fails", () => {
  assert.deepEqual(evaluateVoiceGates(trace({ plcCount: 0 })), []); // default: no minimum
  const fails = evaluateVoiceGates(trace({ plcCount: 0 }), { maxPlcCount: 5, minPlcCount: 1 });
  assert.equal(fails.length, 1);
  assert.match(fails[0], /plc/i);
  assert.deepEqual(
    evaluateVoiceGates(trace({ plcCount: 1 }), { maxPlcCount: 5, minPlcCount: 1 }),
    [],
  );
});

test("missing plcCount does not crash and is treated as zero", () => {
  assert.deepEqual(evaluateVoiceGates({ user1: { perSender: { user2: {} }, playheadLag: null } }), []);
});
