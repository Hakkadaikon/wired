import test from "node:test";
import assert from "node:assert/strict";
import { evaluateVoiceGates } from "../lib/voiceGates.mjs";

const trace = ({ lossRate = 0, lost = 0, received = 100, p99 = 20, firstQ = 10, lastQ = 20 }) => ({
  user1: {
    perSender: {
      user2: {
        loss: { lossRate, lost, received },
        interArrivalMs: { p50: 20, p95: 25, p99 },
      },
    },
    playheadLag: {
      firstQuarterMeanMs: firstQ,
      lastQuarterMeanMs: lastQ,
      min: 0,
      max: lastQ,
      p50: firstQ,
      p95: lastQ,
    },
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
