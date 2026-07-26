import { test } from "node:test";
import assert from "node:assert/strict";
import { summarizeDelivery } from "../lib/metrics.mjs";

// sent: [{ id, senderTag, sentAt }]
// received: [{ id, receiverTag, receivedAt }]  -- one row per (message, receiver) pair actually observed

test("every message reaches every other client: 0% loss, latencies computed", () => {
  const sent = [
    { id: "m1", senderTag: "A", sentAt: 1000 },
    { id: "m2", senderTag: "B", sentAt: 2000 },
  ];
  const received = [
    { id: "m1", receiverTag: "B", receivedAt: 1050 },
    { id: "m1", receiverTag: "C", receivedAt: 1080 },
    { id: "m2", receiverTag: "A", receivedAt: 2040 },
    { id: "m2", receiverTag: "C", receivedAt: 2060 },
  ];
  const clients = ["A", "B", "C"];
  const result = summarizeDelivery(sent, received, clients);
  assert.equal(result.expectedDeliveries, 4); // 2 messages * 2 other clients each
  assert.equal(result.actualDeliveries, 4);
  assert.equal(result.lossRate, 0);
  assert.equal(result.latenciesMs.length, 4);
  assert.deepEqual(
    result.latenciesMs.slice().sort((a, b) => a - b),
    [40, 50, 60, 80],
  );
});

test("a message that never arrives at one client counts as lost, not as zero latency", () => {
  const sent = [{ id: "m1", senderTag: "A", sentAt: 1000 }];
  const received = [{ id: "m1", receiverTag: "B", receivedAt: 1050 }];
  // room of 3 (A, B, C): C never received it
  const result = summarizeDelivery(sent, received, ["A", "B", "C"]);
  assert.equal(result.expectedDeliveries, 2);
  assert.equal(result.actualDeliveries, 1);
  assert.equal(result.lossRate, 0.5);
  assert.deepEqual(result.latenciesMs, [50]);
});

test("total silence: every expected delivery lost, lossRate is 1, no crash on empty latencies", () => {
  const sent = [{ id: "m1", senderTag: "A", sentAt: 1000 }];
  const result = summarizeDelivery(sent, [], ["A", "B"]);
  assert.equal(result.expectedDeliveries, 1);
  assert.equal(result.actualDeliveries, 0);
  assert.equal(result.lossRate, 1);
  assert.deepEqual(result.latenciesMs, []);
  assert.equal(result.p50Ms, null);
  assert.equal(result.p95Ms, null);
});

test("no messages sent at all: lossRate is 0 (vacuously), not NaN", () => {
  const result = summarizeDelivery([], [], ["A", "B"]);
  assert.equal(result.expectedDeliveries, 0);
  assert.equal(result.lossRate, 0);
});

test("a duplicate receive of the same (message, receiver) counts once, not twice", () => {
  const sent = [{ id: "m1", senderTag: "A", sentAt: 1000 }];
  const received = [
    { id: "m1", receiverTag: "B", receivedAt: 1050 },
    { id: "m1", receiverTag: "B", receivedAt: 1060 }, // duplicate delivery
  ];
  const result = summarizeDelivery(sent, received, ["A", "B"]);
  assert.equal(result.expectedDeliveries, 1);
  assert.equal(result.actualDeliveries, 1);
  assert.deepEqual(result.latenciesMs, [50]); // first observed receipt wins
});

test("p50/p95 over a larger sample match nearest-rank percentile", () => {
  const sent = Array.from({ length: 10 }, (_, i) => ({
    id: `m${i}`,
    senderTag: "A",
    sentAt: 0,
  }));
  const received = sent.map((m, i) => ({
    id: m.id,
    receiverTag: "B",
    receivedAt: (i + 1) * 10, // latencies: 10..100
  }));
  const result = summarizeDelivery(sent, received, ["A", "B"]);
  assert.equal(result.p50Ms, 50);
  assert.equal(result.p95Ms, 100);
});

test("a receive from a client not in the room is ignored, not counted as extra delivery", () => {
  const sent = [{ id: "m1", senderTag: "A", sentAt: 1000 }];
  const received = [{ id: "m1", receiverTag: "ghost", receivedAt: 1050 }];
  const result = summarizeDelivery(sent, received, ["A", "B"]);
  assert.equal(result.expectedDeliveries, 1);
  assert.equal(result.actualDeliveries, 0);
});

test("a sender never counts itself as an expected recipient", () => {
  const sent = [{ id: "m1", senderTag: "A", sentAt: 1000 }];
  const received = [{ id: "m1", receiverTag: "A", receivedAt: 1005 }]; // echo, should be ignored
  const result = summarizeDelivery(sent, received, ["A", "B"]);
  assert.equal(result.expectedDeliveries, 1); // only B expected
  assert.equal(result.actualDeliveries, 0); // A's own echo doesn't satisfy B's delivery
});
