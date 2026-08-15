import test from "node:test";
import assert from "node:assert/strict";
import {
  parseJsonSeq,
  groupIdsInOrder,
  groupStreams,
  splitOneShotVsKeepOpen,
  chatUploadSeq,
  dispatchOrder,
  verdictForMissing,
  alignRelays,
} from "../lib/qlogStreamForensics.mjs";

// Test list (S3 chat-loss investigation, qlog forensics):
// 1. parseJsonSeq: RS-delimited JSON-SEQ -> records; a broken record is
//    skipped without killing the rest
// 2. groupIdsInOrder: distinct group_id in first-appearance order (= the
//    server's connection-slot join order)
// 3. groupStreams: one connection's stream_frame_* records bucketed per
//    stream_id into {sent, lost, received}, other events/groups ignored
// 4. splitOneShotVsKeepOpen: small+fin = one-shot; a churned voice stream
//    (small byte count but never finished) must NOT read as one-shot
// 5. chatUploadSeq: client-initiated uni (id%4==2), one-shot, received on
//    the server, ordered by stream id -- index k = msg:<tag>:k
// 6. dispatchOrder: merges per-tag upload seqs by reassembly-completion
//    time (the hub relays in completion order, not first-byte order)
// 7. verdictForMissing: never-sent / sent-no-loss / lost-and-resent /
//    lost-not-resent
// 8. alignRelays: positional expected-id -> relay-stream mapping, refusing
//    to guess when counts or arrival sets don't add up

const RS = "\x1e";
function seq(...objs) {
  return objs.map((o) => RS + JSON.stringify(o) + "\n").join("");
}
function ev(name, group, streamId, { off = 0, len = 19, fin = 1, pn = 0, time = 0 } = {}) {
  return {
    time,
    group_id: group,
    name,
    stream_id: streamId,
    offset: off,
    length: len,
    fin,
    pn,
  };
}

test("parseJsonSeq splits on RS and skips a broken record", () => {
  const buf = seq(ev("stream_frame_sent", 0, 7)) + RS + "{broken\n" + seq(ev("stream_frame_lost", 1, 7));
  const recs = parseJsonSeq(buf);
  assert.equal(recs.length, 2);
  assert.equal(recs[0].name, "stream_frame_sent");
  assert.equal(recs[1].group_id, 1);
});

test("groupIdsInOrder returns first-appearance order", () => {
  const recs = parseJsonSeq(
    seq(
      { time: 0, group_id: 2, name: "connection_state_updated", state: "x" },
      ev("stream_frame_sent", 0, 7),
      ev("stream_frame_sent", 2, 11),
      ev("stream_frame_sent", 1, 7),
    ),
  );
  assert.deepEqual(groupIdsInOrder(recs), [2, 0, 1]);
});

test("groupStreams buckets one group's frames per stream, ignores the rest", () => {
  const recs = parseJsonSeq(
    seq(
      ev("stream_frame_sent", 0, 7, { pn: 5 }),
      ev("stream_frame_lost", 0, 7, { pn: 5 }),
      ev("stream_frame_received", 0, 2, { len: 19, pn: 9 }),
      ev("stream_frame_sent", 1, 7, { pn: 1 }), // other connection
      { time: 3, group_id: 0, name: "packet_sent", pn: 6, bytes: 100 }, // other kind
    ),
  );
  const streams = groupStreams(recs, 0);
  assert.equal(streams.length, 2);
  const s7 = streams.find((s) => s.streamId === 7);
  assert.equal(s7.sent.length, 1);
  assert.equal(s7.sent[0].pn, 5);
  assert.equal(s7.lost.length, 1);
  const s2 = streams.find((s) => s.streamId === 2);
  assert.equal(s2.received.length, 1);
  assert.equal(s2.received[0].length, 19);
});

test("splitOneShotVsKeepOpen: small+fin is one-shot, unfinished small is not", () => {
  const recs = parseJsonSeq(
    seq(
      // chat relay: 19 bytes then bare FIN
      ev("stream_frame_sent", 0, 7, { off: 0, len: 19, fin: 0 }),
      ev("stream_frame_sent", 0, 7, { off: 19, len: 0, fin: 1 }),
      // voice relay: continuous append, no fin
      ev("stream_frame_sent", 0, 11, { off: 0, len: 500, fin: 0 }),
      ev("stream_frame_sent", 0, 11, { off: 500, len: 500, fin: 0 }),
      // churned voice relay: cut off after ~25 bytes, never finished --
      // byte count alone would misread this as a chat one-shot
      ev("stream_frame_sent", 0, 15, { off: 0, len: 25, fin: 0 }),
    ),
  );
  const { oneShot, keepOpen } = splitOneShotVsKeepOpen(groupStreams(recs, 0));
  assert.deepEqual(oneShot.map((s) => s.streamId), [7]);
  assert.deepEqual(keepOpen.map((s) => s.streamId).sort((a, b) => a - b), [11, 15]);
});

test("chatUploadSeq: client-uni one-shot receives, in stream-id order", () => {
  const recs = parseJsonSeq(
    seq(
      // H3 control stream: client uni but never finished
      ev("stream_frame_received", 0, 2, { len: 4, fin: 0 }),
      // voice upload: client uni, keep-open
      ev("stream_frame_received", 0, 6, { len: 800, fin: 0 }),
      // chat uploads, arriving out of stream-id order
      ev("stream_frame_received", 0, 14, { len: 19, fin: 1, time: 30 }),
      ev("stream_frame_received", 0, 10, { len: 19, fin: 1, time: 40 }),
      // server-initiated uni (relay) must not count as an upload
      ev("stream_frame_sent", 0, 7, { len: 19, fin: 1 }),
    ),
  );
  const uploads = chatUploadSeq(groupStreams(recs, 0));
  assert.deepEqual(uploads.map((s) => s.streamId), [10, 14]);
});

test("dispatchOrder merges tags by completion time, stable on ties", () => {
  const mk = (streamId, time) => ({
    streamId,
    sent: [],
    lost: [],
    received: [{ offset: 0, length: 19, fin: 1, pn: 0, time }],
  });
  const order = dispatchOrder({
    user1: [mk(2, 10), mk(6, 50)],
    user2: [mk(2, 20), mk(6, 50)],
  });
  assert.deepEqual(
    order.map((o) => o.id),
    ["msg:user1:0", "msg:user2:0", "msg:user1:1", "msg:user2:1"],
  );
});

test("verdictForMissing: the four-way classification", () => {
  assert.equal(verdictForMissing({ relayStream: null }).verdict, "never-sent");
  assert.equal(
    verdictForMissing({
      relayStream: { streamId: 7, sent: [], lost: [], received: [] },
    }).verdict,
    "never-sent",
  );
  assert.equal(
    verdictForMissing({
      relayStream: {
        streamId: 7,
        sent: [{ offset: 0, length: 19, fin: 1, pn: 3 }],
        lost: [],
        received: [],
      },
    }).verdict,
    "sent-no-loss",
  );
  const resent = verdictForMissing({
    relayStream: {
      streamId: 7,
      sent: [
        { offset: 0, length: 19, fin: 1, pn: 3 },
        { offset: 0, length: 19, fin: 1, pn: 8 }, // same offset, new pn
      ],
      lost: [{ offset: 0, length: 19, fin: 1, pn: 3 }],
      received: [],
    },
  });
  assert.equal(resent.verdict, "lost-and-resent");
  assert.equal(resent.resendCount, 1);
  assert.equal(
    verdictForMissing({
      relayStream: {
        streamId: 7,
        sent: [{ offset: 0, length: 19, fin: 1, pn: 3 }],
        lost: [{ offset: 0, length: 19, fin: 1, pn: 3 }],
        received: [],
      },
    }).verdict,
    "lost-not-resent",
  );
});

test("alignRelays maps expected ids positionally onto relay streams", () => {
  const relays = [{ streamId: 7 }, { streamId: 11 }, { streamId: 15 }];
  const r = alignRelays({
    expectedIds: ["msg:a:0", "msg:b:0", "msg:a:1"],
    relayStreams: relays,
    arrivedIds: ["msg:a:0", "msg:a:1"],
    missingIds: ["msg:b:0"],
  });
  assert.equal(r.ok, true);
  assert.equal(r.byId["msg:b:0"].streamId, 11);
});

test("alignRelays refuses on count mismatch or unexplained arrivals", () => {
  const short = alignRelays({
    expectedIds: ["msg:a:0", "msg:b:0"],
    relayStreams: [{ streamId: 7 }],
    arrivedIds: ["msg:a:0"],
    missingIds: ["msg:b:0"],
  });
  assert.equal(short.ok, false);
  assert.match(short.reason, /alignment-failed/);
  const stranger = alignRelays({
    expectedIds: ["msg:a:0"],
    relayStreams: [{ streamId: 7 }],
    arrivedIds: ["msg:zzz:9"],
    missingIds: [],
  });
  assert.equal(stranger.ok, false);
});
