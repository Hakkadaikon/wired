// Pure record-level forensics over the server's qlog JSON-SEQ stream
// (stream_frame_sent / stream_frame_lost / stream_frame_received), built to
// break the S3 chat-loss dead end -- "sent ... but never arrived" -- into
// concrete server-side verdicts. No I/O here; analyze-s3-qlog.mjs is the
// driver that feeds it a real run's server.qlog + report.json.

const STREAM_EVENTS = new Set([
  "stream_frame_sent",
  "stream_frame_lost",
  "stream_frame_received",
]);

// A chat message on the wire is a ~3-byte WT signal + one small Object
// (~16B text). Anything a one-shot chat stream carries fits well under
// this; the nearest other traffic (voice) crosses it within one frame.
const ONE_SHOT_MAX_BYTES = 64;

/** RS(0x1e)-delimited JSON-SEQ -> array of records; broken records skipped. */
export function parseJsonSeq(input) {
  const text = typeof input === "string" ? input : input.toString("utf8");
  const out = [];
  for (const part of text.split("\x1e")) {
    const body = part.trim();
    if (!body) continue;
    try {
      out.push(JSON.parse(body));
    } catch {
      // A torn write (server killed mid-record) must not sink the run.
    }
  }
  return out;
}

/** Distinct group_id in first-appearance order = connection join order. */
export function groupIdsInOrder(records) {
  const seen = new Set();
  for (const r of records) {
    if (r.group_id !== undefined) seen.add(r.group_id);
  }
  return [...seen];
}

/**
 * One connection's stream_frame_* records, bucketed per stream:
 * [{streamId, sent[], lost[], received[]}] sorted by streamId. Each event
 * keeps {offset, length, fin, pn, time}.
 */
export function groupStreams(records, groupId) {
  const byId = new Map();
  for (const r of records) {
    if (r.group_id !== groupId || !STREAM_EVENTS.has(r.name)) continue;
    let s = byId.get(r.stream_id);
    if (!s) {
      s = { streamId: r.stream_id, sent: [], lost: [], received: [] };
      byId.set(r.stream_id, s);
    }
    const bucket = r.name === "stream_frame_sent" ? s.sent : r.name === "stream_frame_lost" ? s.lost : s.received;
    bucket.push({ offset: r.offset, length: r.length, fin: r.fin, pn: r.pn, time: r.time });
  }
  return [...byId.values()].sort((a, b) => a.streamId - b.streamId);
}

function allEvents(s) {
  return [...s.sent, ...s.received];
}

function extent(s) {
  return allEvents(s).reduce((m, e) => Math.max(m, e.offset + e.length), 0);
}

function finSeen(s) {
  return allEvents(s).some((e) => e.fin === 1);
}

/**
 * One-shot (a chat message: tiny AND finished) vs keep-open (voice,
 * H3 control/QPACK, or a voice stream churned/cut before its data grew --
 * small byte counts alone must not read as chat, hence the fin requirement).
 */
export function splitOneShotVsKeepOpen(streams, { maxBytes = ONE_SHOT_MAX_BYTES } = {}) {
  const oneShot = [];
  const keepOpen = [];
  for (const s of streams) {
    (finSeen(s) && extent(s) <= maxBytes ? oneShot : keepOpen).push(s);
  }
  return { oneShot, keepOpen };
}

/**
 * The connection's chat uploads in send order: client-initiated uni
 * (id%4==2) one-shot streams the server received, sorted by stream id
 * (QUIC assigns ids in open order, so index k = msg:<tag>:k).
 */
export function chatUploadSeq(streams) {
  const uploads = streams.filter((s) => s.streamId % 4 === 2 && s.received.length > 0);
  return splitOneShotVsKeepOpen(uploads).oneShot.sort((a, b) => a.streamId - b.streamId);
}

function completedAt(s) {
  return s.received.reduce((m, e) => Math.max(m, e.time), 0);
}

/**
 * Hub dispatch order of all chat messages: each tag's upload seq indexed
 * into ids, merged by reassembly-completion time (the hub relays a message
 * when its object completes, not when its first byte lands -- a
 * retransmitted upload dispatches late). Ties keep tag-key order.
 * @param {Record<string, ReturnType<typeof chatUploadSeq>>} uploadsByTag
 * @returns {{id:string, tag:string, k:number, completedAt:number}[]}
 */
export function dispatchOrder(uploadsByTag) {
  const all = [];
  for (const [tag, uploads] of Object.entries(uploadsByTag)) {
    uploads.forEach((s, k) => {
      all.push({ id: `msg:${tag}:${k}`, tag, k, completedAt: completedAt(s) });
    });
  }
  return all.sort((a, b) => a.completedAt - b.completedAt);
}

function resendCount(s) {
  const pnsByOffset = new Map();
  for (const e of s.sent) {
    const set = pnsByOffset.get(e.offset) ?? new Set();
    set.add(e.pn);
    pnsByOffset.set(e.offset, set);
  }
  return [...pnsByOffset.values()].reduce((n, set) => n + (set.size - 1), 0);
}

/**
 * The three-way (plus one honest extra) breakdown of a missing message's
 * relay stream:
 *  - never-sent:      no stream_frame_sent at all -> hub mapping/relay bug
 *  - sent-no-loss:    sent, loss detection never fired -> loss-detect gap
 *  - lost-and-resent: declared lost AND re-sent, yet still missing
 *  - lost-not-resent: declared lost, retransmission never went out
 */
export function verdictForMissing({ relayStream }) {
  if (!relayStream || relayStream.sent.length === 0) return { verdict: "never-sent" };
  if (relayStream.lost.length === 0) {
    return { verdict: "sent-no-loss", sentCount: relayStream.sent.length };
  }
  const resends = resendCount(relayStream);
  if (resends === 0) return { verdict: "lost-not-resent", lostCount: relayStream.lost.length };
  return { verdict: "lost-and-resent", resendCount: resends, lostCount: relayStream.lost.length };
}

/**
 * Positional mapping of a receiver's expected message sequence (dispatch
 * order minus its own messages) onto its one-shot relay streams. Refuses
 * (alignment-failed) rather than guessing when the counts or the
 * arrived/missing sets don't reconcile with the expectation.
 */
export function alignRelays({ expectedIds, relayStreams, arrivedIds, missingIds }) {
  if (expectedIds.length !== relayStreams.length) {
    return {
      ok: false,
      reason: `alignment-failed: expected ${expectedIds.length} relay streams, qlog has ${relayStreams.length}`,
    };
  }
  const expected = new Set(expectedIds);
  for (const id of [...arrivedIds, ...missingIds]) {
    if (!expected.has(id)) {
      return { ok: false, reason: `alignment-failed: ${id} not in the expected sequence` };
    }
  }
  const accounted = new Set([...arrivedIds, ...missingIds]);
  if (accounted.size !== expected.size) {
    return {
      ok: false,
      reason: `alignment-failed: ${expected.size} expected but only ${accounted.size} accounted for by arrivals+missing`,
    };
  }
  const byId = {};
  expectedIds.forEach((id, i) => {
    byId[id] = relayStreams[i];
  });
  return { ok: true, byId };
}
