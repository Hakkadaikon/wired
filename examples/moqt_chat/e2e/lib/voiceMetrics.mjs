// Per-frame voice trace aggregation for the chat+voice load test. Pure
// functions, no I/O -- unit-testable like metrics.mjs.
//
// Input: { pageTag: TapEvent[] } where TapEvent is
//   { dir: 'send'|'recv'|'drain'|'play', seq, t, src?, lag? }
// as emitted by the frontend's voiceTap and buffered by voiceLoadTest.mjs's
// injected window.__wiredVoiceTap. Every t shares the Date.now() epoch (the
// tap installer adds each page's Date.now()-performance.now() offset), so a
// receiver-page t minus a sender-page t is absolute milliseconds. seq is the
// u16 wire seq; matching by seq is only unambiguous while a run stays under
// 65536 frames per sender (~21 min at 50 fps) -- fine for a load-test run.

function nearestRankPercentile(sorted, p) {
  if (sorted.length === 0) return null;
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(Math.max(rank, 1), sorted.length) - 1];
}

export function percentileStats(values) {
  if (values.length === 0) return null;
  const s = values.slice().sort((a, b) => a - b);
  return {
    p50: nearestRankPercentile(s, 50),
    p95: nearestRankPercentile(s, 95),
    p99: nearestRankPercentile(s, 99),
  };
}

// Forward u16 distance; > 32768 means the frame is behind `expected`
// (reorder/duplicate/late), not a huge loss.
const u16Gap = (seq, expected) => (seq - expected) & 0xffff;

export function seqGapStats(recvEvents) {
  let lost = 0;
  const burstHistogram = {};
  let expected = null;
  for (const e of recvEvents) {
    if (expected !== null) {
      const gap = u16Gap(e.seq, expected);
      if (gap > 32768) continue; // late/reordered: don't move expected back
      if (gap > 0) {
        lost += gap;
        burstHistogram[gap] = (burstHistogram[gap] ?? 0) + 1;
      }
    }
    expected = (e.seq + 1) & 0xffff;
  }
  const received = recvEvents.length;
  return {
    received,
    lost,
    lossRate: received + lost === 0 ? 0 : lost / (received + lost),
    burstHistogram,
  };
}

export function interArrivalStats(recvEvents) {
  const deltas = [];
  for (let i = 1; i < recvEvents.length; i++) {
    deltas.push(recvEvents[i].t - recvEvents[i - 1].t);
  }
  const histogram = {};
  for (const d of deltas) {
    const lo = Math.max(0, Math.floor(d / 5) * 5);
    const bucket = d >= 100 ? ">100" : `${lo}-${lo + 5}`;
    histogram[bucket] = (histogram[bucket] ?? 0) + 1;
  }
  const stats = percentileStats(deltas) ?? { p50: null, p95: null, p99: null };
  return { ...stats, histogram };
}

export function playheadLagStats(playEvents) {
  const lags = playEvents.map((e) => e.lag).filter((v) => typeof v === "number");
  if (lags.length === 0) return null;
  const mean = (arr) => arr.reduce((a, b) => a + b, 0) / arr.length;
  const q = Math.floor(lags.length / 4);
  const { p50, p95 } = percentileStats(lags);
  return {
    min: Math.min(...lags),
    max: Math.max(...lags),
    p50,
    p95,
    // last >> first reveals a monotonically growing playhead backlog.
    firstQuarterMeanMs: mean(q > 0 ? lags.slice(0, q) : lags),
    lastQuarterMeanMs: mean(q > 0 ? lags.slice(-q) : lags),
  };
}

function groupBySrc(events) {
  const groups = new Map();
  for (const e of events) {
    const key = e.src ?? "";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(e);
  }
  return groups;
}

// pageTag -> Map(seq -> first send t) built from each page's own send events.
function sendTimesByPage(pagesEvents) {
  const out = new Map();
  for (const [tag, events] of Object.entries(pagesEvents)) {
    const bySeq = new Map();
    for (const e of events ?? []) {
      if (e.dir === "send" && !bySeq.has(e.seq)) bySeq.set(e.seq, e.t);
    }
    out.set(tag, bySeq);
  }
  return out;
}

function latenciesAgainst(sendTimes, events) {
  const out = [];
  for (const e of events) {
    const t0 = sendTimes.get(e.seq);
    if (t0 !== undefined) out.push(e.t - t0);
  }
  return out;
}

// Buffer dwell per seq: first drain t minus first recv t, same page/epoch.
function dwellTimes(recvEvents, drainEvents) {
  const recvBySeq = new Map();
  for (const e of recvEvents) if (!recvBySeq.has(e.seq)) recvBySeq.set(e.seq, e.t);
  const out = [];
  const seen = new Set();
  for (const e of drainEvents) {
    if (seen.has(e.seq)) continue;
    seen.add(e.seq);
    const t0 = recvBySeq.get(e.seq);
    if (t0 !== undefined) out.push(e.t - t0);
  }
  return out;
}

export function summarizeVoiceTrace(pagesEvents) {
  const sendTimes = sendTimesByPage(pagesEvents);
  const out = {};
  for (const [tag, events] of Object.entries(pagesEvents)) {
    const evs = events ?? [];
    const recvGroups = groupBySrc(evs.filter((e) => e.dir === "recv"));
    const drainGroups = groupBySrc(evs.filter((e) => e.dir === "drain"));
    const perSender = {};
    for (const [src, recvs] of recvGroups) {
      const drains = drainGroups.get(src) ?? [];
      const senderSends = sendTimes.get(src) ?? new Map();
      perSender[src] = {
        recvLatencyMs: percentileStats(latenciesAgainst(senderSends, recvs)),
        drainLatencyMs: percentileStats(latenciesAgainst(senderSends, drains)),
        dwellMs: percentileStats(dwellTimes(recvs, drains)),
        loss: seqGapStats(recvs),
        interArrivalMs: interArrivalStats(recvs),
      };
    }
    out[tag] = {
      perSender,
      playheadLag: playheadLagStats(evs.filter((e) => e.dir === "play")),
    };
  }
  return out;
}
