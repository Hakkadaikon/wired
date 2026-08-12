// S6 voice-soak: 2-client voice-only endurance run, default 5 minutes
// (the nightly recipe passes --talk-ms=1500000 for 25). The per-frame
// voice-tap buffer caps out long before a run this long ends (s11's own
// doc: ~30000 events), so per-frame quality gates (s1/s10's
// voiceGates.mjs) would silently judge an EARLIER window of the run --
// this scenario gates on the UNCAPPED page counters instead:
//
// - decodedFrameCount must cover most of the expected frame budget
//   (20ms frames from one peer -> ~50/s), and
// - lastDecodeAt must land within the final seconds of the run,
//
// which together say "every receiver kept decoding to the very end" --
// the observable that long-haul receive flow control (the cumulative
// MAX_DATA ceiling that only monotonically advances as reassembled WT
// streams are reaped) never wedges a subscriber. Survival, not jitter:
// jitter gates stay s1/s10's job on runs short enough to trust the tap.

import {
  joinStabilityClient,
  waitFirstDecode,
  clientMetrics,
  closeClient,
} from "../lib/stabilityClient.mjs";

const TAGS = ["user1", "user2"];
const FRAMES_PER_SEC = 50; // 20ms voice frames from the one peer
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function run({ pageUrl, server, arg, log }) {
  const talkMs = Number(arg("talk-ms", "300000"));
  const progressMs = 60000;
  const clients = [];
  try {
    for (const tag of TAGS) {
      log(`joining ${tag} (direct, no proxy)`);
      clients.push(
        await joinStabilityClient({
          pageUrl,
          serverUrl: "",
          certHash: server.certHash,
          participantId: tag,
        }),
      );
    }
    for (const c of clients) await waitFirstDecode(c);
    log(`room live (2 clients); soaking for ${talkMs}ms`);

    for (let elapsed = 0; elapsed < talkMs; ) {
      const step = Math.min(progressMs, talkMs - elapsed);
      await sleep(step);
      elapsed += step;
      for (const c of clients) {
        const m = await clientMetrics(c);
        log(`${c.tag}: decoded=${m?.decodedFrameCount ?? "?"} @${elapsed}ms`);
      }
    }

    const endAt = Date.now();
    const expected = (talkMs / 1000) * FRAMES_PER_SEC;
    const failures = [];
    const counters = {};
    for (const c of clients) {
      const m = await clientMetrics(c);
      counters[c.tag] = {
        decodedFrameCount: m?.decodedFrameCount ?? 0,
        lastDecodeAt: m?.lastDecodeAt ?? null,
      };
      for (const e of c.errors) failures.push(`${c.tag} page error: ${e}`);
      if ((m?.decodedFrameCount ?? 0) < expected * 0.8)
        failures.push(
          `${c.tag}: decoded ${m?.decodedFrameCount ?? 0} < 80% of the ` +
            `~${Math.round(expected)}-frame budget`,
        );
      const last = m?.lastDecodeAt ?? 0;
      if (endAt - last > 5000)
        failures.push(
          `${c.tag}: last decode ${endAt - last}ms before run end ` +
            `(receiver stalled; still-decoding-at-end is the soak gate)`,
        );
    }

    const report = { talkMs, expectedFrames: Math.round(expected), counters };
    for (const c of clients) await closeClient(c);
    return { report, failures };
  } finally {
    /* no proxy to close */
  }
}
