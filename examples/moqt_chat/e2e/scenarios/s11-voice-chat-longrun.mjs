// S11 voice-chat-longrun: manual-only long-duration variant of s10
// (voice-chat-longevity), default 5 minutes. NOT run by CI or any `just`
// recipe -- invoke by hand when checking a fix against the original user
// report ("voice cuts out after about a minute of talking"):
//
//   just e2e-stability s11-voice-chat-longrun
//   just e2e-stability s11-voice-chat-longrun --talk-ms=600000  # 10 min
//
// stabilityClient.mjs's per-page voice-tap buffer caps at 30000 events
// (~150 events/s per page at 4 clients x ~50fps -> caps out around 200s),
// so summarizeVoiceTrace's playheadLag.lastQuarterMeanMs stops reflecting
// the true END of a run this long -- it silently reflects an earlier point
// once the buffer fills. Treat the printed report's playheadLag/interArrival
// numbers as informational past that point; the authoritative signal for a
// run this long is the server's own shutdown log line ("moqt relay:
// sent=... dropped=... open_dropped=..."), which has no such cap. Read it
// from evidence-dir's server.log after the run.

import { run as runS10 } from "./s10-voice-chat-longevity.mjs";

const FIVE_MIN_MS = "300000";

export async function run(ctx) {
  const arg = (name, fallback) =>
    ctx.arg(name, name === "talk-ms" ? FIVE_MIN_MS : fallback);
  return runS10({ ...ctx, arg });
}
