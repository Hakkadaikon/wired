// S9 survivor-hears-rejoin: with exactly TWO participants, one crashes and
// rejoins. The gate is the direction every other reconnect scenario missed:
// the SURVIVOR (who never touched its browser) must decode the rejoined
// peer's audio again -- with two clients, the survivor's decode counter can
// only advance on frames from the rejoined peer, so the signal is clean.
// (The churn scenario gated the REJOINER's decode; survivors there heard
// each other, masking exactly this bug.)

import {
  joinStabilityClient,
  waitFirstDecode,
  clientMetrics,
  crashClient,
  closeClient,
} from "../lib/stabilityClient.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function run({ pageUrl, server, arg, log }) {
  const resumeMaxMs = Number(arg("resume-max-ms", "5000"));
  const failures = [];
  const opts = (tag) => ({ pageUrl, serverUrl: "", certHash: server.certHash, participantId: tag });

  log("joining survivor user1");
  const survivor = await joinStabilityClient(opts("user1"));
  log("joining user2 (will crash and rejoin)");
  let churner = await joinStabilityClient(opts("user2"));
  await waitFirstDecode(survivor); // survivor hears user2: room is live
  await waitFirstDecode(churner);
  log("room live; crashing user2");
  await crashClient(churner);
  await sleep(3000); // let the survivor's pipeline actually go silent

  const atRejoin = await clientMetrics(survivor);
  log("user2 rejoins");
  churner = await joinStabilityClient(opts("user2"));
  let rejoinerHears = null;
  try {
    await waitFirstDecode(churner, { timeoutMs: 15000 });
    rejoinerHears = true;
  } catch {
    rejoinerHears = false;
    failures.push("rejoined user2 never decoded audio (rejoiner side)");
  }
  let survivorResumeMs = null;
  try {
    const at = await waitFirstDecode(survivor, {
      past: atRejoin.decodedFrameCount,
      timeoutMs: resumeMaxMs + 15000,
    });
    survivorResumeMs = at - churner.joinedAt;
  } catch {
    failures.push(
      "survivor never decoded the rejoined peer's audio (the refresh-to-hear bug)",
    );
  }
  if (survivorResumeMs !== null && survivorResumeMs > resumeMaxMs) {
    failures.push(`survivor resumed only after ${survivorResumeMs}ms > ${resumeMaxMs}ms`);
  }

  const report = { rejoinerHears, survivorResumeMs };
  for (const c of [survivor, churner]) {
    for (const e of c.errors.filter((m) => !m.includes("Connection lost")))
      failures.push(`${c.tag} page error: ${e}`);
    await closeClient(c);
  }
  return { report, failures };
}
