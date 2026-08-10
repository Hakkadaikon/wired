// S5 reconnect-churn: 3 voice clients; one of them repeatedly crashes
// (browser SIGKILL -- no clean close reaches the server) and immediately
// rejoins. Gate: every rejoin is decoding audio again within the budget,
// and the two survivors never stop hearing each other.

import {
  joinStabilityClient,
  waitFirstDecode,
  clientMetrics,
  crashClient,
  closeClient,
} from "../lib/stabilityClient.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function run({ pageUrl, server, arg, log }) {
  const cycles = Number(arg("cycles", "6"));
  const dwellMs = Number(arg("dwell-ms", "10000"));
  const rejoinMaxMs = Number(arg("rejoin-max-ms", "5000"));
  const failures = [];
  const opts = (tag) => ({ pageUrl, serverUrl: "", certHash: server.certHash, participantId: tag });

  const survivors = [];
  for (const tag of ["user1", "user2"]) {
    log(`joining ${tag}`);
    survivors.push(await joinStabilityClient(opts(tag)));
  }
  let churner = await joinStabilityClient(opts("user3"));
  for (const c of [...survivors, churner]) await waitFirstDecode(c);
  log("room live (3 clients)");

  const cycleResults = [];
  for (let k = 1; k <= cycles; k++) {
    await sleep(dwellMs);
    const before = await Promise.all(survivors.map((c) => clientMetrics(c)));
    log(`cycle ${k}: crashing user3`);
    await crashClient(churner);
    const t0 = Date.now();
    churner = await joinStabilityClient(opts("user3"));
    let rejoinMs = null;
    try {
      await waitFirstDecode(churner, { timeoutMs: rejoinMaxMs + 10000 });
      rejoinMs = Date.now() - t0;
    } catch {
      failures.push(`cycle ${k}: rejoined user3 never decoded audio`);
    }
    if (rejoinMs !== null && rejoinMs > rejoinMaxMs) {
      failures.push(`cycle ${k}: rejoin ${rejoinMs}ms > ${rejoinMaxMs}ms`);
    }
    // Survivors must keep decoding through the churn (their pair audio does
    // not route through user3).
    await sleep(2000);
    const after = await Promise.all(survivors.map((c) => clientMetrics(c)));
    for (let i = 0; i < survivors.length; i++) {
      if (after[i].decodedFrameCount <= before[i].decodedFrameCount) {
        failures.push(`cycle ${k}: survivor ${survivors[i].tag} stopped decoding`);
      }
    }
    cycleResults.push({ cycle: k, rejoinMs });
  }

  const report = { cycleResults, metrics: {} };
  for (const c of [...survivors, churner]) {
    const m = await clientMetrics(c);
    if (m) delete m.voiceTapEvents;
    report.metrics[c.tag] = m;
    for (const e of c.errors) failures.push(`${c.tag} page error: ${e}`);
    await closeClient(c);
  }
  return { report, failures };
}
