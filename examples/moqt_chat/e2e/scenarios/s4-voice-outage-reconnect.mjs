// S4 voice-outage-reconnect: 3 voice clients, each through its own UDP
// proxy flow. One client suffers a burst outage (its packets dropped both
// ways), crashes during it (browser SIGKILL -- the close can never reach
// the server), and rejoins the moment the outage lifts. Gates: the two
// survivors keep decoding each other throughout, and the rejoin is decoding
// audio again within the budget.

import { startUdpProxy } from "../lib/udpProxy.mjs";
import {
  joinStabilityClient,
  waitFirstDecode,
  clientMetrics,
  crashClient,
  closeClient,
} from "../lib/stabilityClient.mjs";

const PROXY_BASE = 24433;
const SERVER_PORT = 4433;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function run({ pageUrl, server, arg, log }) {
  const outageMs = Number(arg("outage-ms", "3000"));
  const rejoinMaxMs = Number(arg("rejoin-max-ms", "5000"));
  const failures = [];
  const proxy = await startUdpProxy({
    listenBase: PROXY_BASE,
    upstreamPort: SERVER_PORT,
    flowCount: 4, // flow 3 is the rejoin's fresh flow
  });
  const opts = (tag, flow) => ({
    pageUrl,
    serverUrl: `https://127.0.0.1:${proxy.port(flow)}/`,
    certHash: server.certHash,
    participantId: tag,
  });

  const survivors = [];
  try {
    for (const [i, tag] of [["0", "user1"], ["1", "user2"]].map(([f, t]) => [Number(f), t])) {
      log(`joining ${tag} via proxy flow ${i}`);
      survivors.push(await joinStabilityClient(opts(tag, i)));
    }
    let victim = await joinStabilityClient(opts("user3", 2));
    for (const c of [...survivors, victim]) await waitFirstDecode(c);
    log("room live; starting outage on user3's flow");

    const before = await Promise.all(survivors.map((c) => clientMetrics(c)));
    proxy.outage(2, outageMs);
    await sleep(1000);
    log("crashing user3 mid-outage");
    await crashClient(victim);
    await sleep(outageMs); // let the outage window fully lapse
    log("outage over; user3 rejoins immediately on a fresh flow");
    const t0 = Date.now();
    victim = await joinStabilityClient(opts("user3", 3));
    let rejoinMs = null;
    try {
      await waitFirstDecode(victim, { timeoutMs: rejoinMaxMs + 10000 });
      rejoinMs = Date.now() - t0;
    } catch {
      failures.push("rejoined user3 never decoded audio");
    }
    if (rejoinMs !== null && rejoinMs > rejoinMaxMs) {
      failures.push(`rejoin ${rejoinMs}ms > ${rejoinMaxMs}ms`);
    }
    await sleep(2000);
    const after = await Promise.all(survivors.map((c) => clientMetrics(c)));
    for (let i = 0; i < survivors.length; i++) {
      if (after[i].decodedFrameCount <= before[i].decodedFrameCount) {
        failures.push(`survivor ${survivors[i].tag} stopped decoding across the outage`);
      }
    }

    const report = { rejoinMs, proxyStats: proxy.stats(), metrics: {} };
    for (const c of [...survivors, victim]) {
      const m = await clientMetrics(c);
      if (m) delete m.voiceTapEvents;
      report.metrics[c.tag] = m;
      for (const e of c.errors) failures.push(`${c.tag} page error: ${e}`);
      await closeClient(c);
    }
    return { report, failures };
  } finally {
    proxy.close();
  }
}
