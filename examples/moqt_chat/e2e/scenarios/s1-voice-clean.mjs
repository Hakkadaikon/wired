// S1 voice-clean-4: the full 4-client room on a clean network, all voice
// quality gates enforced (voiceGates.mjs). Clients connect through
// pass-through proxy flows, so this run doubles as the proxy's own
// transparency check: the gates must hold THROUGH the proxy before any
// impairment profile's numbers mean anything.

import { startUdpProxy } from "../lib/udpProxy.mjs";
import { summarizeVoiceTrace } from "../lib/voiceMetrics.mjs";
import { evaluateVoiceGates } from "../lib/voiceGates.mjs";
import {
  joinStabilityClient,
  waitFirstDecode,
  clientMetrics,
  closeClient,
} from "../lib/stabilityClient.mjs";

const PROXY_BASE = 24433;
const SERVER_PORT = 4433;
const TAGS = ["user1", "user2", "user3", "user4"];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function run({ pageUrl, server, arg, log }) {
  const talkMs = Number(arg("talk-ms", "30000"));
  const proxy = await startUdpProxy({
    listenBase: PROXY_BASE,
    upstreamPort: SERVER_PORT,
    flowCount: TAGS.length,
  });
  const clients = [];
  try {
    for (let i = 0; i < TAGS.length; i++) {
      log(`joining ${TAGS[i]} via proxy flow ${i}`);
      clients.push(
        await joinStabilityClient({
          pageUrl,
          serverUrl: `https://127.0.0.1:${proxy.port(i)}/`,
          certHash: server.certHash,
          participantId: TAGS[i],
        }),
      );
    }
    for (const c of clients) await waitFirstDecode(c);
    log(`room live (4 clients); talking for ${talkMs}ms`);
    await sleep(talkMs);

    const tapEvents = {};
    const failures = [];
    for (const c of clients) {
      const m = await clientMetrics(c);
      tapEvents[c.tag] = m?.voiceTapEvents ?? [];
      for (const e of c.errors) failures.push(`${c.tag} page error: ${e}`);
    }
    const voiceTrace = summarizeVoiceTrace(tapEvents);
    failures.push(...evaluateVoiceGates(voiceTrace));

    const report = { voiceTrace, proxyStats: proxy.stats() };
    for (const c of clients) await closeClient(c);
    return { report, failures };
  } finally {
    proxy.close();
  }
}
