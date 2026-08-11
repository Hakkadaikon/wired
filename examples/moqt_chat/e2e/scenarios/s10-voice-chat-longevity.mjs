// S10 voice-chat-longevity: the full 4-client room, talking for >60s while
// chat messages keep flowing concurrently -- reproduces a user report of
// voice cutting out after about a minute (server-side shutdown log showed
// stat_relay_drop/stat_open_drop far outweighing stat_relay_sent). s1 alone
// (voice, no chat) stays clean even past 60s; this scenario adds chat's own
// one-shot uni streams (moqtrun's send_uni path) concurrently with voice, on
// the theory that BOTH share the same QUIC-layer server-initiated uni stream
// budget (srvrun.c's wt_uni_opened / peer's MAX_STREAMS(uni)) and together
// exhaust it well before either alone would.

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

async function sendChat(client, id) {
  await client.page.evaluate((text) => {
    const input = document.querySelector('input[data-testid="text"]');
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      "value",
    ).set;
    setter.call(input, text);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  }, id);
}

export async function run({ pageUrl, server, arg, log }) {
  const talkMs = Number(arg("talk-ms", "75000"));
  const chatIntervalMs = Number(arg("chat-interval-ms", "500"));
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
    log(`room live (4 clients); talking + chatting for ${talkMs}ms`);

    const start = Date.now();
    let seq = 0;
    while (Date.now() - start < talkMs) {
      for (const c of clients) {
        await sendChat(c, `msg:${c.tag}:${seq}`);
      }
      seq++;
      await sleep(chatIntervalMs);
    }

    const tapEvents = {};
    const failures = [];
    for (const c of clients) {
      const m = await clientMetrics(c);
      tapEvents[c.tag] = m?.voiceTapEvents ?? [];
      const dead = (m?.wtEvents ?? []).filter((e) => e.closedAt !== null);
      if (dead.length > 0) {
        failures.push(`${c.tag}: connection died mid-run (${dead[0].closeInfo})`);
      }
      for (const e of c.errors) failures.push(`${c.tag} page error: ${e}`);
    }
    const voiceTrace = summarizeVoiceTrace(tapEvents);
    failures.push(...evaluateVoiceGates(voiceTrace));

    const report = { talkMs, chatIntervalMs, chatRounds: seq, voiceTrace, proxyStats: proxy.stats() };
    for (const c of clients) await closeClient(c);
    return { report, failures };
  } finally {
    proxy.close();
  }
}
