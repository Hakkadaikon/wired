// S3 voice-loss: the 4-client room through per-flow UDP proxies with random
// packet loss, chat running concurrently. Gates: the voice quality gates
// (knobs loosened per loss profile), zero chat loss (chat rides reliable
// streams -- retransmission must absorb the drops), and zero connection
// deaths. --loss-rate / --impair-seed make a run reproducible.

import { startUdpProxy } from "../lib/udpProxy.mjs";
import { summarizeVoiceTrace } from "../lib/voiceMetrics.mjs";
import { evaluateVoiceGates } from "../lib/voiceGates.mjs";
import { classifyMissingChat } from "../lib/chatLossVerdict.mjs";
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

async function deliveredChatIds(client) {
  return client.page.evaluate(() =>
    [...document.querySelectorAll('[data-testid="message"]')]
      .map((e) => e.textContent.match(/msg:[A-Za-z0-9]+:\d+/)?.[0])
      .filter(Boolean),
  );
}

export async function run({ pageUrl, server, arg, log }) {
  const lossRate = Number(arg("loss-rate", "0.01"));
  const seed = Number(arg("impair-seed", "1"));
  const messagesPerClient = Number(arg("messages", "15"));
  const gateOverrides = {
    // Voice rides datagrams over two lossy hops (publisher->hub,
    // hub->subscriber), so end-to-end loss compounds: 1-(1-p)^2 (5% -> 9.75%).
    // The 1.3x factor is relative sampling headroom above that expectation;
    // the +0.5pt absolute term covers per-pair binomial sampling variance at
    // small n (~1200 deliveries/run), where relative headroom alone is too
    // tight (1% loss: 2.59% relative bound vs ~0.4% sigma around a 1.99%
    // expectation -- a single unlucky run can exceed it). This gate measures
    // wire loss (seq gaps), not audible gaps: PLC repeats the last frame for
    // up to 2 consecutive lost frames before going silent, so it masks some
    // of this loss from the ear without changing the wire count.
    maxFrameLossRate: Math.max(0.005, (1 - (1 - lossRate) ** 2) * 1.3 + 0.005),
    maxInterArrivalP99Ms: Number(arg("max-inter-arrival-p99", "150")),
    minPlcCount: 1, // a lossy profile must actually exercise PLC
    maxPlcCount: Infinity, // concealment count is reported, not capped, under injected loss
  };
  const proxy = await startUdpProxy({
    listenBase: PROXY_BASE,
    upstreamPort: SERVER_PORT,
    flowCount: TAGS.length,
    profile: { lossRate, seed },
  });
  const clients = [];
  try {
    for (let i = 0; i < TAGS.length; i++) {
      log(`joining ${TAGS[i]} via lossy flow ${i} (loss ${lossRate})`);
      clients.push(
        await joinStabilityClient({
          pageUrl,
          serverUrl: `https://127.0.0.1:${proxy.port(i)}/`,
          certHash: server.certHash,
          participantId: TAGS[i],
        }),
      );
    }
    for (const c of clients) await waitFirstDecode(c, { timeoutMs: 25000 });
    log("room live; chatting under loss");

    const sentIds = [];
    for (let seq = 0; seq < messagesPerClient; seq++) {
      for (const c of clients) {
        const id = `msg:${c.tag}:${seq}`;
        await sendChat(c, id);
        sentIds.push({ id, sender: c.tag });
        await sleep(200);
      }
    }
    await sleep(10000); // settle: retransmissions must finish the job

    const failures = [];
    const tapEvents = {};
    const uniStreams = {};
    const outUniStreams = {};
    // Distinguish "still in flight" from "gone for good": scrape once after
    // the settle, and -- only if something is missing -- again after an
    // extra grace. A pair missing from BOTH scrapes is a real loss; a pair
    // that shows up late is a latency finding (report-only).
    const missingPairs = async () => {
      const out = [];
      for (const c of clients) {
        const got = new Set(await deliveredChatIds(c));
        for (const s of sentIds) {
          if (s.sender !== c.tag && !got.has(s.id)) out.push(`${s.id}->${c.tag}`);
        }
      }
      return out;
    };
    const missingAtSettle = await missingPairs();
    let missingFinal = missingAtSettle;
    if (missingAtSettle.length > 0) {
      log(`${missingAtSettle.length} chat deliveries still missing; extra 20s grace`);
      await sleep(20000);
      missingFinal = await missingPairs();
    }
    for (const c of clients) {
      const m = await clientMetrics(c);
      tapEvents[c.tag] = m?.voiceTapEvents ?? [];
      uniStreams[c.tag] = m?.wtUniStreams ?? [];
      outUniStreams[c.tag] = m?.wtOutUniStreams ?? [];
      const dead = (m?.wtEvents ?? []).filter((e) => e.closedAt !== null);
      if (dead.length > 0) {
        failures.push(`${c.tag}: connection died mid-run (${dead[0].closeInfo})`);
      }
      for (const e of c.errors) failures.push(`${c.tag} page error: ${e}`);
    }
    // Crossmatch each missing delivery against BOTH transport-level taps:
    // the SENDER's outgoing-uni-stream log (did the client's own bytes ever
    // leave, stabilityClient's wrapOutgoingUni) and the RECEIVER's incoming
    // log (did they ever arrive, wrapIncomingUni). classifyMissingChat's own
    // test list documents the three-way verdict and the id-matching edge
    // cases (chatLossVerdict.test.mjs).
    const missingTransport = {};
    for (const pair of missingFinal) {
      const [id, receiver] = pair.split("->");
      missingTransport[pair] = classifyMissingChat({
        id,
        receiver,
        outUniStreams,
        uniStreams,
      });
    }
    if (missingFinal.length > 0) {
      failures.push(
        `chat loss under packet loss: ${missingFinal.length} deliveries missing ` +
          `for good (${missingFinal.slice(0, 6).join(", ")})`,
      );
    }
    const chatMissing = missingFinal.length;
    const voiceTrace = summarizeVoiceTrace(tapEvents);
    failures.push(...evaluateVoiceGates(voiceTrace, gateOverrides));

    const report = {
      lossRate,
      seed,
      gateOverrides,
      chatMissing,
      chatMissingAtSettle: missingAtSettle.length,
      chatLateDelivered: missingAtSettle.length - missingFinal.length,
      missingTransport,
      // Raw transport taps, persisted so offline qlog forensics can align
      // the server's relay streams against what each receiver actually saw
      // at the WebTransport layer (heads carry the message ids).
      uniStreamTaps: uniStreams,
      outUniStreamTaps: outUniStreams,
      voiceTrace,
      proxyStats: proxy.stats(),
    };
    for (const c of clients) await closeClient(c);
    return { report, failures };
  } finally {
    proxy.close();
  }
}
