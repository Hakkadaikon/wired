// S13 screen-longrun: the full 4-client room, everyone sharing their
// (fake) screen while chat keeps flowing, through per-flow UDP proxies with
// light packet loss, for minutes -- reproduces a user report of a share
// that "stops after a while". Two suspects it tells apart: the sender's
// long-lived uni stream wedging on one write that never returns
// (moqtScreenClient.ts's write timeout is the fix under test), and the
// hub's per-connection uni-stream budget (WIRED_SRVLOOP_MAX_WT_UNI_STREAMS)
// starving a reopened stream. The hub's own send-path counters (qlog
// recovery:metrics_updated: wtsend_flow / wtwin_drop / streams_blocked,
// with --server-qlog=1) are reported per connection as evidence.
//
// Gates, per viewer per sender: p99 gap between decoded frames < 3 s,
// zero stalls (a gap of 3 s or more -- the tile's "Stalled" caption). Manual
// only, not in any `just` recipe:
//
//   just e2e-stability s13-screen-longrun --server-qlog=1
//   just e2e-stability s13-screen-longrun --talk-ms=60000 --loss-rate=0

import path from "node:path";
import { readFileSync } from "node:fs";
import { startUdpProxy } from "../lib/udpProxy.mjs";
import { screenGapStats } from "../lib/screenMetrics.mjs";
import { parseJsonSeq } from "../lib/qlogStreamForensics.mjs";
import { FAKE_DISPLAY_MEDIA_SCRIPT } from "../lib/screenShareFake.mjs";
import { joinStabilityClient, clientMetrics, closeClient } from "../lib/stabilityClient.mjs";

const PROXY_BASE = 24433;
const SERVER_PORT = 4433;
const TAGS = ["user1", "user2", "user3", "user4"];
const STALL_MS = 3000; // stallDetector.ts's SCREEN_STALL_MS
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

// Last recovery:metrics_updated per connection (group_id) from the hub's
// qlog, when --server-qlog=1 wrote one; the counters are cumulative.
function hubSendCounters(qlogPath) {
  let text;
  try {
    text = readFileSync(qlogPath, "utf8");
  } catch {
    return null;
  }
  const last = {};
  for (const r of parseJsonSeq(text)) {
    if (r.name !== "recovery:metrics_updated") continue;
    const { wtsend_ok, wtsend_busy, wtsend_flow, wtwin_drop, streams_blocked } = r.data ?? r;
    last[r.group_id] = { wtsend_ok, wtsend_busy, wtsend_flow, wtwin_drop, streams_blocked };
  }
  return last;
}

export async function run({ pageUrl, server, arg, log }) {
  const talkMs = Number(arg("talk-ms", "180000"));
  const chatIntervalMs = Number(arg("chat-interval-ms", "500"));
  const lossRate = Number(arg("loss-rate", "0.01"));
  const seed = Number(arg("impair-seed", "1"));
  const evidenceDir = arg(
    "evidence-dir",
    path.join(path.dirname(new URL(import.meta.url).pathname), "../../../../tasks/voice-stability/s13-screen-longrun"),
  );
  const proxy = await startUdpProxy({
    listenBase: PROXY_BASE,
    upstreamPort: SERVER_PORT,
    flowCount: TAGS.length,
    profile: { lossRate, seed },
  });
  const clients = [];
  try {
    for (let i = 0; i < TAGS.length; i++) {
      log(`joining ${TAGS[i]} via proxy flow ${i} (loss ${lossRate})`);
      clients.push(
        await joinStabilityClient({
          pageUrl,
          serverUrl: `https://127.0.0.1:${proxy.port(i)}/`,
          certHash: server.certHash,
          participantId: TAGS[i],
          initScripts: [FAKE_DISPLAY_MEDIA_SCRIPT],
        }),
      );
    }
    for (const c of clients) await c.page.click('[data-testid="screen-toggle"]');
    for (const c of clients) {
      await c.page.waitForFunction(
        (n) => (window.__wiredScreenTap ?? []).length >= n,
        { timeout: 30000 },
        TAGS.length - 1,
      );
    }
    log(`all 4 sharing; chatting for ${talkMs}ms`);

    const start = Date.now();
    let seq = 0;
    while (Date.now() - start < talkMs) {
      for (const c of clients) await sendChat(c, `msg:${c.tag}:${seq}`);
      seq++;
      await sleep(chatIntervalMs);
    }

    const failures = [];
    const gaps = {};
    const stalledTiles = {};
    for (const c of clients) {
      const entries = await c.page.evaluate(() => window.__wiredScreenTap ?? []);
      gaps[c.tag] = screenGapStats(entries, STALL_MS);
      stalledTiles[c.tag] = await c.page.evaluate(() =>
        [...document.querySelectorAll('[data-testid^="screen-stalled-"]')].map((e) => e.dataset.testid),
      );
      for (const sender of TAGS) {
        if (sender === c.tag) continue;
        const g = gaps[c.tag][sender];
        if (!g) {
          failures.push(`${c.tag}: never decoded a frame from ${sender}`);
          continue;
        }
        if (g.gapP99Ms !== null && g.gapP99Ms >= STALL_MS)
          failures.push(`${c.tag}<-${sender}: frame gap p99 ${g.gapP99Ms}ms (want < ${STALL_MS})`);
        if (g.stalls > 0) failures.push(`${c.tag}<-${sender}: ${g.stalls} stall(s) of ${STALL_MS}ms+`);
      }
      const m = await clientMetrics(c);
      const dead = (m?.wtEvents ?? []).filter((e) => e.closedAt !== null);
      if (dead.length > 0) failures.push(`${c.tag}: connection died mid-run (${dead[0].closeInfo})`);
      for (const e of c.errors) failures.push(`${c.tag} page error: ${e}`);
    }

    const report = {
      talkMs,
      chatIntervalMs,
      lossRate,
      seed,
      chatRounds: seq,
      gaps,
      stalledTiles,
      hubSendCounters: hubSendCounters(path.join(evidenceDir, "server.qlog")),
      proxyStats: proxy.stats(),
    };
    for (const c of clients) await closeClient(c);
    return { report, failures };
  } finally {
    proxy.close();
  }
}
