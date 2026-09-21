#!/usr/bin/env node
// Measures screen-share delivery against a REAL deployment: the production
// frontend at https://hakkadaikon.github.io/wired/moqt_chat/ (or whatever
// --page-url names) talking to a REAL wired_server the operator has
// already started (--server-url, --cert-hash) -- not this repo's own
// local build. Use this when a report ("screen share sometimes doesn't
// reach the other side, even after a hard reload") needs to be measured
// against the actual thing users hit, not a synthetic loopback.
//
// Prerequisites (the operator does these, this script does NOT start or
// stop the server):
//   1. wired_server already running and reachable from this machine
//      (docker ps / docker logs to find its cert fingerprint).
//   2. This machine can reach --server-url over UDP (same LAN/Tailscale/
//      public IP the real users use).
//
// What it does, two headless Chrome tabs (both against the SAME frontend
// URL and SAME server, exactly like two real users):
//   1. user_a and user_b join.
//   2. user_a shares a fake canvas screen (unless --real-screen, which
//      leaves getDisplayMedia untouched -- only useful non-headless with
//      an actual screen to pick, see run-prod-screenshare-check.mjs
//      --help). user_b must decode frames within --resume-max-ms.
//   3. user_a stops sharing.
//   4. user_b does a hard "leave and rejoin" (repro's exact report: a
//      reload/rejoin, not just a page sitting idle) against the now-idle
//      (published, no data) screen track.
//   5. user_a shares again. Both user_b (rejoined) and any --extra-cycles
//      repeats of steps 3-5 must each independently decode frames within
//      --resume-max-ms, with the hub's own relay-stream count staying
//      exactly 1 per re-share (measured via user_b's incoming uni-stream
//      log) -- more than 1 means a stale stream from a previous cycle
//      leaked (see moqtrun_track_reset_stale_relays in the hub).
//
// This is a MEASURE-AND-REPORT tool: it never mutates src/. Pair it with
// `git bisect`/manual before-after commits when you need to attribute a
// regression to a specific change, the way s14-screen-rejoin.mjs's
// before/after evidence was produced for the local build.
//
//   node run-prod-screenshare-check.mjs \
//     --server-url=https://100.89.201.47:4433/ \
//     --cert-hash=86:d7:6e:d8:...
//
// Evidence (report.json, gate.txt) lands under --evidence-dir (default
// tasks/voice-stability/prod-screenshare/<timestamp>/, matching this
// repo's other e2e evidence layout) -- but see this repo's own note:
// tasks/ is gitignored, so evidence survives locally only.

import path from "node:path";
import { mkdirSync, writeFileSync } from "node:fs";
import { arg } from "./lib/args.mjs";
import {
  launchProdBrowser,
  joinProd,
  leaveProd,
  toggleScreenShare,
  screenTapCount,
  waitScreenFrames,
  closeProd,
} from "./lib/prodClient.mjs";

const pageUrl = arg("page-url", "https://hakkadaikon.github.io/wired/moqt_chat/");
const serverUrl = arg("server-url", "");
const certHash = arg("cert-hash", "");
if (!serverUrl || !certHash) {
  console.error(
    "usage: node run-prod-screenshare-check.mjs --server-url=https://<host>:4433/ --cert-hash=<sha-256 fingerprint>\n" +
      "  (docker logs <container> | grep fingerprint) to get --cert-hash from a running wired_server.",
  );
  process.exit(2);
}
const resumeMaxMs = Number(arg("resume-max-ms", "5000"));
const idleMs = Number(arg("idle-ms", "5000"));
const extraCycles = Number(arg("extra-cycles", "1"));
const useFakeScreen = !process.argv.includes("--real-screen");
const evidenceDir = arg(
  "evidence-dir",
  path.join(
    path.dirname(new URL(import.meta.url).pathname),
    "../../../tasks/voice-stability/prod-screenshare",
    new Date().toISOString().replace(/[:.]/g, "-"),
  ),
);
mkdirSync(evidenceDir, { recursive: true });

const sawChat = async (client, text, timeoutMs) => {
  try {
    await client.page.waitForFunction(
      (t) => document.querySelector('[data-testid="messages"]')?.textContent?.includes(t),
      { timeout: timeoutMs },
      text,
    );
    return true;
  } catch {
    return false;
  }
};

const sendChat = async (client, text) => {
  await client.page.evaluate((t) => {
    const input = document.querySelector('input[data-testid="text"]');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
    setter.call(input, t);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  }, text);
};

// Incoming uni streams carrying screen-sized payloads (chat's one-shot
// uploads are a few dozen bytes) opened at/after sinceMs.
async function screenStreamsSince(client, sinceMs) {
  const streams = await client.page.evaluate(() => window.__wtUniStreams ?? []);
  return streams.filter((s) => s.bytes >= 1000 && s.openedAt >= sinceMs).length;
}

const failures = [];
const allErrors = []; // {who, text} across every page this run ever opened, closed ones included
const report = { pageUrl, serverUrl, resumeMaxMs, idleMs, extraCycles, cycles: [] };
let browser;
try {
  browser = await launchProdBrowser();
  const fakeScreen = useFakeScreen ? { width: 1280, height: 720 } : undefined;
  const join = (id) => joinProd(browser, { pageUrl, serverUrl, certHash, participantId: id, fakeScreen });
  const collect = (client) => allErrors.push(...client.errors.map((text) => ({ who: client.id, text })));

  const userA = await join("user1");
  let userB = await join("user2");
  console.error("both joined; user1 sharing first frame");

  await toggleScreenShare(userA);
  const first = { cycle: 0, resumeMs: await waitScreenFrames(userB, "user1", 3, resumeMaxMs + 15000) };
  if (first.resumeMs === null) failures.push("cycle 0: user2 never decoded user1's first share");
  else if (first.resumeMs > resumeMaxMs)
    failures.push(`cycle 0: user2 resumed only after ${first.resumeMs}ms > ${resumeMaxMs}ms`);
  report.cycles.push(first);

  for (let cycle = 1; cycle <= extraCycles; cycle++) {
    console.error(`cycle ${cycle}: user1 stops sharing, user2 leaves+rejoins, idles ${idleMs}ms, user1 re-shares`);
    await toggleScreenShare(userA); // stop
    await leaveProd(userB);
    collect(userB);
    await closeProd(userB);
    userB = await join("user2"); // fresh tab, exactly a real "leave and reopen"
    await new Promise((r) => setTimeout(r, idleMs));

    const reshareAt = Date.now();
    await toggleScreenShare(userA); // share again
    const resumeMs = await waitScreenFrames(userB, "user1", 3, resumeMaxMs + 15000);
    if (resumeMs === null) failures.push(`cycle ${cycle}: rejoined user2 never decoded the re-share`);
    else if (resumeMs > resumeMaxMs)
      failures.push(`cycle ${cycle}: rejoined user2 resumed only after ${resumeMs}ms > ${resumeMaxMs}ms`);

    await new Promise((r) => setTimeout(r, 2000)); // let every stream the hub will open, open
    const streams = await screenStreamsSince(userB, reshareAt);
    if (streams !== 1)
      failures.push(`cycle ${cycle}: user2 received ${streams} screen streams for one re-share (want 1)`);

    await sendChat(userB, `msg:user2:cycle${cycle}`);
    if (!(await sawChat(userA, `msg:user2:cycle${cycle}`, 5000)))
      failures.push(`cycle ${cycle}: user1 never saw rejoined user2's chat message`);

    report.cycles.push({ cycle, resumeMs, streams });
  }

  collect(userA);
  collect(userB);
  for (const { who, text } of allErrors) failures.push(`${who} page error: ${text}`);
  report.finalTapCountUserB = await screenTapCount(userB, "user1");
} catch (err) {
  failures.push(`scenario crashed: ${err.stack ?? err}`);
} finally {
  await browser?.close().catch(() => {});
}

writeFileSync(path.join(evidenceDir, "report.json"), JSON.stringify(report, null, 2));
const verdict = failures.length === 0 ? "PASS" : "FAIL:\n" + failures.map((f) => `  - ${f}`).join("\n");
writeFileSync(path.join(evidenceDir, "gate.txt"), verdict + "\n");
console.log(JSON.stringify(report, null, 2));
console.error(`evidence: ${evidenceDir}`);
if (failures.length > 0) {
  console.error(verdict);
  process.exit(1);
}
console.log("PASS");
