#!/usr/bin/env node
// Measures how many simultaneous tabs a REAL deployment's wired_server
// actually accepts, against a REAL running server (--server-url,
// --cert-hash) -- not this repo's own local build. Use this when a report
// ("the 2nd person can never join") needs to be measured against the
// server's actual connection cap (WIRED_CONNTABLE_CAP), not just guessed at.
//
// Opens N tabs ONE AT A TIME (matching two real users opening the app one
// after another, not a burst), each waiting for its own "connected" status.
// Reports how many joined and which one (if any) never did.
//
//   node run-prod-conncheck.mjs \
//     --server-url=https://100.89.201.47:4433/ \
//     --cert-hash=86:d7:6e:d8:... \
//     --connections=4
//
// This is a MEASURE-AND-REPORT tool: it never mutates src/ and never
// touches screen-share/voice logic, only connection establishment.

import { arg } from "./lib/args.mjs";
import { launchProdBrowser, joinProd, closeProd } from "./lib/prodClient.mjs";

// Mirrors frontend/src/lib/moqtClient.ts's CANDIDATE_PARTICIPANT_IDS (the
// frontend's fixed 4-slot room; a 5th id has no UI button to click).
const PARTICIPANT_IDS = ["user1", "user2", "user3", "user4"];

const pageUrl = arg("page-url", "https://hakkadaikon.github.io/wired/moqt_chat/");
const serverUrl = arg("server-url", "");
const certHash = arg("cert-hash", "");
if (!serverUrl || !certHash) {
  console.error(
    "usage: node run-prod-conncheck.mjs --server-url=https://<host>:4433/ --cert-hash=<sha-256 fingerprint> [--connections=4]\n" +
      "  (docker logs <container> | grep fingerprint) to get --cert-hash from a running wired_server.",
  );
  process.exit(2);
}
const wanted = Math.min(Number(arg("connections", "4")), PARTICIPANT_IDS.length);

const clients = [];
let connected = 0;
let failedAt = null;
let browser;
try {
  browser = await launchProdBrowser();
  for (let i = 0; i < wanted; i++) {
    const id = PARTICIPANT_IDS[i];
    const startedAt = Date.now();
    try {
      const client = await joinProd(browser, { pageUrl, serverUrl, certHash, participantId: id });
      clients.push(client);
      connected++;
      console.error(`${id}: connected in ${Date.now() - startedAt}ms`);
    } catch (err) {
      failedAt = i + 1;
      console.error(`${id}: FAILED to connect (${Date.now() - startedAt}ms): ${err.message}`);
      break;
    }
  }
} finally {
  for (const c of clients) await closeProd(c);
  await browser?.close().catch(() => {});
}

console.log(JSON.stringify({ wanted, connected, failedAt }, null, 2));
if (failedAt !== null) {
  console.error(`FAIL: only ${connected}/${wanted} connections succeeded (stopped at connection #${failedAt})`);
  process.exit(1);
}
console.log(`PASS: all ${connected}/${wanted} connections succeeded`);
