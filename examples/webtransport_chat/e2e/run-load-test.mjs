#!/usr/bin/env node
// CLI entry: `just e2e-load` (see ../justfile) wires FP/PORT and calls this.
// Prints a JSON report and exits non-zero if loss/latency exceed thresholds,
// so it composes as a CI-style gate, not just an interactive tool.

import puppeteer from "puppeteer-core";
import { resolveChromeLaunch } from "./lib/chromeLaunch.mjs";
import { runChatLoadTest } from "./lib/loadTest.mjs";

function arg(name, fallback) {
  const flag = `--${name}=`;
  const found = process.argv.find((a) => a.startsWith(flag));
  return found ? found.slice(flag.length) : fallback;
}

const certHash = arg("cert-hash", process.env.CERT_HASH ?? "");
const pageUrl = arg("url", "http://localhost:8080/");
const clientCount = Number(arg("clients", "3"));
const room = arg("room", "Fox");
const messagesPerClient = Number(arg("messages", "5"));
const sendIntervalMs = Number(arg("interval-ms", "800"));
// 15s, not a smaller "should be enough" guess: measured empirically (see
// tasks/webtransport-chat-scaling/findings.md) that a shorter settle window
// on this sandbox reports false loss on the LAST few messages of a run --
// they were still in flight/rendering when grading ran, not actually lost.
const settleMs = Number(arg("settle-ms", "15000"));
const maxLossRate = Number(arg("max-loss-rate", "1")); // 1 = gate disabled by default
const maxP95Ms = Number(arg("max-p95-ms", Infinity));

if (!certHash) {
  console.error(
    "missing --cert-hash=<sha256 fingerprint> (copy from the server's startup log)",
  );
  process.exit(2);
}

const { executablePath, env } = resolveChromeLaunch();
const browser = await puppeteer.launch({
  executablePath,
  headless: "new",
  env,
  args: [
    "--use-fake-ui-for-media-stream",
    "--use-fake-device-for-media-stream",
    "--autoplay-policy=no-user-gesture-required",
    "--no-sandbox",
  ],
});

let result;
try {
  result = await runChatLoadTest({
    browser,
    pageUrl,
    certHash,
    clientCount,
    room,
    messagesPerClient,
    sendIntervalMs,
    settleMs,
  });
} finally {
  await browser.close();
}

console.log(JSON.stringify(result, null, 2));

const failures = [];
if (result.lossRate > maxLossRate) {
  failures.push(`lossRate ${result.lossRate} > max ${maxLossRate}`);
}
if (result.p95Ms !== null && result.p95Ms > maxP95Ms) {
  failures.push(`p95Ms ${result.p95Ms} > max ${maxP95Ms}`);
}
for (const [tag, errs] of Object.entries(result.pageErrors)) {
  if (errs.length > 0) failures.push(`client ${tag} had page errors: ${errs.join("; ")}`);
}

if (failures.length > 0) {
  console.error("FAIL:\n" + failures.map((f) => `  - ${f}`).join("\n"));
  process.exit(1);
}
console.log("PASS");
