#!/usr/bin/env node
// CLI entry for the chat+voice load test (voiceLoadTest.mjs). Launches
// Chrome with a fake microphone device
// (--use-fake-device-for-media-stream/--use-fake-ui-for-media-stream) so
// getUserMedia succeeds headlessly and MoqtVoiceClient actually publishes
// Opus frames concurrently with chat traffic -- see run-load-test.mjs for
// the chat-only counterpart this mirrors.

import puppeteer from "puppeteer-core";
import { resolveChromeLaunch } from "./lib/chromeLaunch.mjs";
import { runChatVoiceLoadTest, MAX_CLIENTS } from "./lib/voiceLoadTest.mjs";

function arg(name, fallback) {
  const flag = `--${name}=`;
  const found = process.argv.find((a) => a.startsWith(flag));
  return found ? found.slice(flag.length) : fallback;
}

const certHash = arg("cert-hash", process.env.CERT_HASH ?? "");
const pageUrl = arg("url", "http://localhost:8091/");
const clientCount = Number(arg("clients", "2"));
const messagesPerClient = Number(arg("messages", "10"));
const sendIntervalMs = Number(arg("interval-ms", "800"));
const settleMs = Number(arg("settle-ms", "15000"));
const maxLossRate = Number(arg("max-loss-rate", "1"));
// Voice-frame loss gate over the per-seq trace (voiceMetrics.mjs): the relay
// retains busy rounds instead of dropping them, so steady-state voice loss
// should be ~0; 0.1% leaves room for join/teardown edges.
const maxVoiceLossRate = Number(arg("max-voice-loss-rate", "0.001"));

if (!certHash) {
  console.error(
    "missing --cert-hash=<sha256 fingerprint> (copy from the server's startup log)",
  );
  process.exit(2);
}
if (clientCount > MAX_CLIENTS) {
  console.error(`--clients=${clientCount} exceeds MAX_CLIENTS=${MAX_CLIENTS}`);
  process.exit(2);
}

const { executablePath, env } = resolveChromeLaunch();
const browser = await puppeteer.launch({
  executablePath,
  headless: "new",
  env,
  args: [
    "--no-sandbox",
    "--use-fake-device-for-media-stream",
    "--use-fake-ui-for-media-stream", // auto-grant the getUserMedia permission prompt
  ],
});

let result;
try {
  result = await runChatVoiceLoadTest({
    browser,
    pageUrl,
    certHash,
    clientCount,
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
  failures.push(`chat lossRate ${result.lossRate} > max ${maxLossRate}`);
}
{
  let received = 0;
  let lost = 0;
  for (const page of Object.values(result.voiceTrace ?? {})) {
    for (const sender of Object.values(page.perSender ?? {})) {
      received += sender.loss.received;
      lost += sender.loss.lost;
    }
  }
  const voiceLossRate = received + lost > 0 ? lost / (received + lost) : 0;
  if (voiceLossRate > maxVoiceLossRate) {
    failures.push(
      `voice lossRate ${voiceLossRate.toFixed(5)} (${lost}/${received + lost}) > max ${maxVoiceLossRate}`,
    );
  }
}
for (const [tag, errs] of Object.entries(result.pageErrors)) {
  if (errs.length > 0) failures.push(`client ${tag} had page errors: ${errs.join("; ")}`);
}

if (failures.length > 0) {
  console.error("FAIL:\n" + failures.map((f) => `  - ${f}`).join("\n"));
  process.exit(1);
}
console.log("PASS");
