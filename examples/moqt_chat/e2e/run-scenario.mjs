#!/usr/bin/env node
// Stability-scenario runner: loads e2e/scenarios/<id>.mjs, hands it a live
// browser + a controllable server (kill/restart hooks -- serverControl.mjs),
// grades the scenario's own failure list, and drops evidence
// (report.json / gate.txt / server.log) under tasks/voice-stability/<id>/.
// Run through run-stability.sh (or `just e2e-stability <id>`), which owns the
// static frontend and the Chrome pin.

import path from "node:path";
import { mkdirSync, readdirSync, writeFileSync } from "node:fs";
import puppeteer from "puppeteer-core";
import { resolveChromeLaunch } from "./lib/chromeLaunch.mjs";
import { startServer } from "./lib/serverControl.mjs";

const e2eDir = path.dirname(new URL(import.meta.url).pathname);
const scenariosDir = path.join(e2eDir, "scenarios");

function arg(name, fallback) {
  const flag = `--${name}=`;
  const found = process.argv.find((a) => a.startsWith(flag));
  return found ? found.slice(flag.length) : fallback;
}

const scenarioId = arg("scenario", "");
if (!scenarioId) {
  const available = readdirSync(scenariosDir)
    .filter((f) => f.endsWith(".mjs"))
    .map((f) => f.replace(/\.mjs$/, ""));
  console.error("missing --scenario=<id>; available: " + available.join(", "));
  process.exit(2);
}

const mod = await import(path.join(scenariosDir, `${scenarioId}.mjs`));
const evidenceDir = arg(
  "evidence-dir",
  path.join(e2eDir, "../../../tasks/voice-stability", scenarioId),
);
mkdirSync(evidenceDir, { recursive: true });

// --server-qlog=1 turns on the SDK's qlog stream (per-second
// recovery:metrics_updated records with cwnd/srtt/inflight and the WT
// send-path stall counters -- srvrun_qlog_metrics), landing next to the
// other evidence. Off by default: the extra write per packet costs a
// little and most scenarios only need the shutdown stats line.
const serverArgs =
  arg("server-qlog", "") !== ""
    ? ["--qlog", path.join(evidenceDir, "server.qlog")]
    : [];
// --server-cpu-quota=N starves the SERVER alone to N% of one core (systemd
// user scope) -- the resource-exhaustion reproduction knob: the relay's
// drop counters (stat_relay_drop / stat_open_drop) never fire on an
// unconstrained host, where whole-host contention starves the CLIENTS
// first and the server's send path stays clean (see the s10 qlog runs).
const cpuQuota = arg("server-cpu-quota", "");
const serverWrap = cpuQuota
  ? ["systemd-run", "--user", "--scope", "-q", "-p", `CPUQuota=${cpuQuota}%`]
  : undefined;
const server = await startServer({
  binPath: path.join(e2eDir, "..", "wired_server"),
  logPath: path.join(evidenceDir, "server.log"),
  args: serverArgs,
  wrap: serverWrap,
});

const { executablePath, env } = resolveChromeLaunch();
const browser = await puppeteer.launch({
  executablePath,
  headless: "new",
  env,
  args: [
    "--no-sandbox",
    "--use-fake-device-for-media-stream",
    "--use-fake-ui-for-media-stream",
  ],
});

let outcome;
try {
  outcome = await mod.run({
    browser,
    pageUrl: arg("url", "http://localhost:8093/"),
    server,
    arg,
    log: (msg) => console.error(`[${scenarioId}] ${msg}`),
  });
} catch (err) {
  // A scenario crash is still a red run: record it as a gate failure so the
  // evidence directory always ends up with a verdict.
  outcome = { report: { crashed: String(err?.stack ?? err) }, failures: [`scenario crashed: ${err}`] };
} finally {
  await browser.close().catch(() => {});
  await server.stop().catch(() => {});
}

const { report, failures } = outcome;
writeFileSync(path.join(evidenceDir, "report.json"), JSON.stringify(report, null, 2));
const verdict = failures.length === 0 ? "PASS" : "FAIL:\n" + failures.map((f) => `  - ${f}`).join("\n");
writeFileSync(path.join(evidenceDir, "gate.txt"), verdict + "\n");

console.log(JSON.stringify(report, null, 2));
if (failures.length > 0) {
  console.error(verdict);
  process.exit(1);
}
console.log("PASS");
