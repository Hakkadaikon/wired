#!/usr/bin/env node
// `just e2e-movie` (see ../justfile): real-browser check that the hub's
// "movie" track (wired_server --movie, src/app/moqt/run/moqtrun.h's
// wired_moqt_publish_blob) arrives intact through an INDEPENDENT MOQT
// implementation -- Chrome's WebTransport + the frontend's own TS decoder --
// rather than the SDK talking to itself. Starts wired_server --movie and a
// static frontend server, joins headless-Chrome participants, waits for each
// one's <video data-testid="movie">, and compares the received blob's SHA-256
// against the file on disk. Two clients join at once (each must get its own
// copy), one leaves and a third joins (the server's per-session staging must
// be released), then everyone leaves and the first id rejoins.

import puppeteer from "puppeteer-core";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolveChromeLaunch } from "./lib/chromeLaunch.mjs";
import { startServer } from "./lib/serverControl.mjs";
import { arg } from "./lib/args.mjs";

const moviePath = arg("movie", "../../assets/movie.mp4");
const frontendPort = arg("frontend-port", "8091");
const logPath = arg("log", "/tmp/moqt-movie-check.log");
const timeoutMs = Number(arg("timeout-ms", "60000"));

const want = createHash("sha256").update(readFileSync(moviePath)).digest("hex");
const server = await startServer({
  binPath: "./wired_server",
  logPath,
  args: ["--movie", moviePath],
});
const frontend = spawn(
  "python3",
  ["-m", "http.server", frontendPort, "--directory", "frontend/out"],
  { stdio: "ignore" },
);
await sleep(1000);

const { executablePath, env } = resolveChromeLaunch();
const browser = await puppeteer.launch({
  executablePath,
  headless: "new",
  env,
  args: ["--no-sandbox"],
});

async function join(id) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  await page.goto(`http://localhost:${frontendPort}/`);
  await page.type('input[data-testid="certHash"]', server.certHash);
  await page.click(`[data-testid="participant-${id}"]`);
  const t0 = Date.now();
  await page.click('[data-testid="connect"]');
  await page.waitForSelector('[data-testid="movie"]', { timeout: timeoutMs });
  const got = await page.evaluate(async () => {
    const src = document.querySelector('[data-testid="movie"]').src;
    const buf = await (await fetch(src)).arrayBuffer();
    const digest = await crypto.subtle.digest("SHA-256", buf);
    const sha = [...new Uint8Array(digest)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    return { len: buf.byteLength, sha };
  });
  return { id, ms: Date.now() - t0, len: got.len, ok: got.sha === want, ctx };
}

const results = [];
try {
  const [a, b] = await Promise.all([join("user1"), join("user2")]);
  results.push(a, b);
  await a.ctx.close();
  await sleep(1500);
  const c = await join("user3");
  results.push(c);
  await b.ctx.close();
  await c.ctx.close();
  await sleep(1500);
  const d = await join("user1");
  results.push(d);
  await d.ctx.close();
} finally {
  console.log(JSON.stringify(results.map(({ ctx, ...r }) => r), null, 2));
  await browser.close();
  frontend.kill();
  await server.stop();
}

const ok = results.length === 4 && results.every((r) => r.ok);
if (!ok) console.error("FAIL: a client received a movie that does not match the file");
process.exit(ok ? 0 : 1);
