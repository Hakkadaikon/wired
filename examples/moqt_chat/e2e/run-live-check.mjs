#!/usr/bin/env node
// `just e2e-live` (see ../justfile): real-browser check that the hub's
// clock-paced "movie" live track (wired_server --movie with a fragmented
// MP4) plays through an INDEPENDENT MOQT implementation -- Chrome's
// WebTransport + the frontend's own TS decoder + MSE -- rather than the SDK
// talking to itself. Starts wired_server and a static frontend, joins a
// headless-Chrome participant, waits for its <video data-testid="live"> to
// reach playable state, joins a second participant 5 s later and requires
// its first Group to be LATER than the first participant's (a late joiner
// starts at the clock's current Group, not the file's start), requires both
// videos to keep advancing, and finally greps the server's shutdown stats
// for live_sent > 0.
//
// Before running, kill any stale server (`pgrep -a wired_server`): the
// listener binds 4433 with SO_REUSEPORT, so a leftover wired_server from an
// earlier run shares the port and steals this run's handshake (same note as
// run-stability.sh).

import puppeteer from "puppeteer-core";
import { spawn, execSync } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { readFileSync, rmSync } from "node:fs";
import { resolveChromeLaunch } from "./lib/chromeLaunch.mjs";
import { startServer } from "./lib/serverControl.mjs";
import { arg } from "./lib/args.mjs";

const moviePath = arg("movie", "../../assets/movie-live.mp4");
const frontendPort = arg("frontend-port", "8091");
const logPath = arg("log", "/tmp/moqt-live-check.log");
const timeoutMs = Number(arg("timeout-ms", "30000"));

let server, frontend, browser;
const clients = []; // pushed before any await that can throw, so the
// finally block can report console errors of a client whose join failed
async function join(id) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  const c = { id, firstGroup: null, consoleErrors: [], page, ctx };
  clients.push(c);
  page.on("console", (m) => {
    if (m.type() === "error") c.consoleErrors.push(m.text());
  });
  page.on("pageerror", (e) => c.consoleErrors.push(String(e)));
  await page.goto(`http://localhost:${frontendPort}/`);
  await page.type('input[data-testid="certHash"]', server.certHash);
  await page.click(`[data-testid="participant-${id}"]`);
  await page.click('[data-testid="connect"]');
  await page.waitForFunction(
    () => {
      const v = document.querySelector('[data-testid="live"]');
      return v && v.readyState >= 3 && v.currentTime > 4;
    },
    { timeout: timeoutMs },
  );
  c.firstGroup = await page.$eval(
    '[data-testid="live"]',
    (v) => v.dataset.firstGroup,
  );
  return c;
}

const videoTime = (c) =>
  c.page.$eval('[data-testid="live"]', (v) => v.currentTime);

const summary = { ok: false, clients: [], liveSent: 0, errors: [] };
try {
  rmSync(logPath, { force: true }); // the live_sent grep must see THIS run only
  server = await startServer({
    binPath: "./wired_server",
    logPath,
    args: ["--movie", moviePath],
  });
  frontend = spawn(
    "python3",
    ["-m", "http.server", frontendPort, "--directory", "frontend/out"],
    { stdio: "ignore" },
  );
  await sleep(1000);

  const { executablePath, env } = resolveChromeLaunch();
  browser = await puppeteer.launch({
    executablePath,
    headless: "new",
    env,
    args: ["--no-sandbox", "--autoplay-policy=no-user-gesture-required"],
  });

  const user1 = await join("user1");
  await sleep(5000);
  const user2 = await join("user2");
  if (!(BigInt(user2.firstGroup) > BigInt(user1.firstGroup)))
    summary.errors.push(
      `late joiner did not start later: user1 first Group ${user1.firstGroup}, user2 first Group ${user2.firstGroup}`,
    );
  const t0 = await Promise.all([videoTime(user1), videoTime(user2)]);
  await sleep(3000);
  const t1 = await Promise.all([videoTime(user1), videoTime(user2)]);
  [user1, user2].forEach((c, i) => {
    c.advancedSec = Number((t1[i] - t0[i]).toFixed(2));
    if (c.advancedSec < 2)
      summary.errors.push(
        `${c.id}: playback advanced ${c.advancedSec}s over 3s (want >= 2s)`,
      );
  });
  await user1.ctx.close();
  await user2.ctx.close();
} catch (e) {
  summary.errors.push(String(e));
} finally {
  summary.clients = clients.map(({ page, ctx, ...r }) => r);
  try {
    if (browser) await browser.close();
  } catch (e) {
    summary.errors.push(`browser close: ${e}`);
  }
  if (frontend) frontend.kill();
  if (server) await server.stop();
  else
    try {
      // startServer can throw AFTER spawning (no fingerprint in time),
      // leaving a live process with no handle -- reap it by name.
      execSync("pkill -x wired_server");
    } catch {
      /* nothing was left running */
    }
}

if (server) {
  const m = readFileSync(logPath, "utf8").match(/live_sent=(\d+)/);
  summary.liveSent = m ? Number(m[1]) : 0;
  if (summary.liveSent <= 0)
    summary.errors.push(
      `server log has live_sent=${summary.liveSent} (want > 0); log: ${logPath}`,
    );
}
summary.ok = summary.errors.length === 0;
console.log(JSON.stringify(summary, null, 2));
process.exit(summary.ok ? 0 : 1);
