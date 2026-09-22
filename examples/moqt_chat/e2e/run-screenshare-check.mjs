#!/usr/bin/env node
// `just e2e-screen` (see ../justfile): real-browser check that screen-share
// frames captured by one participant (VP8 encode -> MOQT Objects over a
// dedicated uni stream, see screenSharePipeline.ts) arrive, reassemble, and
// decode on another participant's INDEPENDENT MOQT stack -- Chrome's
// WebTransport + the frontend's own TS decoder -- rather than the SDK
// talking to itself.
//
// Headless Chrome has no real screen to share, so navigator.mediaDevices.
// getDisplayMedia is replaced (page.evaluateOnNewDocument, injected before
// the app's own scripts run -- same technique as stabilityClient.mjs/
// voiceLoadTest.mjs's AudioDecoder wrapping) with a fake that returns an
// offscreen <canvas>.captureStream() drawing a moving clock. The receive
// side is verified via window.__wiredScreenTap (screenTap.ts), pushed once
// per decoded frame by useMoqtChat.ts's onFrame handler.
//
// Two scenarios:
//   default (2 participants): sharer + viewer, asserts frames arrive with
//     plausible dimensions.
//   --load (4 participants): all four share simultaneously + one chat
//     message, to observe whether WIRED_SRVLOOP_MAX_WT_UNI_STREAMS=6
//     (chat+audio+screen per participant = up to 3 long-lived uni streams
//     each, 12 total across 4 participants) holds up. This does not fix
//     the constant if insufficient -- see task-9-brief.md's 対象外 section
//     -- only reports what happens.
//   --portrait (2 participants): the fake screen is 720x1280 (9:16), and
//     the viewer's decoded frames must keep that aspect -- getDisplayMedia's
//     size is only an ideal, so an app that encodes at a fixed 16:9 shows
//     up here as frames of the wrong shape.
//
// Before running, kill any stale server (`pgrep -a wired_server`): the
// listener binds 4433 with SO_REUSEPORT, so a leftover wired_server from an
// earlier run shares the port and steals this run's handshake.

import puppeteer from "puppeteer-core";
import { spawn, execSync } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { resolveChromeLaunch } from "./lib/chromeLaunch.mjs";
import { startServer } from "./lib/serverControl.mjs";
import { arg } from "./lib/args.mjs";
import { fakeDisplayMediaScript } from "./lib/screenShareFake.mjs";
import { screenGapStats } from "./lib/screenMetrics.mjs";

const frontendPort = arg("frontend-port", "8092");
const logPath = arg("log", "/tmp/moqt-screenshare-check.log");
const timeoutMs = Number(arg("timeout-ms", "30000"));
const minFrames = Number(arg("min-frames", "3"));
const loadMode = process.argv.includes("--load");
const portraitMode = process.argv.includes("--portrait");
const participantIds = loadMode ? ["user1", "user2", "user3", "user4"] : ["user1", "user2"];
const fakeScreen = portraitMode ? { width: 720, height: 1280 } : { width: 1280, height: 720 };
const fakeScript = fakeDisplayMediaScript(fakeScreen);

let server, frontend, browser;
const clients = [];
async function join(id) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  const c = { id, consoleErrors: [], page, ctx };
  clients.push(c);
  page.on("console", (m) => {
    if (m.type() === "error") c.consoleErrors.push(m.text());
  });
  page.on("pageerror", (e) => c.consoleErrors.push(String(e)));
  await page.evaluateOnNewDocument(fakeScript);
  await page.goto(`http://localhost:${frontendPort}/`);
  await page.type('input[data-testid="certHash"]', server.certHash);
  await page.click(`[data-testid="participant-${id}"]`);
  await page.click('[data-testid="connect"]');
  await page.waitForFunction(
    () => document.querySelector('[data-testid="status"]')?.getAttribute("data-status") === "connected",
    { timeout: timeoutMs },
  );
  return c;
}

const startSharing = (c) => c.page.click('[data-testid="screen-toggle"]');

const tapEntries = (c) => c.page.evaluate(() => window.__wiredScreenTap ?? []);

// Fraction of non-near-black pixels in a tile canvas. A tap count alone
// proves decode succeeded but not that anything actually got DRAWN -- a
// real regression shipped where the sharer's own preview canvas stayed
// fully black because nothing ever called drawImage into it, while every
// other signal (build, unit tests, this file's tap-based checks) stayed
// green. This is the check that would have caught it.
const nonBlackFraction = (c, testid) =>
  c.page.evaluate((tid) => {
    const canvas = document.querySelector(`[data-testid="${tid}"]`);
    if (!canvas) return null;
    const ctx = canvas.getContext("2d");
    const { data } = ctx.getImageData(0, 0, canvas.width, canvas.height);
    let nonBlack = 0;
    for (let i = 0; i < data.length; i += 4) {
      if (data[i] > 8 || data[i + 1] > 8 || data[i + 2] > 8) nonBlack++;
    }
    return nonBlack / (data.length / 4);
  }, testid);

const summary = {
  ok: false,
  mode: loadMode ? "load-4way" : portraitMode ? "2-participant-portrait" : "2-participant",
  fakeScreen,
  clients: [],
  errors: [],
};
try {
  server = await startServer({ binPath: "./wired_server", logPath, args: [] });
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
    args: ["--no-sandbox", "--autoplay-policy=no-user-gesture-required", "--use-fake-ui-for-media-stream"],
  });

  const participants = [];
  for (const id of participantIds) participants.push(await join(id));

  for (const c of participants) await startSharing(c);
  await sleep(500);

  // Every sharer's own outgoing-preview tile must actually have pixels
  // drawn into it, not just exist in the DOM as a black rectangle.
  for (const c of participants) {
    const frac = await nonBlackFraction(c, "screen-tile-own");
    if (frac === null) summary.errors.push(`${c.id}: screen-tile-own canvas not found`);
    else if (frac < 0.5)
      summary.errors.push(`${c.id}: screen-tile-own canvas is ${(frac * 100).toFixed(0)}% non-black (want >=50%, own preview looks blank)`);
  }

  if (loadMode) {
    await participants[0].page.type('input[data-testid="text"]', "hello from load scenario");
    await participants[0].page.keyboard.press("Enter");
  }

  // Every participant should see every OTHER sharer's frames arrive.
  for (const viewer of participants) {
    try {
      await viewer.page.waitForFunction(
        (n) => window.__wiredScreenTap && window.__wiredScreenTap.length >= n,
        { timeout: timeoutMs },
        minFrames,
      );
    } catch (e) {
      summary.errors.push(`${viewer.id}: did not accumulate ${minFrames} tap entries: ${e}`);
    }
    const entries = await tapEntries(viewer);
    const bad = entries.filter((e) => e.width < 100 || e.height < 100);
    if (bad.length > 0)
      summary.errors.push(`${viewer.id}: ${bad.length} tap entries with implausible dimensions`);
    // The decoded frames' aspect must be the shared screen's own, within
    // the rounding a codec's macroblock alignment can add.
    const wantAspect = fakeScreen.width / fakeScreen.height;
    const skewed = entries.filter((e) => Math.abs(e.width / e.height - wantAspect) > 0.02);
    if (skewed.length > 0)
      summary.errors.push(
        `${viewer.id}: ${skewed.length}/${entries.length} tap entries with aspect != ${wantAspect.toFixed(4)} (first: ${skewed[0].width}x${skewed[0].height})`,
      );
    viewer.tapCount = entries.length;
    viewer.senders = [...new Set(entries.map((e) => e.senderId))];
    // Report-only here (a 30 s run is too short to gate on): the gap
    // between consecutive decoded frames per sender, and how many gaps
    // reached the tile's 3 s "Stalled" threshold (stallDetector.ts).
    viewer.gaps = screenGapStats(entries, 3000);
  }

  // 2-participant mode only: also confirm the viewer's remote tile canvas
  // has real pixel content, not just a nonzero tap count (same rationale as
  // the own-preview check above -- draw and decode are separate failure
  // points).
  if (!loadMode) {
    const [sharer, viewer] = participants;
    const frac = await nonBlackFraction(viewer, `screen-tile-${sharer.id}`);
    if (frac === null) summary.errors.push(`${viewer.id}: screen-tile-${sharer.id} canvas not found`);
    else if (frac < 0.5)
      summary.errors.push(`${viewer.id}: screen-tile-${sharer.id} canvas is ${(frac * 100).toFixed(0)}% non-black (want >=50%, remote tile looks blank)`);
  }

  for (const c of participants) await c.ctx.close();
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
      execSync("pkill -x wired_server");
    } catch {
      /* nothing was left running */
    }
}

summary.ok = summary.errors.length === 0;
console.log(JSON.stringify(summary, null, 2));
process.exit(summary.ok ? 0 : 1);
