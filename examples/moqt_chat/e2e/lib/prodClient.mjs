// Headless-Chrome client for testing against a REAL deployment: the
// production frontend served from GitHub Pages (a public origin) and a
// REAL wired_server the operator has already started (a Tailscale/LAN/
// public IP, not this repo's own localhost build). Two things an ordinary
// e2e run doesn't need line up here that this module owns:
//
// 1. Chrome's Private/Local Network Access checks (PNA) block a page
//    loaded from a public origin (github.io) from opening a connection to
//    a private/loopback address (Tailscale's 100.64.0.0/10 CGNAT range
//    included) unless the target opts in via a preflight response this
//    freestanding hub never sends. Confirmed by hand: every other
//    combination of --disable-features around PNA still blocked the
//    WebTransport handshake; only disabling all four flags together let
//    it through. There is no per-origin opt-in flag (Chrome removed
//    --disable-site-isolation-style overrides for this feature), so this
//    is the one working combination as of Chrome 146-153.
// 2. The page itself is untouched -- no getDisplayMedia fake is injected
//    by default, because the whole point of this module is to exercise
//    the deployment a real user hits, not a synthetic stream. Pass
//    `fakeScreen` only when you explicitly want the canvas-clock fake
//    (useful for a controlled two-headless-Chrome repro without a real
//    monitor).
import puppeteer from "puppeteer-core";
import { resolveChromeLaunch } from "./chromeLaunch.mjs";
import { fakeDisplayMediaScript } from "./screenShareFake.mjs";
import { WT_INSTRUMENTATION_SCRIPT } from "./stabilityClient.mjs";

const PNA_DISABLE_FEATURES = [
  "PrivateNetworkAccessSendPreflights",
  "PrivateNetworkAccessRespectPreflightResults",
  "BlockInsecurePrivateNetworkRequests",
  "LocalNetworkAccessChecks",
].join(",");

const JOIN_TIMEOUT_MS = 20000;

/** One shared browser process for a whole prod run (one per real user you
 * want to simulate would each need cert/mic/screen permission prompts a
 * real user answers once; --use-fake-ui-for-media-stream auto-accepts
 * them here the same way the rest of this e2e suite does). */
export async function launchProdBrowser() {
  const { executablePath, env } = resolveChromeLaunch();
  return puppeteer.launch({
    executablePath,
    headless: "new",
    env,
    args: [
      "--no-sandbox",
      "--use-fake-ui-for-media-stream",
      `--disable-features=${PNA_DISABLE_FEATURES}`,
    ],
  });
}

/** Joins pageUrl (the real GitHub Pages frontend) and connects to
 * serverUrl (the real wired_server the operator started) as participantId.
 * fakeScreen ({width,height}) injects the canvas-clock fake instead of a
 * real screen picker -- omit it to let a human answer the real picker
 * (only meaningful for a non-headless run; headless has no screen to
 * offer regardless and getDisplayMedia will simply reject). */
export async function joinProd(browser, { pageUrl, serverUrl, certHash, participantId, fakeScreen }) {
  const page = await browser.newPage();
  const errors = [];
  page.on("console", (m) => {
    if (m.type() === "error") errors.push(m.text());
  });
  page.on("pageerror", (e) => errors.push(String(e)));
  // window.__wtUniStreams (incoming uni-stream byte/open-time log) is how
  // screenStreamsSince() tells a leaked stale relay stream apart from a
  // fresh one -- see stabilityClient.mjs's own doc for what this wraps.
  await page.evaluateOnNewDocument(WT_INSTRUMENTATION_SCRIPT);
  if (fakeScreen) await page.evaluateOnNewDocument(fakeDisplayMediaScript(fakeScreen));
  await page.goto(pageUrl, { waitUntil: "networkidle2", timeout: JOIN_TIMEOUT_MS });
  await page.evaluate((url) => {
    const input = document.querySelector('input[data-testid="url"]');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
    setter.call(input, url);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }, serverUrl);
  await page.type('input[data-testid="certHash"]', certHash);
  await page.click(`[data-testid="participant-${participantId}"]`);
  await page.click('[data-testid="connect"]');
  try {
    await page.waitForFunction(
      () => document.querySelector('[data-testid="status"]')?.getAttribute("data-status") === "connected",
      { timeout: JOIN_TIMEOUT_MS },
    );
  } catch (err) {
    const status = await page
      .evaluate(() => document.querySelector('[data-testid="status"]')?.getAttribute("data-status"))
      .catch(() => "(page gone)");
    throw new Error(`${participantId} did not reach connected (status=${status}): ${err.message}`);
  }
  return { id: participantId, page, errors, joinedAt: Date.now() };
}

/** Leaves the room (clicks "← Leave") without closing the tab -- lets a
 * scenario simulate the same tab rejoining, matching a real user's
 * refresh/rejoin more closely than closing and reopening a page. No
 * data-testid exists on this button in production markup (it's plain
 * button text), so this matches by visible text. */
export async function leaveProd(client) {
  await client.page.evaluate(() => {
    const btn = [...document.querySelectorAll("button")].find((b) =>
      b.textContent?.includes("Leave"),
    );
    btn?.click();
  });
}

export async function toggleScreenShare(client) {
  await client.page.click('[data-testid="screen-toggle"]');
}

/** Decoded-frame tap count from senderId (screenTap.ts via
 * window.__wiredScreenTap), optionally only entries at/after sinceMs. */
export async function screenTapCount(client, senderId, sinceMs = 0) {
  return client.page.evaluate(
    (sender, since) =>
      (window.__wiredScreenTap ?? []).filter((e) => e.senderId === sender && e.t >= since).length,
    senderId,
    sinceMs,
  );
}

export async function screenTapEntries(client, senderId) {
  return client.page.evaluate(
    (sender) => (window.__wiredScreenTap ?? []).filter((e) => e.senderId === sender),
    senderId,
  );
}

/** Polls until senderId has decoded at least `want` MORE frames than it
 * had when this call started, or returns null past timeoutMs -- the prod
 * twin of stabilityClient.mjs's waitFirstDecode, for screen taps. */
export async function waitScreenFrames(client, senderId, want, timeoutMs) {
  const start = Date.now();
  const base = await screenTapCount(client, senderId);
  try {
    await client.page.waitForFunction(
      (sender, wantTotal) =>
        (window.__wiredScreenTap ?? []).filter((e) => e.senderId === sender).length >= wantTotal,
      { timeout: timeoutMs },
      senderId,
      base + want,
    );
    return Date.now() - start;
  } catch {
    return null;
  }
}

export async function closeProd(client) {
  await client.page.close().catch(() => {});
}
