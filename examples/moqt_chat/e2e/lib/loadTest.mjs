// Multi-client MOQT chat load test: N clients, each in its own incognito-like
// BrowserContext, join the same room (moqt_chat has exactly one -- the hub's
// fixed namespace, see src/app/moqt/run/moqtrun.h) and exchange chat
// messages on a fixed interval. Every message id is scraped from the DOM
// the moment it is observed; results feed summarizeDelivery (lib/metrics.mjs)
// for loss-rate/latency numbers.
//
// Participant ids are drawn from the frontend's fixed candidate list
// (frontend/src/lib/moqtClient.ts CANDIDATE_PARTICIPANT_IDS = user1..user4,
// ponytail: SUBSCRIBE-by-guessing since MOQT namespace discovery is out of
// scope for this subset) -- so clientCount must be <= 4. A 5th client would
// PUBLISH successfully but no other client's guess list would ever include
// its id, so it would never receive anything and never be received: that's
// a hub-config limit, not a protocol loss, and is asserted against up front
// rather than silently producing a misleading 100% loss report.

import { summarizeDelivery } from "./metrics.mjs";

const JOIN_TIMEOUT_MS = 20000;
export const CANDIDATE_PARTICIPANT_IDS = ["user1", "user2", "user3", "user4"];
export const MAX_CLIENTS = CANDIDATE_PARTICIPANT_IDS.length;

async function joinClient(browser, pageUrl, certHash, participantId) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));

  await page.goto(pageUrl);
  await page.type("#certHash", certHash);
  await page.type("#author", participantId);
  await page.click("#connect");
  await page.waitForFunction(
    () => document.querySelector("#status")?.className === "status status-connected",
    { timeout: JOIN_TIMEOUT_MS },
  );

  // Poll the message list for new (tag, seq) ids rather than instrumenting
  // the app's own code -- black-box test of what a real user would see
  // rendered. Message format is domRenderer's "[time] author: text", so the
  // regex only has to find the msg:tag:seq token inside the line.
  const seenIds = new Set();
  const received = [];
  const pollHandle = setInterval(async () => {
    let texts;
    try {
      texts = await page.evaluate(() =>
        [...document.querySelectorAll("#messages li")].map((e) => e.textContent),
      );
    } catch {
      return; // page navigating/closing: skip this tick
    }
    for (const line of texts) {
      const m = line.match(/msg:[A-Za-z0-9]+:\d+/);
      if (!m) continue;
      const id = m[0];
      if (seenIds.has(id)) continue;
      seenIds.add(id);
      received.push({ id, receiverTag: participantId, receivedAt: Date.now() });
    }
  }, 100);

  return {
    tag: participantId,
    page,
    errors,
    received,
    stopPolling: () => clearInterval(pollHandle),
  };
}

async function sendOneMessage(client, seq) {
  const id = `msg:${client.tag}:${seq}`;
  await client.page.evaluate((text) => {
    const input = document.querySelector("#text");
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      "value",
    ).set;
    setter.call(input, text);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }, id);
  await client.page.evaluate(() => {
    document.querySelector("#chat-form").requestSubmit();
  });
  return { id, senderTag: client.tag, sentAt: Date.now() };
}

/**
 * @param {object} opts
 * @param {import("puppeteer-core").Browser} opts.browser
 * @param {string} opts.pageUrl static frontend URL (e.g. http://localhost:8091/)
 * @param {string} opts.certHash server's certificate fingerprint (colon hex)
 * @param {number} opts.clientCount number of simultaneous participants (<= MAX_CLIENTS)
 * @param {number} opts.messagesPerClient how many chat messages each client sends
 * @param {number} opts.sendIntervalMs delay between one client's sends
 * @param {number} opts.settleMs extra wait after the last send before grading
 */
export async function runChatLoadTest({
  browser,
  pageUrl,
  certHash,
  clientCount,
  messagesPerClient,
  sendIntervalMs,
  settleMs,
}) {
  if (clientCount > MAX_CLIENTS) {
    throw new Error(
      `clientCount ${clientCount} exceeds MAX_CLIENTS ${MAX_CLIENTS} ` +
        "(frontend's fixed candidate participant id list)",
    );
  }
  const tags = CANDIDATE_PARTICIPANT_IDS.slice(0, clientCount);
  const clients = [];
  for (const tag of tags) {
    // Serial join: joining is not itself under test here, and serializing
    // keeps this test isolated to steady-state chat throughput.
    clients.push(await joinClient(browser, pageUrl, certHash, tag));
    await new Promise((r) => setTimeout(r, 1500));
  }

  const sent = [];
  for (let seq = 0; seq < messagesPerClient; seq++) {
    for (const client of clients) {
      sent.push(await sendOneMessage(client, seq));
      await new Promise((r) => setTimeout(r, sendIntervalMs));
    }
  }

  await new Promise((r) => setTimeout(r, settleMs));

  const received = clients.flatMap((c) => c.received);
  const pageErrors = Object.fromEntries(clients.map((c) => [c.tag, c.errors]));

  for (const c of clients) c.stopPolling();
  for (const c of clients) await c.page.browserContext().close();

  return { ...summarizeDelivery(sent, received, tags), pageErrors, clientCount };
}
