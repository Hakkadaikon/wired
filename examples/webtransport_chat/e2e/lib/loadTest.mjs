// Multi-client chat load test: N clients, each in its own incognito-like
// BrowserContext (so the known headless-Chrome same-profile cert-pinning
// flake -- see examples/webtransport_chat/README.md -- never triggers),
// join the same room and exchange chat messages on a fixed interval. Every
// message id is scraped from the DOM the moment it is observed; results feed
// summarizeDelivery (lib/metrics.mjs) for loss-rate/latency numbers.

import { summarizeDelivery } from "./metrics.mjs";

const JOIN_TIMEOUT_MS = 20000;

async function joinClient(browser, pageUrl, certHash, tag, room) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));

  await page.goto(pageUrl);
  await page.type('input[name="Certificate hash (SHA-256)"]', certHash);
  await page.type('input[name="Display name"]', tag);
  await page.evaluate((label) => {
    const btn = [...document.querySelectorAll("button")].find(
      (b) => b.textContent.trim() === label,
    );
    if (!btn) throw new Error(`room button "${label}" not found`);
    btn.click();
  }, room);
  await page.evaluate(() => {
    const btn = [...document.querySelectorAll("button")].find((b) =>
      b.textContent.includes("Join"),
    );
    if (!btn) throw new Error("Join button not found");
    btn.click();
  });
  await page.waitForFunction(
    () => document.body.textContent.includes("Connected"),
    { timeout: JOIN_TIMEOUT_MS },
  );

  // Poll the message list for new (tag, seq) ids rather than instrumenting
  // the app's own code -- this stays a black-box test of what a real user
  // would see rendered, not of internal event wiring.
  const seenIds = new Set();
  const received = [];
  const pollHandle = setInterval(async () => {
    let texts;
    try {
      texts = await page.evaluate(() =>
        [...document.querySelectorAll("*")]
          .map((e) => e.textContent)
          .filter((t) => t && /^msg:[A-Za-z0-9]+:\d+$/.test(t)),
      );
    } catch {
      return; // page navigating/closing: skip this tick
    }
    for (const t of texts) {
      if (seenIds.has(t)) continue;
      seenIds.add(t);
      received.push({ id: t, receiverTag: tag, receivedAt: Date.now() });
    }
  }, 100);

  return { tag, page, errors, received, stopPolling: () => clearInterval(pollHandle) };
}

async function sendOneMessage(client, seq) {
  const id = `msg:${client.tag}:${seq}`;
  await client.page.evaluate((text) => {
    const input = document.querySelector('input[name="chat-message"]');
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      "value",
    ).set;
    setter.call(input, text);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }, id);
  await client.page.evaluate(() => {
    const btn = [...document.querySelectorAll("button")].find((b) =>
      b.textContent.includes("Send"),
    );
    btn.click();
  });
  return { id, senderTag: client.tag, sentAt: Date.now() };
}

/**
 * @param {object} opts
 * @param {import("puppeteer-core").Browser} opts.browser
 * @param {string} opts.pageUrl static frontend URL (e.g. http://localhost:8080/)
 * @param {string} opts.certHash server's certificate fingerprint (colon hex)
 * @param {number} opts.clientCount number of simultaneous participants
 * @param {string} opts.room one of the fixed room names (Fox/Owl/Wolf/Bear)
 * @param {number} opts.messagesPerClient how many chat messages each client sends
 * @param {number} opts.sendIntervalMs delay between one client's sends
 * @param {number} opts.settleMs extra wait after the last send before grading
 */
export async function runChatLoadTest({
  browser,
  pageUrl,
  certHash,
  clientCount,
  room,
  messagesPerClient,
  sendIntervalMs,
  settleMs,
}) {
  const tags = Array.from({ length: clientCount }, (_, i) => `C${i}`);
  const clients = [];
  for (const tag of tags) {
    // Serial join: joining is not itself under test here (see README's
    // single-pending-slot note applying to presence datagrams too), and
    // serializing keeps this test isolated to steady-state chat throughput.
    clients.push(await joinClient(browser, pageUrl, certHash, tag, room));
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

  return { ...summarizeDelivery(sent, received, tags), pageErrors, room, clientCount };
}
