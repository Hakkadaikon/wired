// Chat + voice load test: same multi-client chat exchange as loadTest.mjs,
// but every client also joins with a fake microphone device
// (--use-fake-device-for-media-stream) so MoqtVoiceClient's audio publish
// path (moqtVoiceClient.ts) is exercised concurrently with chat. This is
// what verifies the WT uni-stream-slot exhaustion fix: voice used to open a
// fresh uni stream per 20ms Opus frame and starve chat's own uni streams of
// the same fixed receive-slot pool (WIRED_SRVLOOP_MAX_WT_UNI_STREAMS).
//
// Voice delivery itself is graded by counting AudioDecoder.decode() calls in
// each page (window.AudioDecoder is wrapped before navigation via
// evaluateOnNewDocument) rather than instrumenting the app's own source --
// same black-box principle as loadTest.mjs's DOM polling for chat.

import { summarizeDelivery } from "./metrics.mjs";

const JOIN_TIMEOUT_MS = 20000;
export const CANDIDATE_PARTICIPANT_IDS = ["user1", "user2", "user3", "user4"];
export const MAX_CLIENTS = CANDIDATE_PARTICIPANT_IDS.length;

const DECODE_COUNTER_INIT_SCRIPT = `
  window.__decodedFrameCount = 0;
  const RealAudioDecoder = window.AudioDecoder;
  if (RealAudioDecoder) {
    window.AudioDecoder = class extends RealAudioDecoder {
      decode(chunk) {
        window.__decodedFrameCount++;
        return super.decode(chunk);
      }
    };
  }
  window.__uniStreamOpenCount = 0;
  const realCreateUni = WebTransport.prototype.createUnidirectionalStream;
  WebTransport.prototype.createUnidirectionalStream = function (...args) {
    window.__uniStreamOpenCount++;
    return realCreateUni.apply(this, args);
  };
`;

async function joinVoiceClient(browser, pageUrl, certHash, participantId) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.evaluateOnNewDocument(DECODE_COUNTER_INIT_SCRIPT);

  await page.goto(pageUrl);
  await page.type('input[data-testid="certHash"]', certHash);
  await page.click(`[data-testid="participant-${participantId}"]`);
  await page.click('[data-testid="connect"]');
  await page.waitForFunction(
    () => document.querySelector('[data-testid="status"]')?.getAttribute("data-status") === "connected",
    { timeout: JOIN_TIMEOUT_MS },
  );

  const seenIds = new Set();
  const received = [];
  const pollHandle = setInterval(async () => {
    let texts;
    try {
      texts = await page.evaluate(() =>
        [...document.querySelectorAll('[data-testid="message"]')].map((e) => e.textContent),
      );
    } catch {
      return;
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
    const input = document.querySelector('input[data-testid="text"]');
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      "value",
    ).set;
    setter.call(input, text);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  }, id);
  return { id, senderTag: client.tag, sentAt: Date.now() };
}

/**
 * @param {object} opts
 * @param {import("puppeteer-core").Browser} opts.browser
 * @param {string} opts.pageUrl
 * @param {string} opts.certHash
 * @param {number} opts.clientCount
 * @param {number} opts.messagesPerClient
 * @param {number} opts.sendIntervalMs
 * @param {number} opts.settleMs
 */
export async function runChatVoiceLoadTest({
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
    clients.push(await joinVoiceClient(browser, pageUrl, certHash, tag));
    await new Promise((r) => setTimeout(r, 1500));
  }

  // Give the mic pipeline (getUserMedia -> AudioEncoder -> first
  // sendOpusFrame, which opens the long-lived audio relay stream) a moment
  // to actually start producing frames before chat sending begins, so voice
  // traffic is genuinely concurrent with chat rather than trailing it.
  await new Promise((r) => setTimeout(r, 2000));

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
  const decodedFrameCounts = {};
  const uniStreamOpenCounts = {};
  for (const c of clients) {
    try {
      decodedFrameCounts[c.tag] = await c.page.evaluate(() => window.__decodedFrameCount ?? 0);
      uniStreamOpenCounts[c.tag] = await c.page.evaluate(() => window.__uniStreamOpenCount ?? 0);
    } catch {
      decodedFrameCounts[c.tag] = null;
      uniStreamOpenCounts[c.tag] = null;
    }
  }

  for (const c of clients) c.stopPolling();
  for (const c of clients) await c.page.browserContext().close();

  return {
    ...summarizeDelivery(sent, received, tags),
    pageErrors,
    clientCount,
    decodedFrameCounts,
    uniStreamOpenCounts,
  };
}
