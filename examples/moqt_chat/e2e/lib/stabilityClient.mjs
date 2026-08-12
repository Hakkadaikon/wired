// Per-client browser control for stability scenarios. Unlike loadTest.mjs's
// shared-browser BrowserContexts, each client here owns a whole Chrome
// process, so crash() (SIGKILL) is a genuine abrupt disconnect: no clean
// QUIC CONNECTION_CLOSE ever reaches the server and its state for the
// client lingers -- exactly the condition reconnect scenarios need.
//
// Instrumentation is injected before navigation (same black-box principle
// as voiceLoadTest.mjs): AudioDecoder.decode() counting, a 1s-bucketed
// decode timeline, and WebTransport open/ready/closed timestamps (the
// frontend never subscribes to wt.closed, so transport-level death is
// measured here, not from the UI badge).

import puppeteer from "puppeteer-core";
import { resolveChromeLaunch } from "./chromeLaunch.mjs";

const JOIN_TIMEOUT_MS = 20000;

const INIT_SCRIPT = `
  window.__decodedFrameCount = 0;
  const RealAudioDecoder = window.AudioDecoder;
  if (RealAudioDecoder) {
    window.AudioDecoder = class extends RealAudioDecoder {
      decode(chunk) {
        window.__decodedFrameCount++;
        window.__lastDecodeAt = Date.now();
        return super.decode(chunk);
      }
    };
  }
  window.__decodeTimeline = [];
  setInterval(() => {
    window.__decodeTimeline.push(window.__decodedFrameCount);
  }, 1000);
  window.__wtEvents = [];
  // Transport-level receive log: one record per INCOMING uni stream --
  // openedAt/bytes/head (first 256 bytes, printable-projected so a chat
  // payload's "msg:userX:N" text is grep-able)/closed ("fin" or
  // "abort:..."). Lets a scenario tell "the bytes never reached this
  // client" apart from "arrived at transport but lost above it" -- the
  // distinction DOM-scrape chat gates cannot make. Each incoming stream is
  // tee'd: one branch to the app untouched, the logging branch is drained
  // continuously (an unread tee branch would buffer the whole stream).
  window.__wtUniStreams = [];
  const wrapIncomingUni = (transport) => {
    const inner = transport.incomingUnidirectionalStreams;
    const wrapped = new ReadableStream({
      async start(controller) {
        const reader = inner.getReader();
        try {
          for (;;) {
            const { value, done } = await reader.read();
            if (done) { controller.close(); return; }
            const [toApp, toLog] = value.tee();
            const srec = { openedAt: Date.now(), bytes: 0, head: "", closed: null };
            window.__wtUniStreams.push(srec);
            (async () => {
              const r = toLog.getReader();
              try {
                for (;;) {
                  const { value: chunk, done: d } = await r.read();
                  if (d) { srec.closed = "fin"; return; }
                  if (srec.head.length < 256) {
                    let s = "";
                    for (const c of chunk)
                      s += c >= 32 && c < 127 ? String.fromCharCode(c) : ".";
                    srec.head = (srec.head + s).slice(0, 256);
                  }
                  srec.bytes += chunk.length;
                }
              } catch (e) { srec.closed = "abort:" + String(e); }
            })();
            controller.enqueue(toApp);
          }
        } catch (e) { controller.error(e); }
      },
    });
    Object.defineProperty(transport, "incomingUnidirectionalStreams", {
      get: () => wrapped,
      configurable: true,
    });
  };
  const RealWT = window.WebTransport;
  window.WebTransport = class extends RealWT {
    constructor(...args) {
      super(...args);
      const rec = { openedAt: Date.now(), readyAt: null, closedAt: null, closeInfo: null };
      window.__wtEvents.push(rec);
      wrapIncomingUni(this);
      this.ready.then(() => { rec.readyAt = Date.now(); }, () => {});
      this.closed.then(
        (info) => { rec.closedAt = Date.now(); rec.closeInfo = "closed:" + (info && info.closeCode); },
        (e) => { rec.closedAt = Date.now(); rec.closeInfo = "error:" + String(e); },
      );
    }
  };
  const voiceTapEpochOffset = Date.now() - performance.now();
  window.__wiredVoiceTap = (e) => {
    const buf = (window.__wiredVoiceTapBuf ||= []);
    if (buf.length < 30000) {
      e.t += voiceTapEpochOffset;
      buf.push(e);
    }
  };
`;

// Join-form values are seeded through the frontend's own saved-prefs
// mechanism (localStorage "moqt-chat.join", restored on mount) instead of
// typing into the inputs: a synthetic fill can race React hydration -- a
// value written before hydration is wiped by the first controlled render,
// and the connect click then goes out with an empty cert hash. Watching the
// controlled input render the seeded value doubles as the hydration gate.

/**
 * Launch one dedicated Chrome process (with fake mic) and join the room.
 * @param {object} opts
 * @param {string} opts.pageUrl       static frontend URL
 * @param {string} opts.serverUrl     WebTransport URL (proxy or direct); "" keeps the page default
 * @param {string} opts.certHash      server cert fingerprint
 * @param {string} opts.participantId user1..user4
 */
export async function joinStabilityClient({ pageUrl, serverUrl, certHash, participantId }) {
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
  const client = {
    tag: participantId,
    browser,
    page: null,
    errors: [],
    joinedAt: null,
  };
  await connectClient(client, { pageUrl, serverUrl, certHash, participantId });
  return client;
}

/** (Re)connect an existing client object's browser to the room. Usable both
 * for the initial join and for a rejoin after the server came back. */
export async function connectClient(client, { pageUrl, serverUrl, certHash, participantId }) {
  const page = await client.browser.newPage();
  client.page = page;
  page.on("pageerror", (e) => client.errors.push(e.message));
  await page.evaluateOnNewDocument(INIT_SCRIPT);
  await page.evaluateOnNewDocument(
    (prefs) => localStorage.setItem("moqt-chat.join", JSON.stringify(prefs)),
    {
      url: serverUrl || "https://localhost:4433/",
      certHash,
      name: participantId,
    },
  );
  await page.goto(pageUrl);
  await page.waitForFunction(
    (h) => document.querySelector('input[data-testid="certHash"]')?.value === h,
    { timeout: JOIN_TIMEOUT_MS },
    certHash,
  );
  await page.click(`[data-testid="participant-${participantId}"]`);
  const connectStart = Date.now();
  await page.click('[data-testid="connect"]');
  try {
    await page.waitForFunction(
      () => document.querySelector('[data-testid="status"]')?.getAttribute("data-status") === "connected",
      { timeout: JOIN_TIMEOUT_MS },
    );
  } catch (err) {
    const state = await page
      .evaluate(() => ({
        status: document.querySelector('[data-testid="status"]')?.getAttribute("data-status") ?? "(no badge)",
        wtEvents: window.__wtEvents ?? [],
      }))
      .catch(() => null);
    throw new Error(
      `${participantId} did not reach connected in ${JOIN_TIMEOUT_MS}ms; ` +
        `state=${JSON.stringify(state)}`,
      { cause: err },
    );
  }
  client.joinedAt = Date.now();
  client.connectStart = connectStart;
  return client;
}

/** Wait until this page decoded at least `past` + 1 audio frames.
 * Returns the wall-clock time the threshold was crossed. */
export async function waitFirstDecode(client, { past = 0, timeoutMs = 15000 } = {}) {
  await client.page.waitForFunction(
    (past) => (window.__decodedFrameCount ?? 0) > past,
    { timeout: timeoutMs },
    past,
  );
  return Date.now();
}

/** Snapshot the page's instrumentation counters. */
export async function clientMetrics(client) {
  try {
    return await client.page.evaluate(() => ({
      decodedFrameCount: window.__decodedFrameCount ?? 0,
      lastDecodeAt: window.__lastDecodeAt ?? null,
      decodeTimeline: window.__decodeTimeline ?? [],
      wtEvents: window.__wtEvents ?? [],
      wtUniStreams: window.__wtUniStreams ?? [],
      voiceTapEvents: window.__wiredVoiceTapBuf ?? [],
    }));
  } catch {
    return null;
  }
}

/** Abrupt disconnect: SIGKILL the whole browser process. No clean close is
 * sent, so the server's state for this client lingers. */
export async function crashClient(client) {
  const proc = client.browser.process();
  proc.kill("SIGKILL");
  await new Promise((r) => proc.once("exit", r));
}

/** Clean teardown (end-of-scenario, not part of the measured behavior). */
export async function closeClient(client) {
  await client.browser.close().catch(() => {});
}
