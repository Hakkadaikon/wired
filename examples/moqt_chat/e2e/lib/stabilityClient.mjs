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
import { defaultRoom, E2E_SERVER_URL, withDefaultRoom } from "./args.mjs";
import { resolveChromeLaunch } from "./chromeLaunch.mjs";
import { keyOf, nostrLogin } from "./nostrE2e.mjs";
import {
	creator,
	DEFAULT_HOST_KEY,
	linkOf,
	settled as settledScript,
	waitRoomLog,
} from "./roomsE2e.mjs";

const JOIN_TIMEOUT_MS = 20000;

export const WT_INSTRUMENTATION_SCRIPT = `
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
  // payload's "msg:userX:N" text is grep-able)/type (the first byte: the
  // Stream Type, 0x05 for a FETCH_HEADER fill)/closed ("fin" or
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
                  if (srec.bytes === 0) srec.type = chunk[0];
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
  // Outgoing (client-to-server) uni stream log: mirrors __wtUniStreams but
  // for THIS client's own sends -- one record per createUnidirectionalStream
  // call, appended to as the app's WritableStreamDefaultWriter writes and
  // closes. Wraps the STREAM object's own writable.getWriter, not the
  // WritableStream class globally, so only streams this client actually
  // opened are logged (a shared class patch would also catch unrelated
  // internal writers). Lets a scenario tell "the bytes never left this
  // client" apart from "left but never reached the receiver" -- the missing
  // half of __wtUniStreams' receive-side-only view.
  window.__wtOutUniStreams = [];
  const wrapOutgoingUni = (transport) => {
    const orig = transport.createUnidirectionalStream.bind(transport);
    transport.createUnidirectionalStream = async (...args) => {
      const stream = await orig(...args);
      const srec = { openedAt: Date.now(), bytes: 0, head: "", closed: null };
      window.__wtOutUniStreams.push(srec);
      const origGetWriter = stream.getWriter.bind(stream);
      stream.getWriter = () => {
        const w = origGetWriter();
        const origWrite = w.write.bind(w);
        const origClose = w.close.bind(w);
        const origAbort = w.abort.bind(w);
        w.write = (chunk) => {
          if (chunk instanceof Uint8Array) {
            if (srec.head.length < 256) {
              let s = "";
              for (const c of chunk)
                s += c >= 32 && c < 127 ? String.fromCharCode(c) : ".";
              srec.head = (srec.head + s).slice(0, 256);
            }
            srec.bytes += chunk.length;
          }
          return origWrite(chunk);
        };
        w.close = () => { srec.closed = "fin"; return origClose(); };
        w.abort = (reason) => { srec.closed = "abort:" + String(reason); return origAbort(reason); };
        return w;
      };
      return stream;
    };
  };
  // Total createUnidirectionalStream calls across ALL transports on this
  // page (same tap name as voiceLoadTest.mjs's): an auto-rejoin proves its
  // new session actually sends again by bumping this count.
  window.__uniStreamOpenCount = 0;
  const realCreateUni = window.WebTransport.prototype.createUnidirectionalStream;
  window.WebTransport.prototype.createUnidirectionalStream = function (...args) {
    window.__uniStreamOpenCount++;
    return realCreateUni.apply(this, args);
  };
  const RealWT = window.WebTransport;
  window.WebTransport = class extends RealWT {
    constructor(...args) {
      super(...args);
      const rec = { openedAt: Date.now(), readyAt: null, closedAt: null, closeInfo: null };
      window.__wtEvents.push(rec);
      wrapIncomingUni(this);
      wrapOutgoingUni(this);
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
 * @param {string[]} [opts.initScripts] extra scripts injected before navigation (after WT_INSTRUMENTATION_SCRIPT)
 * @param {(page) => Promise<void>} [opts.beforeConnect] runs on the loaded join screen, before Join
 * @param {boolean} [opts.expectClosed] a final screen instead of connected
 *   is the expected outcome (client.closedReason)
 *
 * A pageUrl without ?room= joins the run's default room; the first such
 * client creates it (as key DEFAULT_HOST_KEY) and waits until it is live.
 */
export async function joinStabilityClient(opts) {
	if (new URL(opts.pageUrl).searchParams.has("room")) return joinOnce(opts);
	if (defaultRoom.id) return joinOnce(withGuestLogin(opts));
	const client = await createRoomClient(
		opts,
		DEFAULT_HOST_KEY,
		defaultRoom.mode,
	);
	const link = new URL(client.link);
	defaultRoom.id = link.searchParams.get("room");
	defaultRoom.host = link.searchParams.get("host");
	return client;
}

// A login-required default room (defaultRoom.mode "auth", for crash-rejoin
// scenarios): guest user<k> logs in with test key 10 + k, so its rejoin
// after a crash carries the same key and takes its id over from the stale
// session (server.md 5.3).
function withGuestLogin(opts) {
	if (defaultRoom.mode !== "auth") return opts;
	const login = nostrLogin(keyOf(10 + Number(opts.participantId.slice(4))));
	return {
		...opts,
		beforeConnect: async (page) => {
			await login(page);
			await opts.beforeConnect?.(page);
		},
	};
}

/** After a hub restart (every room gone): client, the default room's
 * creator, creates a new default room on a fresh page and waits until it
 * is live; later default-room joins go there. */
export async function recreateDefaultRoom(client, opts) {
	const c = creator(opts.pageUrl, DEFAULT_HOST_KEY);
	defaultRoom.id = ""; // else the page would open the old room's link
	await client.page?.close().catch(() => {});
	await connectClient(client, {
		...opts,
		pageUrl: c.pageUrl,
		initScripts: c.initScripts,
		beforeConnect: c.beforeConnect,
	});
	const link = new URL(await linkOf(client, opts.pageUrl));
	if (!(await waitRoomLog(link.href, "live")))
		throw new Error("the default room was not re-created");
	defaultRoom.id = link.searchParams.get("room");
	defaultRoom.host = link.searchParams.get("host");
	client.link = link.href;
}

/** Key n creates a room (mode open|auth) through the UI and joins it as
 * its host; resolves once the hub logs the room live. client.link is the
 * link guests join by. opts as joinStabilityClient's (its beforeConnect
 * runs after the login and the create; with expectClosed it does not wait
 * for live). */
export async function createRoomClient(opts, n, mode = "open") {
	const c = creator(opts.pageUrl, n, mode);
	const client = await joinOnce({
		...opts,
		pageUrl: c.pageUrl,
		initScripts: [...c.initScripts, ...(opts.initScripts ?? [])],
		beforeConnect: async (page) => {
			await c.beforeConnect(page);
			await opts.beforeConnect?.(page);
		},
	});
	client.link = await linkOf(client, opts.pageUrl);
	if (opts.expectClosed) return client; // a refused create: the caller checks
	if (!(await waitRoomLog(client.link, "live"))) {
		await closeClient(client);
		throw new Error(`the room of key ${n} did not go live`);
	}
	return client;
}

async function joinOnce({
	pageUrl,
	serverUrl,
	certHash,
	participantId,
	initScripts,
	beforeConnect,
	expectClosed,
}) {
	const { executablePath, env } = resolveChromeLaunch();
	const browser = await launchChrome({
		executablePath,
		headless: "new",
		env,
		// Chrome's default CDP protocolTimeout (180s) is shorter than a large
		// attachment's own waitForSelector wait, so a slow round trip fails at
		// the CDP layer with a misleading net::ERR_* before that wait ever
		// expires. Match it to the longest scenario timeout in this directory.
		protocolTimeout: 900_000,
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
	// A failed join closes its Chrome: a leaked one keeps the runner alive.
	await connectClient(client, {
		pageUrl,
		serverUrl,
		certHash,
		participantId,
		initScripts,
		beforeConnect,
		expectClosed,
	}).catch(async (err) => {
		await closeClient(client);
		throw err;
	});
	return client;
}

/** puppeteer.launch, retried once when Chrome's browser process itself
 * fails to start (seen on this host with no server involved); any other
 * error is thrown at once. */
export function launchChrome(opts) {
	return puppeteer.launch(opts).catch((err) => {
		if (!String(err?.message).includes("Failed to launch the browser process"))
			throw err;
		return puppeteer.launch(opts);
	});
}

/** (Re)connect an existing client object's browser to the room. Usable both
 * for the initial join and for a rejoin after the server came back. */
export async function connectClient(
	client,
	{
		pageUrl,
		serverUrl,
		certHash,
		participantId,
		initScripts = [],
		beforeConnect,
		expectClosed,
	},
) {
	const page = await client.browser.newPage();
	client.page = page;
	page.on("pageerror", (e) => client.errors.push(e.message));
	page.on("error", (e) => client.errors.push(`page crashed: ${e.message}`));
	await page.evaluateOnNewDocument(WT_INSTRUMENTATION_SCRIPT);
	for (const script of initScripts) await page.evaluateOnNewDocument(script);
	await page.evaluateOnNewDocument(
		(prefs) => localStorage.setItem("moqt-chat.join", JSON.stringify(prefs)),
		{
			url: serverUrl || E2E_SERVER_URL,
			certHash,
			name: participantId,
		},
	);
	// The e2e harness always runs with RNNoise off: 4 worklets (one per
	// headless Chrome) on a shared box is a test-environment CPU artifact,
	// and the transport gates (loss/jitter/plc) must measure the network
	// path, not worklet CPU (see noiseSuppressionDefault in joinPrefs.ts).
	// E2E_RNNOISE=1 keeps the production default (RNNoise on) instead.
	const nsOffUrl = new URL(withDefaultRoom(pageUrl));
	if (process.env.E2E_RNNOISE !== "1") nsOffUrl.searchParams.set("ns", "0");
	await page.goto(nsOffUrl.href);
	await page.waitForFunction(
		(h) => document.querySelector('input[data-testid="certHash"]')?.value === h,
		{ timeout: JOIN_TIMEOUT_MS },
		certHash,
	);
	await page.click(`[data-testid="participant-${participantId}"]`);
	await beforeConnect?.(page);
	const connectStart = Date.now();
	await page.click('[data-testid="connect"]');
	try {
		const h = await page.waitForFunction(settledScript, {
			timeout: JOIN_TIMEOUT_MS,
		});
		const settled = await h.jsonValue();
		if (settled !== "connected") {
			client.closedReason = settled;
			if (expectClosed) return client;
			throw new Error(`closed: ${settled}`);
		}
	} catch (err) {
		const state = await page
			.evaluate(() => ({
				status:
					document
						.querySelector('[data-testid="status"]')
						?.getAttribute("data-status") ?? "(no badge)",
				wtEvents: window.__wtEvents ?? [],
			}))
			.catch(() => null);
		throw new Error(
			`${participantId} did not reach connected in ${JOIN_TIMEOUT_MS}ms ` +
				`(${err.message}); state=${JSON.stringify(state)}; ` +
				`errors=${client.errors.join(" | ")}`,
			{ cause: err },
		);
	}
	client.joinedAt = Date.now();
	client.connectStart = connectStart;
	return client;
}

/** Wait until this page decoded at least `past` + 1 audio frames.
 * Returns the wall-clock time the threshold was crossed. */
export async function waitFirstDecode(
	client,
	{ past = 0, timeoutMs = 15000 } = {},
) {
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
			wtOutUniStreams: window.__wtOutUniStreams ?? [],
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
