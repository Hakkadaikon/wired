// Rooms in e2e (tasks/moqt-chat-rooms.md P8). The hub always runs rooms
// (--public-url --nip05), so every run also starts a NIP-05 fixture
// (HTTPS, self-signed, on loopback) and nip05d pointed at it with its
// test-only -allow-host flag. A creator page gets a fake profile relay
// (kind 0 with nip05) and creates the room through the Create room UI.
//
// Test key n has the NIP-05 user@k<n>.e2e.test: one domain per key, since
// the hub allows one room per creator domain.

import { execFileSync, spawn } from "node:child_process";
import { appendFileSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:https";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { finalizeEvent } from "nostr-tools/pure";
import { defaultRoom, withDefaultRoom } from "./args.mjs";
import { keyOf, nostrLogin, pubkeyOf, WAIT_MS } from "./nostrE2e.mjs";

const e2eDir = path.dirname(path.dirname(new URL(import.meta.url).pathname));
const NIP05D_BIN = path.join(e2eDir, "..", "nip05d", "nip05d");
const FAKE_RELAY = "wss://relay.e2e.test/";

export const nip05Of = (n) => `user@k${n}.e2e.test`;

/** What the run's hub logs to: run-scenario.mjs sets it, the bash
 * harnesses export WIRED_E2E_HUB_LOG. */
export const hubLog = { path: process.env.WIRED_E2E_HUB_LOG ?? "" };

/** The default room's host: a test key no scenario logs in with. */
export const DEFAULT_HOST_KEY = 9;

// nostr.json for user@k<n>.e2e.test: nip05d sends Host k<n>.e2e.test.
function fixtureReply(req, res) {
	const n = Number(/^k(\d+)\.e2e\.test$/.exec(req.headers.host ?? "")?.[1]);
	res.setHeader("content-type", "application/json");
	res.end(JSON.stringify({ names: n ? { user: pubkeyOf(n) } : {} }));
}

async function startFixture() {
	const dir = mkdtempSync(path.join(os.tmpdir(), "nip05-fixture-"));
	const key = path.join(dir, "key.pem");
	const cert = path.join(dir, "cert.pem");
	execFileSync(
		"openssl",
		[
			...["req", "-x509", "-newkey", "ec", "-pkeyopt"],
			...["ec_paramgen_curve:prime256v1", "-nodes", "-days", "1"],
			...["-subj", "/CN=e2e.test", "-keyout", key, "-out", cert],
		],
		{ stdio: "ignore" },
	);
	const srv = createServer(
		{ key: readFileSync(key), cert: readFileSync(cert) },
		fixtureReply,
	);
	await new Promise((r) => srv.listen(0, "127.0.0.1", r));
	// The directory holds the fixture's private key: gone with the run.
	const removeDir = () => rmSync(dir, { recursive: true, force: true });
	process.on("exit", removeDir);
	srv.on("close", removeDir);
	return srv;
}

// nip05d on a free loopback port; resolves its ip:port from its log line.
function startNip05d(fixturePort, logPath) {
	const proc = spawn(
		NIP05D_BIN,
		["-tcp", "127.0.0.1:0", "-allow-host", `127.0.0.1:${fixturePort}`],
		{ stdio: ["ignore", "ignore", "pipe"] },
	);
	// A runner that dies without stop() must not leave nip05d behind.
	process.on("exit", () => proc.kill());
	let seen = "";
	const addr = new Promise((resolve, reject) => {
		proc.stderr.on("data", (chunk) => {
			appendFileSync(logPath, chunk);
			seen += chunk;
			const m = /listening on (127\.0\.0\.1:\d+)/.exec(seen);
			if (m) resolve(m[1]);
		});
		proc.on("exit", (code) => reject(new Error(`nip05d exited ${code}`)));
	});
	return { proc, addr };
}

/** The fixture and nip05d; `args(publicUrl)` are the hub's room flags
 * (publicUrl: the scheme://host:port the creating page connects to, the
 * NIP-98 "u"). */
export async function startRoomServices(evidenceDir) {
	const fixture = await startFixture();
	const nip05d = startNip05d(
		fixture.address().port,
		path.join(evidenceDir, "nip05d.log"),
	);
	const addr = await nip05d.addr;
	const stopNip05d = async () => {
		if (nip05d.proc.exitCode !== null || nip05d.proc.signalCode) return;
		const exited = new Promise((r) => nip05d.proc.once("exit", r));
		nip05d.proc.kill("SIGTERM");
		await exited;
	};
	return {
		args: (publicUrl) => [...["--public-url", publicUrl], ...["--nip05", addr]],
		stopNip05d,
		async stop() {
			await stopNip05d();
			fixture.close();
		},
	};
}

/** A page script: window.WebSocket answers every REQ from events, then
 * EOSE -- the creator's profile relay, so its kind 0 nip05 shows. */
export function fakeRelayScript(events) {
	return `(() => {
  const EVENTS = ${JSON.stringify(events)};
  const match = (f, e) =>
    (!f.kinds || f.kinds.includes(e.kind)) &&
    (!f.authors || f.authors.includes(e.pubkey));
  class FakeRelay {
    static CONNECTING = 0; static OPEN = 1; static CLOSING = 2; static CLOSED = 3;
    constructor(url) {
      this.url = url;
      this.readyState = 0;
      setTimeout(() => { this.readyState = 1; this.onopen?.(); });
    }
    emit(m) { setTimeout(() => this.onmessage?.({ data: JSON.stringify(m) })); }
    send(d) {
      const [op, sub, ...filters] = JSON.parse(d);
      if (op !== "REQ") return;
      for (const e of EVENTS)
        if (filters.some((f) => match(f, e))) this.emit(["EVENT", sub, e]);
      this.emit(["EOSE", sub]);
    }
    close() {
      this.readyState = 3;
      setTimeout(() => this.onclose?.({ code: 1000, reason: "" }));
    }
  }
  window.WebSocket = FakeRelay;
})();`;
}

/** Key n's kind 0 carrying its NIP-05. */
export const profileOf = (n) =>
	finalizeEvent(
		{
			kind: 0,
			created_at: Math.floor(Date.now() / 1000),
			tags: [],
			content: JSON.stringify({ nip05: nip05Of(n) }),
		},
		keyOf(n),
	);

/** joinStabilityClient options that make key n create a room (mode open
 * or auth) through the UI, then connect as its host. */
export function creator(pageUrl, n, mode = "open") {
	const u = new URL(pageUrl);
	u.searchParams.delete("room");
	u.searchParams.delete("host");
	u.searchParams.set("relays", FAKE_RELAY);
	const login = nostrLogin(keyOf(n));
	return {
		pageUrl: u.href,
		initScripts: [fakeRelayScript([profileOf(n)])],
		beforeConnect: async (page) => {
			await login(page);
			await page.waitForSelector(
				'[data-testid="create-room"][aria-disabled="false"]',
				{ timeout: WAIT_MS },
			);
			await page.click(`[data-testid="room-mode-${mode}"]`);
			await page.click('[data-testid="create-room"]');
			await page.waitForSelector('[data-testid="room-joining"]');
		},
	};
}

/** The link a guest joins by: pageUrl with the creator page's room and
 * host, off the profile relays. */
export async function linkOf(client, pageUrl) {
	const here = new URL(await client.page.evaluate(() => location.href));
	const u = new URL(pageUrl);
	u.searchParams.set("relays", "");
	u.searchParams.set("room", here.searchParams.get("room"));
	u.searchParams.set("host", here.searchParams.get("host"));
	return u.href;
}

/** The hub log's current length: a mark for waitRoomLog's since. */
export const hubLogMark = () => readFileSync(hubLog.path, "utf8").length;

/** Waits for the hub's "moqt room: <what> <id6> slot=<i> <tail>" line
 * (live, or end with its why: host, alone, empty, lifetime, nip05) after
 * the log offset since (a hub restart re-creates the same id). */
export async function waitRoomLog(
	link,
	what,
	tail = "",
	timeoutMs = WAIT_MS,
	since = 0,
) {
	const id6 = new URL(link).searchParams.get("room").slice(0, 6);
	const line = new RegExp(`moqt room: ${what} ${id6} slot=\\d+ ${tail}`);
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (line.test(readFileSync(hubLog.path, "utf8").slice(since))) return true;
		await new Promise((r) => setTimeout(r, 100));
	}
	return false;
}

/** In the page: "connected", or the final screen's reason token (a
 * refused join never reaches connected); falsy while neither. */
export const settled = () =>
	document.querySelector('[data-testid="room-closed"]')?.dataset.reason ??
	(document
		.querySelector('[data-testid="status"]')
		?.getAttribute("data-status") === "connected" &&
		"connected");

/** A guest after a hub restart (which ends every room): back on its own
 * ("auto"), or, having come before the host re-created the room, on the
 * no-such-room screen, from which it joins again by hand ("manual") once
 * the room is live. Anything else is returned as a failure text. */
export async function guestBack(client, link, since, timeoutMs) {
	const page = client.page;
	const h = await page
		.waitForFunction(settled, { timeout: timeoutMs })
		.catch(() => null);
	const got = h && (await h.jsonValue());
	if (got === "connected") return "auto";
	if (got !== "no-such-room") return `came back as ${got}`;
	if (!(await waitRoomLog(link, "live", "", timeoutMs, since)))
		return "the room was not re-created";
	await page.click('[data-testid="room-closed-back"]');
	await page.click('[data-testid="connect"]');
	const ok = await page
		.waitForFunction(settled, { timeout: timeoutMs })
		.then((x) => x.jsonValue())
		.catch(() => null);
	return ok === "connected" ? "manual" : `manual rejoin: ${ok}`;
}

/** A counter of the hub's "moqt rooms:" stats line (every 10 s) once it
 * reaches n, e.g. "replaced" (crashed sessions closed by their key's
 * rejoin) or "id-taken". The count. */
export async function waitCounter(name, n, timeoutMs = 15000) {
	const deadline = Date.now() + timeoutMs;
	let got = 0;
	while (Date.now() < deadline) {
		const all = [
			...readFileSync(hubLog.path, "utf8").matchAll(
				new RegExp(` ${name}=(\\d+)`, "g"),
			),
		];
		got = Number(all.at(-1)?.[1] ?? 0);
		if (got >= n) return got;
		await new Promise((r) => setTimeout(r, 500));
	}
	return got;
}

/** The final screen's reason token once it shows, or null. */
export async function waitClosed(client, timeoutMs = WAIT_MS) {
	try {
		const h = await client.page.waitForFunction(
			() =>
				document.querySelector('[data-testid="room-closed"]')?.dataset.reason,
			{ timeout: timeoutMs },
		);
		return await h.jsonValue();
	} catch {
		return null;
	}
}

/** Clicks Leave: the session closes at once (a closed browser's session
 * may linger at the hub until the idle timeout). */
export const leave = (client) =>
	client.page.evaluate(() =>
		[...document.querySelectorAll("button")]
			.find((b) => b.textContent.includes("Leave"))
			?.click(),
	);

/** For harnesses that drive their own pages (load tests, e2e-screen): the
 * URL to open and the step before Join for the run's default room. The
 * first page creates it as DEFAULT_HOST_KEY; call created() once that page
 * is connected. */
export async function defaultRoomJoin(page, pageUrl) {
	if (defaultRoom.id)
		return {
			url: withDefaultRoom(pageUrl),
			beforeConnect: async () => {},
			created: async () => {},
		};
	const c = creator(pageUrl, DEFAULT_HOST_KEY);
	for (const s of c.initScripts) await page.evaluateOnNewDocument(s);
	return {
		url: c.pageUrl,
		beforeConnect: c.beforeConnect,
		created: async () => {
			const link = new URL(await linkOf({ page }, pageUrl));
			if (!(await waitRoomLog(link.href, "live")))
				throw new Error("the default room did not go live");
			defaultRoom.id = link.searchParams.get("room");
			defaultRoom.host = link.searchParams.get("host");
		},
	};
}

// `node roomsE2e.mjs <dir> <hub port>` (run.sh, run-voice.sh): starts the
// fixture and nip05d, prints the hub's room flags on one line, and stops
// both on SIGTERM.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
	const rooms = await startRoomServices(process.argv[2]);
	console.log(rooms.args(`https://localhost:${process.argv[3]}`).join(" "));
	process.on("SIGTERM", () => rooms.stop().then(() => process.exit(0)));
}
