// S14 screen-rejoin: a participant leaves and rejoins while (and after)
// someone else shares their screen -- reproduces the user report "after I
// leave and come back I don't see the share (and chat is gone)". Four
// clients, no proxy, direct to the hub:
//
//   1. user1 shares; every viewer decodes frames.
//   2. user2 leaves (page closed) and rejoins while the share is live:
//      gate A -- user2 decodes user1's frames again within resume-max-ms;
//      gate B -- chat still reaches user2 and comes back from user2.
//   3. user1 stops sharing (its screen track stays PUBLISHed, idle).
//   4. user3 leaves and rejoins against that idle track, then the room
//      idles for idle-ms (a rejoined client used to resend SUBSCRIBE for
//      the idle track every second, and the hub granted a fresh slot to
//      each -- 31 slots gone in about 31 s).
//   5. user1 shares again: gate C -- user3 and user4 both decode frames
//      within resume-max-ms; gate D -- user3 receives one live screen
//      stream per Group (each keyframe, every 2 s, opens a new one), not
//      one per slot it had piled up; gate E -- the hub's
//      shutdown stats report open_dropped=0.
//
//   just e2e-stability s14-screen-rejoin
//   just e2e-stability s14-screen-rejoin --idle-ms=5000   # quick smoke
//   just e2e-stability s14-screen-rejoin --shots=<dir>    # share-*.png

import { readFileSync } from "node:fs";
import path from "node:path";
import { FAKE_DISPLAY_MEDIA_SCRIPT } from "../lib/screenShareFake.mjs";
import {
	clientMetrics,
	closeClient,
	connectClient,
	joinStabilityClient,
} from "../lib/stabilityClient.mjs";

const TAGS = ["user1", "user2", "user3", "user4"];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const tapsFrom = (client, sender) =>
	client.page.evaluate(
		(s) =>
			(window.__wiredScreenTap ?? []).filter((e) => e.senderId === s).length,
		sender,
	);

// Wall-clock ms until `client` has decoded `n` more frames from `sender`
// than it had at the call, or null past timeoutMs.
async function waitFrames(client, sender, n, timeoutMs) {
	const start = Date.now();
	const base = await tapsFrom(client, sender);
	try {
		await client.page.waitForFunction(
			(s, want) =>
				(window.__wiredScreenTap ?? []).filter((e) => e.senderId === s)
					.length >= want,
			{ timeout: timeoutMs },
			sender,
			base + n,
		);
		return Date.now() - start;
	} catch {
		return null;
	}
}

async function sendChat(client, text) {
	await client.page.evaluate((t) => {
		const input = document.querySelector('input[data-testid="text"]');
		const setter = Object.getOwnPropertyDescriptor(
			window.HTMLInputElement.prototype,
			"value",
		).set;
		setter.call(input, t);
		input.dispatchEvent(new Event("input", { bubbles: true }));
		input.dispatchEvent(
			new KeyboardEvent("keydown", { key: "Enter", bubbles: true }),
		);
	}, text);
}

async function sawChat(client, text, timeoutMs) {
	try {
		await client.page.waitForFunction(
			(t) =>
				document
					.querySelector('[data-testid="messages"]')
					?.textContent?.includes(t),
			{ timeout: timeoutMs },
			text,
		);
		return true;
	} catch {
		return false;
	}
}

// Incoming live Group streams carrying a screen share (chat's one-shot
// uploads are a few dozen bytes) opened at or after `since`. History fills
// (FETCH_HEADER, Stream Type 0x05) are not counted: each SUBSCRIBE asks
// for one, so an Auto watcher's hi and lo pair adds two per re-share.
async function screenStreamsSince(client, since) {
	const m = await clientMetrics(client);
	return (m?.wtUniStreams ?? []).filter(
		(s) => s.bytes >= 1000 && s.openedAt >= since && s.type !== 0x05,
	).length;
}

function hubOpenDropped(logPath) {
	const m = readFileSync(logPath, "utf8").match(/open_dropped=(\d+)/g);
	return m ? Number(m.at(-1).slice("open_dropped=".length)) : null;
}

// --shots=<dir>: a viewer's room while user1's share is live (the share
// fills the stage, no camera tiles) at desktop, tablet and phone widths.
async function shootShare(client, dir) {
	const sizes = { desktop: [1280, 800], tablet: [800, 600], phone: [390, 667] };
	for (const [name, [width, height]] of Object.entries(sizes)) {
		await client.page.setViewport({ width, height });
		await sleep(500);
		await client.page.screenshot({ path: `${dir}/share-${name}.png` });
	}
}

// Camera / avatar tiles on the client's stage (none while a share is live).
const peerTiles = (client) =>
	client.page.evaluate(
		() =>
			document.querySelectorAll(
				'[data-testid^="camera-tile-"], [data-testid^="avatar-tile-"]',
			).length,
	);

async function tilesBack(client, ms) {
	for (const end = Date.now() + ms; Date.now() < end; await sleep(250))
		if ((await peerTiles(client)) > 0) return true;
	return false;
}

const splitter = (client) =>
	client.page.evaluate(() => ({
		now: Number(
			document
				.querySelector('[data-testid="splitter"]')
				?.getAttribute("aria-valuenow"),
		),
		stage: document.querySelector(".stage")?.offsetHeight,
	}));

// The splitter on a desktop-sized viewer: ArrowDown grows the stage one
// step (5 points) and the ratio is saved for the rejoin to restore.
async function splitterDown(client, report, failures) {
	await client.page.setViewport({ width: 1280, height: 800 });
	await sleep(300);
	const before = await splitter(client);
	await client.page.focus('[data-testid="splitter"]');
	await client.page.keyboard.press("ArrowDown");
	await sleep(300);
	const after = await splitter(client);
	report.splitter = { before, after };
	if (!(after.now === before.now + 5 && after.stage > before.stage))
		failures.push(`splitter ArrowDown: ${JSON.stringify(report.splitter)}`);
}

async function splitterKept(client, report, failures) {
	await client.page.setViewport({ width: 1280, height: 800 });
	await sleep(300);
	report.splitter.reloaded = await splitter(client);
	if (report.splitter.reloaded.now !== report.splitter.after.now)
		failures.push(`splitter not restored: ${JSON.stringify(report.splitter)}`);
}

// While a share is live the stage shows it alone (no camera tiles), then
// the shots and the splitter step on the same viewer.
async function layoutDuringShare(client, shots, report, failures) {
	report.tilesDuringShare = await peerTiles(client);
	if (report.tilesDuringShare !== 0)
		failures.push(`${report.tilesDuringShare} camera tiles during the share`);
	if (shots) await shootShare(client, shots);
	await splitterDown(client, report, failures);
}

async function layoutAfterShare(client, report, failures) {
	report.tilesBackAfterShare = await tilesBack(client, 15000);
	if (!report.tilesBackAfterShare)
		failures.push("camera tiles did not come back after the share stopped");
}

// The rejoined user2 decodes the live share again in time, and its page
// restored the splitter ratio it saved before leaving.
async function gateA(user2, resumeMaxMs, report, failures) {
	report.user2ResumeMs = await waitFrames(
		user2,
		"user1",
		3,
		resumeMaxMs + 15000,
	);
	if (report.user2ResumeMs === null)
		failures.push(
			"gate A: rejoined user2 never decoded user1's live share again",
		);
	else if (report.user2ResumeMs > resumeMaxMs)
		failures.push(
			`gate A: rejoined user2 resumed only after ${report.user2ResumeMs}ms > ${resumeMaxMs}ms`,
		);
	await splitterKept(user2, report, failures);
}

export async function run({ pageUrl, server, arg, log }) {
	const resumeMaxMs = Number(arg("resume-max-ms", "5000"));
	const idleMs = Number(arg("idle-ms", "40000"));
	const chatMaxMs = Number(arg("chat-max-ms", "5000"));
	const evidenceDir = arg(
		"evidence-dir",
		path.join(
			path.dirname(new URL(import.meta.url).pathname),
			"../../../../tasks/voice-stability/s14-screen-rejoin",
		),
	);
	const opts = (tag) => ({
		pageUrl,
		serverUrl: "",
		certHash: server.certHash,
		participantId: tag,
		initScripts: [FAKE_DISPLAY_MEDIA_SCRIPT],
	});
	const rejoin = async (client) => {
		await client.page.close();
		await connectClient(client, opts(client.tag));
	};
	const toggleShare = (client) =>
		client.page.click('[data-testid="screen-toggle"]');

	const failures = [];
	const report = { resumeMaxMs, idleMs };
	const clients = [];
	try {
		for (const tag of TAGS) {
			log(`joining ${tag}`);
			clients.push(await joinStabilityClient(opts(tag)));
		}
		const [user1, user2, user3, user4] = clients;

		log("user1 shares");
		await toggleShare(user1);
		for (const c of [user2, user3, user4]) {
			if ((await waitFrames(c, "user1", 3, 30000)) === null)
				failures.push(
					`${c.tag}: never decoded user1's share before the rejoin test began`,
				);
		}
		await layoutDuringShare(user2, arg("shots", ""), report, failures);

		log("user2 leaves and rejoins while the share is live");
		await rejoin(user2);
		await gateA(user2, resumeMaxMs, report, failures);

		await sendChat(user2, "msg:user2:after-rejoin");
		for (const c of [user1, user3, user4]) {
			if (!(await sawChat(c, "msg:user2:after-rejoin", chatMaxMs)))
				failures.push(
					`gate B: ${c.tag} never saw the rejoined user2's chat message`,
				);
		}
		await sendChat(user3, "msg:user3:to-rejoined");
		if (!(await sawChat(user2, "msg:user3:to-rejoined", chatMaxMs)))
			failures.push("gate B: rejoined user2 never saw user3's chat message");

		log("user1 stops sharing; user3 leaves and rejoins against the idle track");
		await toggleShare(user1);
		await layoutAfterShare(user4, report, failures);
		await rejoin(user3);
		log(`room idles for ${idleMs}ms`);
		await sleep(idleMs);

		log("user1 shares again");
		const reshareAt = Date.now();
		await toggleShare(user1);
		report.user3ResumeMs = await waitFrames(
			user3,
			"user1",
			3,
			resumeMaxMs + 15000,
		);
		report.user4ResumeMs = await waitFrames(
			user4,
			"user1",
			3,
			resumeMaxMs + 15000,
		);
		for (const [tag, ms] of [
			["user3", report.user3ResumeMs],
			["user4", report.user4ResumeMs],
		]) {
			if (ms === null)
				failures.push(`gate C: ${tag} never decoded user1's re-share`);
			else if (ms > resumeMaxMs)
				failures.push(
					`gate C: ${tag} decoded the re-share only after ${ms}ms > ${resumeMaxMs}ms`,
				);
		}
		await sleep(3000); // let every relay stream the hub is going to open, open
		report.user3ScreenStreams = await screenStreamsSince(user3, reshareAt);
		// One Group per 2 s keyframe interval (screenSharePipeline.ts), plus
		// the one in progress at either end of the window.
		const groups = Math.ceil((Date.now() - reshareAt) / 2000) + 1;
		if (report.user3ScreenStreams > groups)
			failures.push(
				`gate D: user3 received ${report.user3ScreenStreams} live screen streams for one re-share (at most ${groups} Groups)`,
			);

		for (const c of clients)
			for (const e of c.errors) failures.push(`${c.tag} page error: ${e}`);
		for (const c of clients) await closeClient(c);
	} finally {
		// The hub prints its relay stats only at shutdown; stop it here (the
		// runner's own stop afterwards is a no-op on an exited process).
		await server.stop();
		report.hubOpenDropped = hubOpenDropped(
			path.join(evidenceDir, "server.log"),
		);
		if (report.hubOpenDropped !== 0)
			failures.push(
				`gate E: hub open_dropped=${report.hubOpenDropped} (want 0)`,
			);
	}
	return { report, failures };
}
