// S25 nostr-room: the NIP-53 meeting space over the MoQ hub. user1 is the
// host -- the room link's `host` is its fixed test key (0x01..) -- and
// user2 a guest; both log in with a mocked
// NIP-07 extension. The guest must see the host's space and live meeting
// (kinds 30312/30313, latest-only tracks) and the host's name in the Room
// list before anyone posts (kind 10312 presence). Then: the guest's raised
// hand shows at the host, the guest's "+" reaction (kind 7) is counted under
// the host's post, the host's kind 5 deletion turns its post into the
// "Deleted" line at the guest, and the host leaving ends the meeting.
// --shots=<dir> saves room2-desktop-light.png, room2-tablet-light.png and
// room2-phone-light.png (guest) and
// room2-phone-dark.png (host) before the host leaves.
//
//   just e2e-stability s25-nostr-room [--shots=<dir>]

import {
	keyOf,
	nostrLogin,
	pubkeyOf,
	roomUrl,
	sendChat,
	shortNpub,
	WAIT_MS,
} from "../lib/nostrE2e.mjs";
import { closeClient, joinStabilityClient } from "../lib/stabilityClient.mjs";

const MEETING_TITLE = "Open session"; // nostr.ts NOSTR_MEETING_TITLE

/** Waits until fn(arg) in the page returns truthy; its value, or null. */
async function waitFor(client, fn, arg) {
	try {
		const h = await client.page.waitForFunction(fn, { timeout: WAIT_MS }, arg);
		return await h.jsonValue();
	} catch {
		return null;
	}
}

const textOf = (client, testId) =>
	waitFor(
		client,
		(id) => document.querySelector(`[data-testid="${id}"]`)?.textContent,
		testId,
	);

// The message bubble containing `text`, then a click on the testId inside
// it (or on the picked reaction, after "Add reaction" opened the row).
function clickIn(client, text, testId) {
	return waitFor(
		client,
		([t, id]) => {
			const m = [...document.querySelectorAll('[data-testid="message"]')].find(
				(x) => x.textContent.includes(t),
			);
			const b = m?.querySelector(`[data-testid="${id}"]`);
			b?.click();
			return Boolean(b);
		},
		[text, testId],
	);
}

async function checkMeeting(guest, hostPk, roomName, report, failures) {
	// The host names its space roomName(id) (roomLink.ts), the same text
	// the guest shows before the 30312 is in -- so wait for the meeting.
	report.space = await waitFor(
		guest,
		(want) =>
			document.querySelector('[data-testid="space-name"]')?.textContent ===
				want && want,
		roomName,
	);
	report.title = await textOf(guest, "meeting-title");
	report.status = await textOf(guest, "meeting-status");
	if (report.space !== roomName || report.title !== MEETING_TITLE)
		failures.push(`space/meeting: ${report.space} / ${report.title}`);
	if (report.status !== "live") failures.push(`status: ${report.status}`);
	report.hostInRoomList = await waitFor(
		guest,
		(want) =>
			[...document.querySelectorAll(".peers .nostr-author")].some(
				(a) => a.textContent === want,
			),
		shortNpub(hostPk),
	);
	if (!report.hostInRoomList)
		failures.push("guest's Room list lacks the host (presence)");
}

async function checkHand(host, guest, report, failures) {
	await guest.page.click('[data-testid="hand-toggle"]');
	report.handPressed = await waitFor(
		guest,
		() =>
			document
				.querySelector('[data-testid="hand-toggle"]')
				?.getAttribute("aria-pressed") === "true",
	);
	report.handAtHost = await waitFor(host, () =>
		document
			.querySelector('[data-testid="hand-user2"]')
			?.getAttribute("aria-label"),
	);
	if (!report.handPressed || report.handAtHost !== "Hand raised")
		failures.push(`hand: ${report.handPressed} / ${report.handAtHost}`);
}

async function checkReaction(host, guest, text, report, failures) {
	await clickIn(guest, text, "reaction-add");
	await clickIn(guest, text, "reaction-pick"); // the first one: "+"
	report.reactionAtHost = await waitFor(
		host,
		(t) =>
			[...document.querySelectorAll('[data-testid="message"]')]
				.find((x) => x.textContent.includes(t))
				?.querySelector('[data-testid="reaction-count"]')
				?.getAttribute("aria-label"),
		text,
	);
	if (report.reactionAtHost !== "Like: 1")
		failures.push(`reaction at host: ${report.reactionAtHost}`);
}

async function checkDelete(host, guest, hostPk, text, report, failures) {
	await clickIn(host, text, "nostr-delete");
	report.deletedAtGuest = await waitFor(
		guest,
		([pk, t]) => {
			const mine = [
				...document.querySelectorAll(
					`[data-testid="message"][data-sender="${pk}"]`,
				),
			];
			const gone = !mine.some((m) => m.textContent.includes(t));
			const line = document.querySelector('[data-testid="message-deleted"]');
			return gone && line?.textContent;
		},
		[hostPk, text],
	);
	if (!report.deletedAtGuest) failures.push("deletion not shown at the guest");
}

async function shoot(host, guest, dir) {
	// The settings drawer open, to show its one control size.
	await guest.page.evaluate(() => {
		document.querySelector('[data-testid="settings"]').open = true;
	});
	await guest.page.setViewport({ width: 1280, height: 800 });
	await guest.page.screenshot({ path: `${dir}/room2-desktop-light.png` });
	await guest.page.setViewport({ width: 800, height: 600 });
	await guest.page.screenshot({ path: `${dir}/room2-tablet-light.png` });
	await guest.page.setViewport({ width: 390, height: 667 });
	await guest.page.screenshot({ path: `${dir}/room2-phone-light.png` });
	await host.page.emulateMediaFeatures([
		{ name: "prefers-color-scheme", value: "dark" },
	]);
	// No isMobile: Puppeteer reloads the page to change it. At 390px the
	// room shows one pane (the Video tab) above the bottom tabs.
	await host.page.setViewport({
		width: 390,
		height: 1400,
		deviceScaleFactor: 2,
	});
	await host.page.screenshot({
		path: `${dir}/room2-phone-dark.png`,
		fullPage: true,
	});
}

async function checkEnded(host, guest, report, failures) {
	await host.page.evaluate(() =>
		[...document.querySelectorAll("button")]
			.find((b) => b.textContent.includes("Leave"))
			?.click(),
	);
	report.endedAtGuest = await waitFor(
		guest,
		() =>
			document.querySelector('[data-testid="meeting-status"]')?.textContent ===
			"ended",
	);
	if (!report.endedAtGuest) failures.push("meeting not ended after host left");
}

export async function run({ pageUrl, serverUrl, server, arg, log }) {
	const url = roomUrl(pageUrl, 1);
	const roomName = `Room ${new URL(url).searchParams.get("room").slice(0, 6)}`;
	const opts = (tag, n) => ({
		pageUrl: url,
		serverUrl,
		certHash: server.certHash,
		participantId: tag,
		beforeConnect: nostrLogin(keyOf(n)),
	});
	const hostPk = pubkeyOf(1);
	const stamp = Date.now();
	const failures = [];
	const report = { hostPk };
	const clients = [];
	try {
		log("host (user1) joins, then the guest (user2)");
		const host = await joinStabilityClient(opts("user1", 1));
		clients.push(host);
		await textOf(host, "meeting-title"); // the meeting is out before the guest
		const guest = await joinStabilityClient(opts("user2", 2));
		clients.push(guest);

		await checkMeeting(guest, hostPk, roomName, report, failures);
		await checkHand(host, guest, report, failures);

		const kept = `room-kept-${stamp}`;
		const gone = `room-gone-${stamp}`;
		await sendChat(host, kept);
		await sendChat(host, gone);
		await checkReaction(host, guest, kept, report, failures);
		await checkDelete(host, guest, hostPk, gone, report, failures);
		const shots = arg("shots", "");
		if (shots) await shoot(host, guest, shots);
		await checkEnded(host, guest, report, failures);

		for (const c of clients)
			if (c.errors.length > 0)
				failures.push(`${c.tag} page errors: ${c.errors.join("; ")}`);
	} finally {
		for (const c of clients) await closeClient(c);
	}
	return { report, failures };
}
