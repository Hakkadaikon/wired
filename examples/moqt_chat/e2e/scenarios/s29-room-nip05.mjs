// S29 room NIP-05 (tasks/moqt-chat-rooms.md P8): the create depends on
// nip05d, and losing nip05d ends only the room being verified.
//   nip05d running   key 1 creates a room, it goes live, user2 joins
//   nip05d stopped   key 2 creates a room: no verdict, so after 3 s the
//                    creator lands on the nip05-unverified final screen
//   meanwhile        key 1's room keeps running: both stay connected and
//                    a message still crosses
//
//   just e2e-stability s29-room-nip05

import { readFileSync } from "node:fs";
import { sendChat, WAIT_MS } from "../lib/nostrE2e.mjs";
import {
	hubLog,
	hubLogMark,
	waitClosed,
	waitRoomLog,
} from "../lib/roomsE2e.mjs";
import {
	closeClient,
	createRoomClient,
	joinStabilityClient,
} from "../lib/stabilityClient.mjs";

// When the hub logs a create and the nip05 end after since (20 ms polls).
function stamps(since) {
	const at = {};
	const timer = setInterval(() => {
		const log = readFileSync(hubLog.path, "utf8").slice(since);
		at.create ??= /moqt room: create /.test(log) ? Date.now() : undefined;
		at.end ??= / nip05\n/.test(log) ? Date.now() : undefined;
	}, 20);
	return { at, stop: () => clearInterval(timer) };
}

const status = (c) =>
	c.page.evaluate(() =>
		document
			.querySelector('[data-testid="status"]')
			?.getAttribute("data-status"),
	);

async function received(client, text) {
	try {
		await client.page.waitForFunction(
			(t) =>
				[...document.querySelectorAll('[data-testid="message"]')].some((m) =>
					m.textContent.includes(t),
				),
			{ timeout: WAIT_MS },
			text,
		);
		return true;
	} catch {
		return false;
	}
}

export async function run({ pageUrl, serverUrl, server, rooms, log }) {
	const failures = [];
	const report = {};
	const open = [];
	const opts = (participantId, url) => ({
		pageUrl: url,
		serverUrl,
		certHash: server.certHash,
		participantId,
	});
	let hub;
	try {
		log("nip05d running: key 1's room goes live, user2 joins");
		const host = await createRoomClient(opts("user1", pageUrl), 1);
		open.push(host);
		const guest = await joinStabilityClient(opts("user2", host.link));
		open.push(guest);

		log("nip05d stopped: key 2's create is not verified");
		await rooms.stopNip05d();
		hub = stamps(hubLogMark());
		const c = await createRoomClient(
			{ ...opts("user3", pageUrl), expectClosed: true },
			2,
		);
		open.push(c);
		const link = c.link;
		report.creatorScreen = c.closedReason ?? (await waitClosed(c, 10000));
		report.closedAfterMs = Date.now() - c.connectStart;
		hub.stop();
		// The hub's 3 s lookup timeout, from its create line to its end line
		// (each seen within a 20 ms poll; the room's clock is the tick before
		// the create, so a little under 3 s is on time), at most 6 s.
		report.hubEndAfterMs = hub.at.end - hub.at.create;
		if (!(report.hubEndAfterMs >= 2900 && report.hubEndAfterMs <= 6000))
			failures.push(
				`hub ended it ${report.hubEndAfterMs} ms after create, not 2.9-6 s`,
			);
		report.unverifiedLog = await waitRoomLog(link, "end", "nip05");
		if (report.creatorScreen !== "nip05-unverified")
			failures.push(`creator screen: ${report.creatorScreen}`);
		if (!report.unverifiedLog) failures.push('no "end nip05" log');

		const stamp = `still-here-${Date.now()}`;
		await sendChat(host, stamp);
		report.othersConnected = [await status(host), await status(guest)];
		report.messageCrossed = await received(guest, stamp);
		if (report.othersConnected.some((s) => s !== "connected"))
			failures.push(`room 1 status ${report.othersConnected}`);
		if (!report.messageCrossed) failures.push("room 1 message lost");
	} finally {
		hub?.stop();
		for (const c of open) await closeClient(c);
	}
	for (const c of open)
		for (const e of c.errors) failures.push(`${c.tag} page error: ${e}`);
	return { report, failures };
}
