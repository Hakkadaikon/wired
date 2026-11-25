// S28 room timers (tasks/moqt-chat-rooms.md P8), on short durations
// (serverArgs): each room ends, every member lands on the room-ended final
// screen, and the hub logs the end's why.
//   alone        key 1 creates a room and stays alone past the timeout
//   empty grace  key 2's room: host and guest go away together; past the
//                grace a joiner by the link gets room-ended (tombstone)
//   lifetime     key 3's room, host + guest (never alone): both are
//                closed at the lifetime
// (Host end by 30313 is s25's last step.)
//
//   just e2e-stability s28-room-timers

import { waitClosed, waitRoomLog } from "../lib/roomsE2e.mjs";
import {
	closeClient,
	createRoomClient,
	joinStabilityClient,
} from "../lib/stabilityClient.mjs";

// Longer than a guest may take to join (JOIN_TIMEOUT_MS, 20 s), or the
// empty and lifetime rooms end alone first.
const ALONE_S = 25;
const EMPTY_S = 3;
const LIFETIME_S = 40;

export const serverArgs = [
	...["--room-alone-timeout", String(ALONE_S)],
	...["--room-empty-grace", String(EMPTY_S)],
	...["--room-lifetime", String(LIFETIME_S)],
];

const WAIT_END_MS = (LIFETIME_S + 10) * 1000;

// t: { pageUrl, serverUrl, certHash, open, report, failures }
const opts = (t, participantId, url) => ({
	pageUrl: url,
	serverUrl: t.serverUrl,
	certHash: t.certHash,
	participantId,
});

async function create(t, n) {
	const c = await createRoomClient(opts(t, "user1", t.pageUrl), n);
	t.open.push(c);
	return c;
}

async function join(t, url) {
	const c = await joinStabilityClient(opts(t, "user2", url));
	t.open.push(c);
	return c;
}

// The hub logged the end with why, and every client shows room-ended.
async function ended(t, name, [link, why], clients) {
	const r = {
		log: await waitRoomLog(link, "end", why, WAIT_END_MS),
		screens: await Promise.all(clients.map((c) => waitClosed(c, 5000))),
		// sessions each page opened (more than one: it reconnected)
		sessions: await Promise.all(
			clients.map((c) =>
				c.page
					.evaluate(() =>
						(window.__wtEvents ?? []).map((e) => [
							e.openedAt % 1e6,
							e.closedAt && e.closedAt % 1e6,
							e.closeInfo,
						]),
					)
					.catch(() => null),
			),
		),
	};
	t.report[name] = r;
	if (!r.log) t.failures.push(`${name}: no "end ${why}" log`);
	if (r.screens.some((x) => x !== "room-ended"))
		t.failures.push(`${name}: screens ${r.screens}`);
}

// Host and guest go away together; past the grace the link gets room-ended.
async function emptyGrace(t) {
	const host = await create(t, 2);
	const guest = await join(t, host.link);
	// Closing the pages ends both sessions without the host's Leave, which
	// would end the room by its 30313 instead.
	await Promise.all([host, guest].map((c) => c.page.close().catch(() => {})));
	// Both sessions gone at the hub (not lingering until the idle timeout,
	// which would end the room "alone" instead).
	t.report.emptyLeft = await waitRoomLog(host.link, "leave", "n=0");
	if (!t.report.emptyLeft) t.failures.push("empty: sessions did not leave");
	t.report.emptyLog = await waitRoomLog(host.link, "end", "empty");
	if (!t.report.emptyLog) t.failures.push('empty: no "end empty" log');
	// A failed join is one failure; the lifetime step still runs.
	const late = await joinStabilityClient({
		...opts(t, "user3", host.link),
		expectClosed: true,
	}).catch((e) => ({ closedReason: `join failed: ${e.message}` }));
	if (late.browser) t.open.push(late);
	t.report.emptyLate = late.closedReason ?? (await waitClosed(late));
	if (t.report.emptyLate !== "room-ended")
		t.failures.push(`empty: late joiner ${t.report.emptyLate}`);
}

export async function run({ pageUrl, serverUrl, server, log }) {
	const t = {
		pageUrl,
		serverUrl,
		certHash: server.certHash,
		open: [],
		report: {},
		failures: [],
	};
	try {
		log("alone: key 1's room, nobody joins");
		const alone = await create(t, 1);
		await ended(t, "alone", [alone.link, "alone"], [alone]);
		log("empty grace: key 2's room empties, then a joiner comes");
		await emptyGrace(t);
		log(`lifetime: key 3's room, two members until ${LIFETIME_S}s`);
		const lhost = await create(t, 3);
		const lguest = await join(t, lhost.link);
		await ended(t, "lifetime", [lhost.link, "lifetime"], [lhost, lguest]);
	} finally {
		for (const c of t.open) await closeClient(c);
	}
	for (const c of t.open)
		for (const e of c.errors) t.failures.push(`${c.tag} page error: ${e}`);
	return { report: t.report, failures: t.failures };
}
