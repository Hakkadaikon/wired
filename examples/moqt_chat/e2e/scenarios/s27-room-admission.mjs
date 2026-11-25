// S27 room admission (tasks/moqt-chat-rooms.md P8): who the hub lets into
// a room, and the final screen each refusal shows (data-reason = the
// close reason token, roomAuth.ts).
//   create -> live   key 1 creates open room R1 as user1 (hub logs live)
//   join             user2 joins R1 by its link
//   id-taken         a second user2 joins R1: closed id-taken, it joins
//                    again as user3 by itself
//   room-full        user3 + user4 fill R1; a 5th joiner is refused
//   host mismatch    R1's link with another host: unauthorized
//   auth room        key 2 creates auth room R2: a joiner without a
//                    login is refused (unauthorized), one with a login
//                    gets in
//   no-room-slots    key 3 creates R3 (3 rooms live); key 4's create is
//                    refused
//
//   just e2e-stability s27-room-admission

import { keyOf, nostrLogin, pubkeyOf, WAIT_MS } from "../lib/nostrE2e.mjs";
import { leave, waitClosed, waitCounter } from "../lib/roomsE2e.mjs";
import {
	closeClient,
	createRoomClient,
	joinStabilityClient,
} from "../lib/stabilityClient.mjs";

// malformed-auth, expired-auth and server-busy do not come from an honest
// page on a correct clock; the hub's unit tests cover them. (A page with
// Date.now shifted back hung Chrome's main thread past every timeout.)

// t: { pageUrl, serverUrl, certHash, open, report, failures }
const opts = (t, participantId, url, beforeConnect) => ({
	pageUrl: url,
	serverUrl: t.serverUrl,
	certHash: t.certHash,
	participantId,
	beforeConnect,
});

async function join(t, id, url, beforeConnect) {
	const c = await joinStabilityClient(opts(t, id, url, beforeConnect));
	t.open.push(c);
	return c;
}

async function create(t, id, n, mode) {
	const c = await createRoomClient(opts(t, id, t.pageUrl), n, mode);
	t.open.push(c);
	return c;
}

// A join that must end on the final screen with token. A failed join is
// one failure, not the end of the run: the later checks still report.
async function refused(t, name, token, [id, url]) {
	const c = await joinStabilityClient({
		...opts(t, id, url),
		expectClosed: true,
	}).catch((e) => ({ closedReason: `join failed: ${e.message}` }));
	t.report[name] = c.closedReason ?? (await waitClosed(c));
	if (t.report[name] !== token)
		t.failures.push(`${name}: want ${token}, got ${t.report[name]}`);
	if (c.browser) await closeClient(c);
}

// id-taken: a second user2 is closed id-taken, and the page joins again as
// the next free id (useIdTakenRetry): the hub counts the refusal and the
// host's roster shows user3 (lasting signals, not the 5 s toast).
async function idTaken(t, host, link) {
	const dup = await join(t, "user2", link);
	const asUser3 = await host.page
		.waitForSelector('[data-testid="quality-user3"]', { timeout: WAIT_MS })
		.then(() => true)
		.catch(() => false);
	const counted = (await waitCounter("id-taken", 1)) >= 1;
	t.report.idTaken = { asUser3, counted };
	if (!asUser3 || !counted)
		t.failures.push(`id-taken: ${JSON.stringify(t.report.idTaken)}`);
	await leave(dup);
	await closeClient(dup);
}

// R1: create, join, id-taken, room-full, host mismatch.
async function openRoom(t) {
	const host = await create(t, "user1", 1, "open");
	const g2 = await join(t, "user2", host.link);
	await idTaken(t, host, host.link);
	const g3 = await join(t, "user3", host.link);
	const g4 = await join(t, "user4", host.link);
	await refused(t, "roomFull", "room-full", ["user1", host.link]);
	// Fewer Chromes for the rest (4 cores): R1 stays live with its host.
	for (const c of [g2, g3, g4]) await closeClient(c);
	const other = new URL(host.link);
	other.searchParams.set("host", pubkeyOf(5));
	await refused(t, "hostMismatch", "unauthorized", ["user3", other.href]);
}

// R2: an auth room refuses a joiner without a login, admits one with.
async function authRoom(t) {
	const authHost = await create(t, "user1", 2, "auth");
	await refused(t, "authNoLogin", "unauthorized", ["user2", authHost.link]);
	const member = await join(t, "user2", authHost.link, nostrLogin(keyOf(6)));
	t.report.authWithLogin = member.closedReason ?? "connected";
	if (t.report.authWithLogin !== "connected")
		t.failures.push(`auth room with login: ${t.report.authWithLogin}`);
	await closeClient(member);
}

// R3 makes three rooms; key 4's create finds no free slot.
async function fourthRoom(t) {
	await create(t, "user1", 3, "open");
	const fourth = await createRoomClient(
		{ ...opts(t, "user1", t.pageUrl), expectClosed: true },
		4,
	).catch((e) => ({ closedReason: `join failed: ${e.message}` }));
	t.report.fourthRoom = fourth.closedReason ?? (await waitClosed(fourth));
	if (fourth.browser) await closeClient(fourth);
	if (t.report.fourthRoom !== "no-room-slots")
		t.failures.push(`4th room: ${t.report.fourthRoom}`);
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
		log("key 1 creates R1, user2 joins");
		await openRoom(t);
		log("key 2 creates auth room R2");
		await authRoom(t);
		log("key 3 creates R3; key 4 finds no free slot");
		await fourthRoom(t);
	} finally {
		for (const c of t.open) await closeClient(c);
	}
	for (const c of t.open)
		for (const e of c.errors) t.failures.push(`${c.tag} page error: ${e}`);
	return { report: t.report, failures: t.failures };
}
